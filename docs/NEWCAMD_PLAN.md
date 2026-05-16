# newcamd descrambler — design & implementation plan

Status: draft / in-progress on `feat/newcamd`.

## Motivation

minisatip already supports oscam via dvbapi (`src/dvbapi.cpp`), but dvbapi is
an "I will be your local cam process" protocol: only one client can hold the
dvbapi socket against an oscam instance in the typical setup, and on a host
where another process closer to the card already uses the dvbapi socket
(e.g. a CI-equipped tvheadend, or a different minisatip), the remote minisatip
has nowhere to plug in.

newcamd solves this: it is oscam's native **card-emulation** TCP protocol.
Multiple newcamd clients can connect to one oscam concurrently, each
authenticating with its own user/password and pinned to a single CAID per
connection.

## Protocol choice

Evaluated alternatives:

| Protocol      | Verdict   | Notes |
|---------------|-----------|-------|
| newcamd       | **chosen** | Simple TCP, well-documented, first-class oscam support (`[newcamd]` server). One TCP connection per CAID. |
| cccam         | rejected   | Reverse-engineered, ~3× the code, designed for card-sharing peer networks not point-to-point cam access. |
| camd35 udp/tcp | rejected  | Legacy, weaker auth, lower-quality oscam path. |
| gbox/radegast | rejected   | Niche / obsolete. |

References: oscam-emm-newcamd implementation, tvheadend's `src/descrambler/cwc.c`,
the [vdr newcamd plugin](https://github.com/vdr-projects/vdr-plugin-newcamd)
(canonical wire format reference).

## Wire format (summary, for implementer)

- Transport: plain TCP, default port 15050 (configured in oscam `[newcamd]`).
- All non-login traffic is framed as `[len_hi | len_lo | payload...]` and
  encrypted with Triple-DES (EDE3, CBC) using a session key derived during
  login. Length is the cipher payload size; payload pads to 8-byte DES block.
- Login: client sends 14 random bytes; server echoes them XORed with the
  configured 14-byte "DES key" string (this becomes the initial Triple-DES
  session key). Client then sends `MSG_CLIENT_2_SERVER_LOGIN` payload
  containing username + MD5(`$1$abcdefgh$` salted password) — see the
  crypt(3) MD5 scheme. Server replies `MSG_CLIENT_2_SERVER_LOGIN_ACK` or
  `_NAK`. Then `MSG_CARD_DATA_REQ` / `_CARD_DATA` exchanges the CAID, provider
  id list, and serial.
- ECM request: client wraps a ~32–256 byte ECM table section
  (`0x80`/`0x81` table id + length + payload) in a 12-byte newcamd header:
  `seq_lo, seq_hi, sid_hi, sid_lo, capid_hi, capid_lo, pid_hi, pid_lo, ...`,
  encrypts, sends.
- ECM response: server replies with same `seq` and either a 19-byte payload
  (3-byte header + 16-byte CW pair, even+odd) on success, or a 3-byte error
  payload. Either CW half may be zero if oscam only has one parity.
- Keepalive: most oscam builds use `MSG_KEEPALIVE` (a 3-byte command-only
  packet) every ~120 s. Treat it as a heartbeat — answer with the same code.

## Architecture & integration

minisatip's CA layer is already protocol-agnostic; `dvbapi.cpp` slots in via
`SCA_op` (`src/tables.h:28`) and CW delivery via `send_cw()`
(`src/pmt.cpp:806`). newcamd plugs in alongside it.

### Module layout

```
src/newcamd.h          new — public init/register API + SNewcamd struct
src/newcamd.cpp        new — protocol, connection pool, ECM filter glue
src/opts.h             += newcamd_* fields
src/opts.cpp           += parse_newcamd_opt()
src/minisatip.cpp      += NEWCAMD_OPT in long_options, getopt switch
src/tables.cpp         += init_newcamd() call in tables_init()
CMakeLists.txt         += option(NEWCAMD ...), src/newcamd.cpp,
                          libcrypto in MINISATIP_LIBS
```

### Build switch

`-DNEWCAMD=ON` (default ON when `libcrypto` is found, mirroring `DVBCA`).
`config.h` macro: `DISABLE_NEWCAMD` when option off. libcrypto already
required by `DVBCA`; on Linux with both enabled there's no new dependency.
On macOS (where DVBCA is force-OFF), newcamd still wants libcrypto — pull
the existing `find_library(CRYPTO_LIBRARY crypto)` into a separate gate so
NEWCAMD can be ON without DVBCA.

### Runtime structure

```c++
// One per CAID per oscam server. minisatip can connect to several oscams,
// each can answer several CAIDs — so we have a pool keyed by (host,user,caid).
struct SNewcamd {
    int sock_id;           // socketworks id
    int fd;                 // raw socket
    char host[64];
    int port;
    char user[64];
    char pass[64];
    uint8_t des_key[14];    // raw 14-byte newcamd "DES key"
    uint16_t caid;          // CAID this connection is authenticated for; 0=unbound
    uint8_t session_key[16]; // Triple-DES key after login
    int logged_in;          // 0=connecting, 1=login sent, 2=ready
    uint16_t seq;            // ECM sequence counter, per-conn
    int64_t last_rx;         // for keepalive timeout
    // pending ECMs awaiting reply, keyed by (seq, pmt_id)
    struct pending { uint16_t seq; int pmt_id; int parity; uint16_t ecm_pid; }
        pending[MAX_PENDING];
};

static SNewcamd *conns[MAX_NEWCAMD_CONNS];
static SCA_op newcamd_ca;
static int newcamd_ca_id;
static int newcamd_poller_sock;   // 1s ticker, mirrors dvbapi's poller_sock
```

### Flow: PMT → ECM → CW

1. `tables_init()` (already runs) calls new `init_newcamd()` which
   `register_newcamd()`s into the CA framework (`add_ca`) and starts a 1-s
   `poller_sock` (same trick as `connect_dvbapi`, `src/dvbapi.cpp:584`) to
   (re)connect/login any conn that's down.
2. `ca_add_pmt(adapter, pmt)`: for each `pmt->ca[i]` (the parsed CA
   descriptors, see `pmt_add_caid` at `src/pmt.cpp:1708`), pick the first
   CAID we have a configured oscam reader for. Install an ECM filter:
   `add_filter_mask(ad->id, capid, newcamd_ecm_cb, key_ctx,
   FILTER_ADD_REMOVE | FILTER_CRC, filter={0x80}, mask={0xFE})`. Store the
   key_ctx so the cb can map back to pmt+conn.
3. `newcamd_ecm_cb(filter_id, buf, len, opaque)`: drop duplicate parity (same
   `b[0] & 1` as last sent), bump `seq`, frame & encrypt, write to the
   conn's socket. Record pending entry with `seq → (pmt_id, parity, capid)`.
4. socketworks-driven read callback `newcamd_reply(s)`: parse one or more
   framed messages, decrypt, match `seq` to pending. On CW: call
   `send_cw(pmt_id, CA_ALGO_DVBCSA, parity, cw16, NULL, 0, conn)` — same call
   dvbapi uses (`src/dvbapi.cpp` set_algo + send_cw flow). On error: log and
   leave the filter active so the next ECM will retry.
5. `ca_del_pmt(adapter, pmt)`: `del_filter()` the ECM filters; drop the
   conn's pending entries for that pmt.

### Multi-CAID (v1 scope)

newcamd binds one TCP connection to one CAID at login time. **v1 supports
one oscam server (single `--newcamd` flag) with a CAID list — we open one
TCP connection per CAID, all to the same `host:port:user:pass:deskey`.**
When a PMT lists multiple CA descriptors we pick the first matching
configured CAID.

Multi-reader (multiple `--newcamd` flags for different oscam servers /
different cards) is deferred to a follow-up; promoting the flag to
repeatable is a non-breaking change.

### Reconnect / keepalive

- Reconnect is free: `poller_sock` registered via `sockets_add` + timeout
  pattern (see `src/dvbapi.cpp:584`) re-runs `connect_newcamd()` every 1 s.
  If `fd <= 0` it reconnects + re-logins. socketworks fires
  `newcamd_close` on disconnect, which just sets `fd = -1` and lets the
  poller retry.
- Keepalive: track `last_rx`. If `now - last_rx > 60s` and we haven't sent
  one in 30s, send `MSG_KEEPALIVE`. If `now - last_rx > 240s`, force-close.

## CLI

```
-Y, --newcamd host:port:user:pass:deskey:caid[,caid...]
```

v1: **not repeatable** — pass one flag with the CAID list you want
answered (up to `MAX_NEWCAMD_CONNS`, start at 8). `deskey` is the 14-byte
hex DES key from oscam's `[newcamd]` config (28 hex chars). We open one
TCP connection per CAID, all logging in to the same oscam.

Example:
```
minisatip -o ... -Y 192.168.1.10:15050:user:pass:0102030405060708091011121314:0500,0604
```

Coexists with `-o` (dvbapi); first CA that accepts a PMT wins via the
existing `ca_mask` machinery.

## Milestones

- [x] M0  Map integration surface — done.
- [x] M1  Plan (this doc) on `feat/newcamd`.
- [x] M2  Skeleton: `newcamd.h/.cpp`, `SCA_op` registration, CLI plumbing,
          `init_newcamd()` called from `tables_init()`, build option,
          compiles clean on macOS *and* Linux.
- [x] M3+M4  Connect + login + ECM/CW round-trip implemented in one pass
             after the protocol-spec cross-check: state-machine driven login
             (server-rand → login key → LOGIN → ACK → session key →
             CARD_DATA), DES-EDE2-CBC framing with random IV + checksum,
             repeatable `--newcamd` (one flag per port; CAID learned from
             `MSG_CARD_DATA`), ECM filter install in `ca_add_pmt`,
             `send_cw()` on CW reply. md5-crypt `$1$` reimplemented on top
             of OpenSSL MD5 (verified against `openssl passwd -1`) so the
             auth path works on macOS too.
- [ ] M5  Live testing against a real oscam; reconnect & keepalive
          hardening; provider id / EMM follow-ups.
- [ ] M6  Tests under `tests/test_newcamd.cpp` (unit: DES key derivation,
          frame round-trip; integration needs live oscam).

## Open questions / non-goals (for now)

- **EMM forwarding** — newcamd supports forwarding EMMs upstream (`0x82`/
  `0x83` tables) so the user's card gets updated. Out of scope for M2–M5;
  add behind a flag in a follow-up. Minisatip running *remote* from the
  card usually wants this off anyway (the dvbapi process closer to the
  card handles EMMs).
- **TLS** — newcamd has no native TLS; if exposing across networks, users
  should tunnel (wireguard/ssh). Not our problem.
- **Card sharing across minisatip instances** — not a goal; that's what
  cccam is for and we're explicitly not implementing it.
- **Anti-cascading** — oscam handles it server-side; nothing to do here.

## Risk register

| Risk | Mitigation |
|---|---|
| DES key derivation off by one — login silently fails | Unit test the key schedule against a captured oscam handshake. |
| Multiple PMTs share an ECM PID; double-filter installs | Reuse `get_pid_filter()` lookup before `add_filter()`. |
| Connection pool starvation when many channels share a CAID | One conn per CAID per reader is enough — oscam serializes ECM requests anyway. Just queue. |
| CW arrives after pmt stopped | Match on `pmt_id` validity in reply path; drop stale. |

## Code-locality cheat sheet

| What | Where |
|---|---|
| CA framework | `src/tables.h:28` (`SCA_op`), `src/tables.cpp` (`add_ca`, `init`) |
| Existing oscam client | `src/dvbapi.cpp` — copy the lifecycle shape, not the wire |
| CW delivery | `int send_cw(pmt_id, algo, parity, cw, iv, expiry, opaque)` @ `src/pmt.cpp:806` |
| Filter install | `add_filter_mask(aid, pid, cb, opaque, flags, filter, mask)` @ `src/pmt.cpp:257` |
| PMT CA descriptors | `pmt->ca[i]` populated by `pmt_add_caid` @ `src/pmt.cpp:1708` |
| socketworks pattern | `sockets_add` + `sockets_timeout` + `set_sockets_rtime`, mirror `src/dvbapi.cpp:570-589` |
| CLI plumbing | `src/minisatip.cpp:147` (long_options), `:199` (DVBAPI_OPT example), `:1029` (handler) |
| Opt parser | `src/opts.cpp` — add `parse_newcamd_opt()` next to `parse_dvbapi_opt` |
