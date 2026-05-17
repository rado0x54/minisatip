/*
 * newcamd client for minisatip.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 or later.
 *
 * Wire format references: OpenE2/CSP/etc/protocol.txt and the tsdecrypt
 * project's camd-newcamd.c. We use OpenSSL's DES_ede2_cbc_encrypt for the
 * standard EDE2-CBC framing — the protocol's three-stage description is
 * literally what that function does internally.
 *
 * macOS-friendly: we don't rely on libc crypt(3) (which on macOS only
 * implements legacy DES). md5_crypt_phk() below ports the Poul-Henning Kamp
 * algorithm using OpenSSL MD5, so the "$1$abcdefgh$..." password hashing
 * works on both Linux and macOS.
 */

#ifndef DISABLE_NEWCAMD

#include "newcamd.h"
#include "adapter.h"
#include "pmt.h"
#include "socketworks.h"
#include "tables.h"
#include "utils.h"
#include "utils/logging/logging.h"
#include "utils/ticks.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
// The newcamd wire protocol mandates DES-EDE2-CBC framing — every DES_* call
// below is protocol interop, not a chosen-cryptography decision. CodeQL flags
// the symbols anyway; we silence each call site with an explicit
// lgtm[cpp/weak-cryptographic-algorithm] annotation.
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#define DEFAULT_LOG LOG_NEWCAMD

#define NEWCAMD_DEFAULT_PORT 15050
#define NEWCAMD_CONNECT_RETRY_MS 10000
#define NEWCAMD_DEAD_MS 240000

#define MSG_CLIENT_2_SERVER_LOGIN 0xE0
#define MSG_CLIENT_2_SERVER_LOGIN_ACK 0xE1
#define MSG_CLIENT_2_SERVER_LOGIN_NAK 0xE2
#define MSG_CARD_DATA_REQ 0xE3
#define MSG_CARD_DATA 0xE4
#define MSG_KEEPALIVE 0xFD

#define NEWCAMD_CLIENT_ID 0x7878

typedef struct struct_newcamd_endpoint {
    char host[100];
    int port;
    char user[64];
    char pass[64];
    uint8_t deskey[NEWCAMD_DESKEY_LEN];
} SNewcamdEndpoint;

typedef struct struct_newcamd_pending {
    int in_use;
    uint16_t msg_id;
    int pmt_id;
    int parity;
    int filter_id;
    int64_t sent;
} SNewcamdPending;

typedef struct struct_newcamd_conn {
    int idx;
    int enabled;
    int state;
    int endpoint_idx;
    int sock_id;
    int fd;
    uint16_t caid;
    uint16_t msg_id;
    int64_t last_rx;
    int64_t last_connect_attempt;
    char crypt_pw[128];
    // ks1/ks2 are mutated by the socketworks thread during state transitions
    // (set_login_key, set_session_key) and read by the AD0 thread inside
    // newcamd_send_msg. Ordering invariant: state advances to READY *after*
    // the session key is installed, and ECM filters that drive AD0 sends
    // are only installed when state == READY (see ca_add_pmt). No lock
    // required as long as that invariant holds.
    DES_key_schedule ks1, ks2;
    SNewcamdPending pending[MAX_NEWCAMD_PENDING];
    uint8_t rxbuf[NEWCAMD_MSG_SIZE * 2];
} SNewcamdConn;

static SNewcamdEndpoint endpoints[MAX_NEWCAMD_ENDPOINTS];
static int nendpoints = 0;

static SNewcamdConn *conns[MAX_NEWCAMD_ENDPOINTS];
static int nconns = 0;
static SMutex conns_mutex;

typedef struct struct_newcamd_pmt_key {
    int conn_idx;
    int pmt_id;
    int adapter;
    int ecm_pid;
    int filter_id;
    uint16_t sid;
    int last_parity;
} SNewcamdPmtKey;

#define MAX_NEWCAMD_PMT_KEYS 256
static SNewcamdPmtKey *pmt_keys[MAX_NEWCAMD_PMT_KEYS];

static SCA_op newcamd_ca_op;
static int newcamd_ca_id = -1;
static int newcamd_poller_sock = -1;

// ---------- hex parsing -----------------------------------------------------

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        int hi = hex_nibble(s[i * 2]);
        int lo = hex_nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

// ---------- md5-crypt ($1$) — Poul-Henning Kamp algo via OpenSSL MD5 --------
// Produces "$1$<salt>$<hash>" matching glibc crypt(pw, "$1$<salt>$").

static const char itoa64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, unsigned long v, int n) {
    while (--n >= 0) {
        *s++ = itoa64[v & 0x3f];
        v >>= 6;
    }
}

static int md5_crypt_phk(const char *pw, const char *salt, char *out,
                         int out_len) {
    static const char *magic = "$1$";
    const char *sp = salt;
    if (!strncmp(sp, magic, strlen(magic)))
        sp += strlen(magic);
    const char *ep = sp;
    while (*ep && *ep != '$' && (ep - sp) < 8)
        ep++;
    int sl = (int)(ep - sp);
    int pwl = (int)strlen(pw);

    MD5_CTX ctx, ctx1;
    MD5_Init(&ctx);
    MD5_Update(&ctx, pw, pwl);
    MD5_Update(&ctx, magic, strlen(magic));
    MD5_Update(&ctx, sp, sl);

    MD5_Init(&ctx1);
    MD5_Update(&ctx1, pw, pwl);
    MD5_Update(&ctx1, sp, sl);
    MD5_Update(&ctx1, pw, pwl);
    unsigned char final_md[16];
    MD5_Final(final_md, &ctx1);

    for (int pl = pwl; pl > 0; pl -= 16)
        MD5_Update(&ctx, final_md, pl > 16 ? 16 : pl);
    memset(final_md, 0, sizeof(final_md));

    for (int i = pwl; i; i >>= 1) {
        if (i & 1)
            MD5_Update(&ctx, final_md, 1);
        else
            MD5_Update(&ctx, pw, 1);
    }
    MD5_Final(final_md, &ctx);

    for (int i = 0; i < 1000; i++) {
        MD5_Init(&ctx1);
        if (i & 1)
            MD5_Update(&ctx1, pw, pwl);
        else
            MD5_Update(&ctx1, final_md, 16);
        if (i % 3)
            MD5_Update(&ctx1, sp, sl);
        if (i % 7)
            MD5_Update(&ctx1, pw, pwl);
        if (i & 1)
            MD5_Update(&ctx1, final_md, 16);
        else
            MD5_Update(&ctx1, pw, pwl);
        MD5_Final(final_md, &ctx1);
    }

    int n = snprintf(out, out_len, "$1$%.*s$", sl, sp);
    if (n < 0 || n + 22 + 1 > out_len)
        return -1;
    char *p = out + n;
    unsigned long l;
    l = (final_md[0] << 16) | (final_md[6] << 8) | final_md[12];
    to64(p, l, 4);
    p += 4;
    l = (final_md[1] << 16) | (final_md[7] << 8) | final_md[13];
    to64(p, l, 4);
    p += 4;
    l = (final_md[2] << 16) | (final_md[8] << 8) | final_md[14];
    to64(p, l, 4);
    p += 4;
    l = (final_md[3] << 16) | (final_md[9] << 8) | final_md[15];
    to64(p, l, 4);
    p += 4;
    l = (final_md[4] << 16) | (final_md[10] << 8) | final_md[5];
    to64(p, l, 4);
    p += 4;
    l = final_md[11];
    to64(p, l, 2);
    p += 2;
    *p = 0;
    memset(final_md, 0, sizeof(final_md));
    return 0;
}

// ---------- newcamd key derivation -----------------------------------------

static void set_odd_parity(uint8_t *key) {
    DES_set_odd_parity((DES_cblock *)&key[0]); // lgtm[cpp/weak-cryptographic-algorithm]
    DES_set_odd_parity((DES_cblock *)&key[8]); // lgtm[cpp/weak-cryptographic-algorithm]
}

static void des_key_spread(uint8_t *spread, const uint8_t *normal) {
    spread[0] = normal[0] & 0xfe;
    spread[1] = ((normal[0] << 7) | (normal[1] >> 1)) & 0xfe;
    spread[2] = ((normal[1] << 6) | (normal[2] >> 2)) & 0xfe;
    spread[3] = ((normal[2] << 5) | (normal[3] >> 3)) & 0xfe;
    spread[4] = ((normal[3] << 4) | (normal[4] >> 4)) & 0xfe;
    spread[5] = ((normal[4] << 3) | (normal[5] >> 5)) & 0xfe;
    spread[6] = ((normal[5] << 2) | (normal[6] >> 6)) & 0xfe;
    spread[7] = normal[6] << 1;
    spread[8] = normal[7] & 0xfe;
    spread[9] = ((normal[7] << 7) | (normal[8] >> 1)) & 0xfe;
    spread[10] = ((normal[8] << 6) | (normal[9] >> 2)) & 0xfe;
    spread[11] = ((normal[9] << 5) | (normal[10] >> 3)) & 0xfe;
    spread[12] = ((normal[10] << 4) | (normal[11] >> 4)) & 0xfe;
    spread[13] = ((normal[11] << 3) | (normal[12] >> 5)) & 0xfe;
    spread[14] = ((normal[12] << 2) | (normal[13] >> 6)) & 0xfe;
    spread[15] = normal[13] << 1;
    set_odd_parity(spread);
}

static void schedule_key(SNewcamdConn *c, const uint8_t *spread16) {
    DES_key_sched((const_DES_cblock *)&spread16[0], &c->ks1); // lgtm[cpp/weak-cryptographic-algorithm]
    DES_key_sched((const_DES_cblock *)&spread16[8], &c->ks2); // lgtm[cpp/weak-cryptographic-algorithm]
}

static void set_login_key(SNewcamdConn *c, const uint8_t *server_rand) {
    uint8_t tmp[14], spread[16];
    const uint8_t *dk = endpoints[c->endpoint_idx].deskey;
    for (int i = 0; i < 14; i++)
        tmp[i] = server_rand[i] ^ dk[i];
    des_key_spread(spread, tmp); // lgtm[cpp/weak-cryptographic-algorithm]
    schedule_key(c, spread);
}

static void set_session_key(SNewcamdConn *c) {
    uint8_t tmp[14], spread[16];
    const uint8_t *dk = endpoints[c->endpoint_idx].deskey;
    memcpy(tmp, dk, 14);
    int crl = (int)strlen(c->crypt_pw);
    for (int i = 0; i < crl; i++)
        tmp[i % 14] ^= (uint8_t)c->crypt_pw[i];
    des_key_spread(spread, tmp); // lgtm[cpp/weak-cryptographic-algorithm]
    schedule_key(c, spread);
}

// ---------- send / receive --------------------------------------------------

static uint8_t xor_sum(const uint8_t *p, int len) {
    uint8_t cs = 0;
    while (len-- > 0)
        cs ^= *p++;
    return cs;
}

static int pad_and_checksum(uint8_t *data, int len) {
    DES_cblock pad;
    int npad = (8 - ((len - 1) % 8)) % 8;
    if (len + npad + 1 >= NEWCAMD_MSG_SIZE - 8)
        return -1;
    DES_random_key(&pad); // lgtm[cpp/weak-cryptographic-algorithm]
    memcpy(data + len, pad, npad);
    len += npad;
    data[len] = xor_sum(data + 2, len - 2);
    return len + 1;
}

static int newcamd_send_msg(SNewcamdConn *c, const uint8_t *payload,
                            int payload_len, uint16_t sid, int use_msg_id) {
    uint8_t buf[NEWCAMD_MSG_SIZE];

    if (c->fd < 0)
        return -1;
    if (payload_len < 3 || payload_len + NEWCAMD_HDR_LEN + 4 > NEWCAMD_MSG_SIZE)
        return -1;

    memset(&buf[2], 0, NEWCAMD_HDR_LEN + 2);
    memcpy(&buf[NEWCAMD_HDR_LEN + 4], payload, payload_len);
    buf[NEWCAMD_HDR_LEN + 4 + 1] =
        (payload[1] & 0xF0) | (((payload_len - 3) >> 8) & 0x0F);
    buf[NEWCAMD_HDR_LEN + 4 + 2] = (payload_len - 3) & 0xFF;

    int total = payload_len + 4;
    buf[4] = sid >> 8;
    buf[5] = sid & 0xFF;
    total += NEWCAMD_HDR_LEN;

    if (use_msg_id) {
        c->msg_id++;
        buf[2] = c->msg_id >> 8;
        buf[3] = c->msg_id & 0xFF;
    }

    total = pad_and_checksum(buf, total);
    if (total < 0)
        return -1;

    DES_cblock iv;
    DES_random_key(&iv); // lgtm[cpp/weak-cryptographic-algorithm]
    memcpy(buf + total, iv, sizeof(iv));
    DES_ede2_cbc_encrypt(buf + 2, buf + 2, total - 2, &c->ks1, &c->ks2,
                         (DES_cblock *)iv, DES_ENCRYPT); // lgtm[cpp/weak-cryptographic-algorithm]
    total += sizeof(iv);
    buf[0] = (total - 2) >> 8;
    buf[1] = (total - 2) & 0xFF;

    int w = write(c->fd, buf, total);
    return (w == total) ? 0 : -1;
}

// Decrypts a complete framed message in-place and returns the
// length of the inner payload (cmd + 12-bit length + data).
// `wirebuf` includes the 2-byte length prefix.
static int newcamd_decrypt_in_place(SNewcamdConn *c, uint8_t *wirebuf,
                                    int wirelen, uint8_t *out_payload,
                                    int max_out, uint16_t *out_msg_id) {
    if (wirelen < 2)
        return -1;
    int body = ((wirebuf[0] << 8) | wirebuf[1]) & 0xFFFF;
    if (body + 2 != wirelen)
        return -1;
    if (body % 8 || body < 16)
        return -1;
    DES_cblock iv;
    int enc_end = wirelen - 8;
    memcpy(iv, wirebuf + enc_end, 8);
    DES_ede2_cbc_encrypt(wirebuf + 2, wirebuf + 2, enc_end - 2, &c->ks1,
                         &c->ks2, (DES_cblock *)iv, DES_DECRYPT); // lgtm[cpp/weak-cryptographic-algorithm]
    if (xor_sum(wirebuf + 2, enc_end - 2) != 0)
        return -1;

    int payload_off = 4 + NEWCAMD_HDR_LEN;
    if (payload_off + 3 > enc_end)
        return -1;
    int paylen = (((wirebuf[payload_off + 1] & 0x0F) << 8) |
                  wirebuf[payload_off + 2]) +
                 3;
    if (paylen > max_out || payload_off + paylen > enc_end)
        return -1;
    if (out_msg_id)
        *out_msg_id = (wirebuf[2] << 8) | wirebuf[3];
    memcpy(out_payload, wirebuf + payload_off, paylen);
    return paylen;
}

// ---------- pending ECMs ---------------------------------------------------

static SNewcamdPending *find_pending(SNewcamdConn *c, uint16_t msg_id) {
    for (int i = 0; i < MAX_NEWCAMD_PENDING; i++)
        if (c->pending[i].in_use && c->pending[i].msg_id == msg_id)
            return &c->pending[i];
    return NULL;
}

static SNewcamdPending *alloc_pending(SNewcamdConn *c) {
    for (int i = 0; i < MAX_NEWCAMD_PENDING; i++)
        if (!c->pending[i].in_use)
            return &c->pending[i];
    return NULL;
}

static void clear_pending_for_filter(SNewcamdConn *c, int filter_id) {
    for (int i = 0; i < MAX_NEWCAMD_PENDING; i++)
        if (c->pending[i].in_use && c->pending[i].filter_id == filter_id)
            c->pending[i].in_use = 0;
}

#define NEWCAMD_PENDING_TIMEOUT_MS 5000

static void sweep_stale_pending(SNewcamdConn *c) {
    int64_t now = getTick();
    for (int i = 0; i < MAX_NEWCAMD_PENDING; i++)
        if (c->pending[i].in_use &&
            now - c->pending[i].sent > NEWCAMD_PENDING_TIMEOUT_MS) {
            LOGM("newcamd[%d]: timing out stale pending msg_id=%04X pmt=%d",
                 c->idx, c->pending[i].msg_id, c->pending[i].pmt_id);
            c->pending[i].in_use = 0;
        }
}

// ---------- protocol state machine -----------------------------------------

static void newcamd_send_login(SNewcamdConn *c) {
    SNewcamdEndpoint *e = &endpoints[c->endpoint_idx];
    if (md5_crypt_phk(e->pass, "$1$abcdefgh$", c->crypt_pw,
                       sizeof(c->crypt_pw)) < 0) {
        LOG("newcamd[%d]: md5_crypt failed", c->idx);
        return;
    }
    int userLen = (int)strlen(e->user) + 1;
    int passLen = (int)strlen(c->crypt_pw) + 1;
    uint8_t buf[NEWCAMD_MSG_SIZE];
    buf[0] = MSG_CLIENT_2_SERVER_LOGIN;
    buf[1] = 0;
    buf[2] = (uint8_t)(userLen + passLen);
    memcpy(&buf[3], e->user, userLen);
    memcpy(&buf[3 + userLen], c->crypt_pw, passLen);

    c->msg_id = 0;
    int rc;
    {
        std::lock_guard<SMutex> lock(conns_mutex);
        rc = newcamd_send_msg(c, buf, buf[2] + 3, NEWCAMD_CLIENT_ID, 1);
    }
    if (rc < 0) {
        LOG("newcamd[%d]: failed to send LOGIN", c->idx);
        return;
    }
    c->state = NEWCAMD_STATE_LOGIN_SENT;
    LOG("newcamd[%d]: LOGIN sent user=%s", c->idx, e->user);
}

static void newcamd_send_card_data_req(SNewcamdConn *c) {
    uint8_t buf[3] = {MSG_CARD_DATA_REQ, 0, 0};
    int rc;
    {
        std::lock_guard<SMutex> lock(conns_mutex);
        rc = newcamd_send_msg(c, buf, 3, 0, 0);
    }
    if (rc < 0) {
        LOG("newcamd[%d]: failed to send CARD_DATA_REQ", c->idx);
        return;
    }
    c->state = NEWCAMD_STATE_CARD_DATA_SENT;
    LOG("newcamd[%d]: CARD_DATA_REQ sent", c->idx);
}

static void newcamd_close_conn(SNewcamdConn *c, const char *reason);

static void newcamd_on_login_rand(SNewcamdConn *c, const uint8_t *rand14) {
    set_login_key(c, rand14);
    newcamd_send_login(c);
}

static void newcamd_handle_card_data(SNewcamdConn *c, const uint8_t *payload,
                                     int len) {
    if (len < 7) {
        LOG("newcamd[%d]: CARD_DATA too short (%d)", c->idx, len);
        newcamd_close_conn(c, "short card_data");
        return;
    }
    uint16_t caid = ((uint16_t)payload[4] << 8) | payload[5];
    if (caid == 0) {
        LOG("newcamd[%d]: CARD_DATA reports caid=0, rejecting", c->idx);
        newcamd_close_conn(c, "invalid caid");
        return;
    }
    int admin = payload[3];
    int nprov = (len > 11) ? payload[11] : 0;
    c->caid = caid;
    c->state = NEWCAMD_STATE_READY;
    LOG("newcamd[%d]: READY caid=%04X admin=%d providers=%d", c->idx, caid,
        admin, nprov);
}

static void newcamd_handle_ecm_reply(SNewcamdConn *c, uint16_t msg_id,
                                     const uint8_t *payload, int len) {
    SNewcamdPending *p = find_pending(c, msg_id);
    if (!p) {
        LOGM("newcamd[%d]: stray ECM reply msg_id=%04X", c->idx, msg_id);
        return;
    }
    p->in_use = 0;
    if (len == 19 && (payload[0] == 0x80 || payload[0] == 0x81)) {
        SPMT *pmt = get_pmt(p->pmt_id);
        if (!pmt) {
            LOG("newcamd[%d]: ECM CW for stale pmt %d", c->idx, p->pmt_id);
            return;
        }
        const uint8_t *cw_even = payload + 3;
        const uint8_t *cw_odd = payload + 3 + 8;
        uint8_t cw16[16];
        memcpy(cw16, cw_even, 8);
        memcpy(cw16 + 8, cw_odd, 8);
        send_cw(p->pmt_id, CA_ALGO_DVBCSA, p->parity,
                p->parity ? cw16 + 8 : cw16, NULL, 0, c);
        LOGM("newcamd[%d]: CW pmt=%d parity=%d", c->idx, p->pmt_id, p->parity);
    } else if (len == 3) {
        LOGM("newcamd[%d]: card couldn't decode (pmt=%d)", c->idx, p->pmt_id);
    } else {
        LOG("newcamd[%d]: unexpected ECM reply len=%d", c->idx, len);
    }
}

static int newcamd_process_one(SNewcamdConn *c, uint8_t *wirebuf, int wirelen) {
    uint8_t payload[NEWCAMD_MSG_SIZE];
    uint16_t msg_id = 0;
    int plen =
        newcamd_decrypt_in_place(c, wirebuf, wirelen, payload, sizeof(payload),
                                  &msg_id);
    if (plen < 1) {
        LOG("newcamd[%d]: decrypt failed (state=%d, wire=%d)", c->idx, c->state,
            wirelen);
        newcamd_close_conn(c, "bad packet");
        return -1;
    }
    uint8_t cmd = payload[0];

    switch (c->state) {
    case NEWCAMD_STATE_LOGIN_SENT:
        if (cmd == MSG_CLIENT_2_SERVER_LOGIN_ACK) {
            set_session_key(c);
            newcamd_send_card_data_req(c);
        } else {
            LOG("newcamd[%d]: LOGIN rejected (cmd=%02X)", c->idx, cmd);
            newcamd_close_conn(c, "login nak");
        }
        break;
    case NEWCAMD_STATE_CARD_DATA_SENT:
        if (cmd == MSG_CARD_DATA) {
            newcamd_handle_card_data(c, payload, plen);
        } else {
            LOG("newcamd[%d]: expected CARD_DATA got %02X", c->idx, cmd);
            newcamd_close_conn(c, "no card_data");
        }
        break;
    case NEWCAMD_STATE_READY:
        if (cmd == 0x80 || cmd == 0x81) {
            newcamd_handle_ecm_reply(c, msg_id, payload, plen);
        } else if (cmd == MSG_KEEPALIVE) {
            uint8_t ka[3] = {MSG_KEEPALIVE, 0, 0};
            std::lock_guard<SMutex> lock(conns_mutex);
            newcamd_send_msg(c, ka, 3, 0, 0);
        } else {
            LOGM("newcamd[%d]: unhandled cmd %02X in READY", c->idx, cmd);
        }
        break;
    default:
        LOG("newcamd[%d]: unexpected packet in state %d", c->idx, c->state);
        break;
    }
    // Any close path inside the switch (login NAK, missing CARD_DATA,
    // short/invalid CARD_DATA) drops the conn and frees s->buf via
    // sockets_del. Signal the caller to stop touching s->buf.
    if (c->state == NEWCAMD_STATE_DISCONNECTED)
        return -1;
    return 0;
}

// ---------- socketworks callbacks ------------------------------------------

static void newcamd_close_conn(SNewcamdConn *c, const char *reason) {
    LOG("newcamd[%d]: closing (%s)", c->idx, reason);
    std::lock_guard<SMutex> lock(conns_mutex);
    if (c->sock_id >= 0)
        sockets_del(c->sock_id);
    c->sock_id = -1;
    c->fd = -1;
    c->state = NEWCAMD_STATE_DISCONNECTED;
    c->msg_id = 0;
    c->caid = 0;
    memset(c->pending, 0, sizeof(c->pending));
}

static SNewcamdConn *conn_for_sock(int sock_id) {
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->sock_id == sock_id)
            return conns[i];
    return NULL;
}

static int newcamd_sock_close(sockets *s) {
    SNewcamdConn *c = conn_for_sock(s->id);
    if (c) {
        c->fd = -1;
        c->sock_id = -1;
        c->state = NEWCAMD_STATE_DISCONNECTED;
        c->caid = 0;
        memset(c->pending, 0, sizeof(c->pending));
    }
    return 0;
}

static int newcamd_sock_timeout(sockets *s) {
    SNewcamdConn *c = conn_for_sock(s->id);
    if (!c)
        return 0;
    {
        std::lock_guard<SMutex> lock(conns_mutex);
        sweep_stale_pending(c);
    }
    int64_t now = getTick();
    if (c->state >= NEWCAMD_STATE_READY && c->last_rx > 0 &&
        now - c->last_rx > NEWCAMD_DEAD_MS) {
        newcamd_close_conn(c, "rx idle");
    }
    return 0;
}

static int newcamd_sock_reply(sockets *s) {
    SNewcamdConn *c = conn_for_sock(s->id);
    if (!c)
        return 0;
    if (s->rlen == 0)
        return 0; // connect completion, nothing yet
    c->last_rx = getTick();

    // CONNECTING transitions to AWAITING_RAND on first byte.
    if (c->state == NEWCAMD_STATE_CONNECTING)
        c->state = NEWCAMD_STATE_AWAITING_RAND;

    // Initial 14-byte cleartext server random has no length prefix.
    if (c->state == NEWCAMD_STATE_AWAITING_RAND) {
        if (s->rlen < 14)
            return 0;
        uint8_t rand14[14];
        memcpy(rand14, s->buf, 14);
        memmove(s->buf, s->buf + 14, s->rlen - 14);
        s->rlen -= 14;
        newcamd_on_login_rand(c, rand14);
        if (s->rlen == 0)
            return 0;
        // fall through — more data may already be queued
    }

    while (s->rlen >= 2) {
        int body = ((s->buf[0] << 8) | s->buf[1]) & 0xFFFF;
        if (body + 2 > (int)sizeof(c->rxbuf)) {
            newcamd_close_conn(c, "oversized packet");
            return 0;
        }
        if (s->rlen < body + 2)
            break; // wait for more
        if (newcamd_process_one(c, s->buf, body + 2) < 0)
            return 0; // conn closed
        memmove(s->buf, s->buf + body + 2, s->rlen - (body + 2));
        s->rlen -= (body + 2);
    }
    return 0;
}

static int newcamd_connect_one(SNewcamdConn *c) {
    int64_t now = getTick();
    if (c->state != NEWCAMD_STATE_DISCONNECTED)
        return 0;
    if (c->last_connect_attempt &&
        now - c->last_connect_attempt < NEWCAMD_CONNECT_RETRY_MS)
        return 0;
    c->last_connect_attempt = now;

    SNewcamdEndpoint *e = &endpoints[c->endpoint_idx];
    int fd = tcp_connect(e->host, e->port, NULL, 0);
    if (fd < 0) {
        LOG("newcamd[%d]: tcp_connect %s:%d failed", c->idx, e->host, e->port);
        return -1;
    }
    int sid =
        sockets_add(fd, NULL, -1, TYPE_TCP | TYPE_CONNECT,
                    (socket_action)newcamd_sock_reply,
                    (socket_action)newcamd_sock_close,
                    (socket_action)newcamd_sock_timeout);
    if (sid < 0) {
        close(fd);
        return -1;
    }
    set_socket_buffer(sid, c->rxbuf, sizeof(c->rxbuf));
    sockets_timeout(sid, 5000);
    c->fd = fd;
    c->sock_id = sid;
    c->state = NEWCAMD_STATE_CONNECTING;
    c->last_rx = now;
    LOG("newcamd[%d]: connecting %s:%d", c->idx, e->host, e->port);
    return 0;
}

static int newcamd_poller(void *arg) {
    (void)arg;
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->enabled)
            newcamd_connect_one(conns[i]);
    return 0;
}

// ---------- ECM filter callback + CA hooks ---------------------------------

static SNewcamdConn *conn_for_caid_locked(uint16_t caid) {
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->state == NEWCAMD_STATE_READY &&
            conns[i]->caid == caid)
            return conns[i];
    return NULL;
}

static int newcamd_ecm_cb(int filter_id, void *buf_v, int len, void *opaque) {
    uint8_t *b = (uint8_t *)buf_v;
    SNewcamdPmtKey *k = (SNewcamdPmtKey *)opaque;
    if (!k || k->filter_id != filter_id)
        return 0;
    if (len < 3 || (b[0] != 0x80 && b[0] != 0x81))
        return 0;
    SNewcamdConn *c = (k->conn_idx >= 0 && k->conn_idx < nconns)
                          ? conns[k->conn_idx]
                          : NULL;
    if (!c || c->state != NEWCAMD_STATE_READY)
        return 0;

    int parity = b[0] & 1;
    if (parity == k->last_parity)
        return 0;

    int ecm_len = (((b[1] & 0x0F) << 8) | b[2]) + 3;
    if (ecm_len > len || ecm_len > NEWCAMD_MSG_SIZE - 32)
        return 0;

    std::lock_guard<SMutex> lock(conns_mutex);
    if (newcamd_send_msg(c, b, ecm_len, k->sid, 1) < 0) {
        LOG("newcamd[%d]: send ECM failed (pmt=%d)", c->idx, k->pmt_id);
        return 0;
    }
    SNewcamdPending *p = alloc_pending(c);
    if (p) {
        p->in_use = 1;
        p->msg_id = c->msg_id;
        p->pmt_id = k->pmt_id;
        p->parity = parity;
        p->filter_id = filter_id;
        p->sent = getTick();
    }
    k->last_parity = parity;
    LOGM("newcamd[%d]: ECM pmt=%d caid=%04X sid=%04X parity=%d len=%d msg_id=%04X",
         c->idx, k->pmt_id, c->caid, k->sid, parity, ecm_len, c->msg_id);
    return 0;
}

static SNewcamdPmtKey *alloc_pmt_key() {
    for (int i = 0; i < MAX_NEWCAMD_PMT_KEYS; i++)
        if (!pmt_keys[i]) {
            pmt_keys[i] = (SNewcamdPmtKey *)calloc(1, sizeof(SNewcamdPmtKey));
            return pmt_keys[i];
        }
    return NULL;
}

static void free_pmt_key(SNewcamdPmtKey *k) {
    if (!k)
        return;
    if (k->filter_id >= 0) {
        if (k->conn_idx >= 0 && k->conn_idx < nconns && conns[k->conn_idx]) {
            std::lock_guard<SMutex> lock(conns_mutex);
            clear_pending_for_filter(conns[k->conn_idx], k->filter_id);
        }
        del_filter(k->filter_id);
    }
    for (int i = 0; i < MAX_NEWCAMD_PMT_KEYS; i++)
        if (pmt_keys[i] == k) {
            pmt_keys[i] = NULL;
            break;
        }
    free(k);
}

static int newcamd_ca_add_pmt(adapter *ad, SPMT *pmt) {
    if (nconns == 0)
        return TABLES_RESULT_ERROR_NORETRY;

    // pmt->opaque is a single slot shared with dvbapi; if someone else
    // already claimed this PMT (e.g. --dvbapi running alongside us),
    // stand down so del_pmt doesn't try to free the wrong object.
    if (pmt->opaque)
        return TABLES_RESULT_ERROR_NORETRY;

    // A PMT may list several CAIDs across providers; we pick the first one
    // we have a configured reader for and wire up a single decode for it.
    // pmt->opaque is a single slot, so it's one decode per PMT regardless.
    std::lock_guard<SMutex> lock(conns_mutex);
    for (int i = 0; i < pmt->caids; i++) {
        SPMTCA *ca = pmt->ca[i];
        if (!ca)
            continue;
        SNewcamdConn *c = conn_for_caid_locked(ca->id);
        if (!c)
            continue;

        SNewcamdPmtKey *k = alloc_pmt_key();
        if (!k)
            return TABLES_RESULT_ERROR_NORETRY;
        k->conn_idx = c->idx;
        k->pmt_id = pmt->id;
        k->adapter = ad->id;
        k->ecm_pid = ca->pid;
        k->sid = pmt->sid;
        k->last_parity = -1;
        k->filter_id = -1;

        uint8_t flt[FILTER_SIZE] = {0x80};
        uint8_t msk[FILTER_SIZE] = {0xFE};
        k->filter_id = add_filter_mask(ad->id, ca->pid, (void *)newcamd_ecm_cb,
                                        k, FILTER_ADD_REMOVE, flt, msk);
        if (k->filter_id < 0) {
            free_pmt_key(k);
            return TABLES_RESULT_ERROR_NORETRY;
        }
        pmt->opaque = k;
        LOG("newcamd[%d]: ca_add_pmt pmt=%d caid=%04X sid=%04X ecm_pid=%d",
            c->idx, pmt->id, ca->id, pmt->sid, ca->pid);
        return TABLES_RESULT_OK;
    }
    // No conn ready for any of this PMT's CAIDs yet — retry later.
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->state != NEWCAMD_STATE_READY)
            return TABLES_RESULT_ERROR_RETRY;
    return TABLES_RESULT_ERROR_NORETRY;
}

static int newcamd_ca_del_pmt(adapter *ad, SPMT *pmt) {
    (void)ad;
    SNewcamdPmtKey *k = (SNewcamdPmtKey *)pmt->opaque;
    if (k) {
        LOG("newcamd: ca_del_pmt pmt=%d", pmt->id);
        free_pmt_key(k);
        pmt->opaque = NULL;
    }
    return TABLES_RESULT_OK;
}

static int newcamd_ca_init_dev(adapter *ad) {
    (void)ad;
    if (newcamd_poller_sock >= 0)
        set_sockets_rtime(newcamd_poller_sock, 0);
    return TABLES_RESULT_OK;
}

// ---------- CLI parsing & init ---------------------------------------------

static void parse_one_endpoint(char *spec) {
    if (nendpoints >= MAX_NEWCAMD_ENDPOINTS) {
        LOG("newcamd: too many endpoints (max %d)", MAX_NEWCAMD_ENDPOINTS);
        return;
    }

    char *parts[5] = {NULL};
    int n = 0;
    char *p = spec;
    while (n < 5 && p) {
        parts[n++] = p;
        char *colon = strchr(p, ':');
        if (!colon)
            break;
        *colon = 0;
        p = colon + 1;
    }
    if (n < 5) {
        LOG("newcamd: bad endpoint spec; expected "
            "host:port:user:pass:deskey");
        return;
    }

    SNewcamdEndpoint *e = &endpoints[nendpoints];
    safe_strncpy(e->host, parts[0]);
    e->port = atoi(parts[1]);
    if (e->port <= 0)
        e->port = NEWCAMD_DEFAULT_PORT;
    safe_strncpy(e->user, parts[2]);
    safe_strncpy(e->pass, parts[3]);

    if (strlen(parts[4]) != NEWCAMD_DESKEY_LEN * 2 ||
        parse_hex(parts[4], e->deskey, NEWCAMD_DESKEY_LEN) < 0) {
        LOG("newcamd: deskey must be %d hex chars", NEWCAMD_DESKEY_LEN * 2);
        return;
    }

    LOG("newcamd[%d]: configured %s:%d user=%s", nendpoints, e->host, e->port,
        e->user);
    nendpoints++;
}

void parse_newcamd_opt(char *optarg) {
    // host:port:user:pass:deskey[,host:port:user:pass:deskey...]
    char buf[1024];
    if (strlen(optarg) >= sizeof(buf))
        LOG("newcamd: --newcamd / MINISAT_NEWCAMD truncated at %zu bytes; "
            "trailing endpoint(s) may be dropped",
            sizeof(buf) - 1);
    safe_strncpy(buf, optarg);

    char *p = buf;
    while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
            *comma = 0;
        parse_one_endpoint(p);
        p = comma ? comma + 1 : NULL;
    }
}

void init_newcamd() {
    char *envarg = getenv("MINISAT_NEWCAMD");
    if (envarg && *envarg)
        parse_newcamd_opt(envarg);

    if (nendpoints == 0)
        return;

    nconns = 0;
    for (int i = 0; i < nendpoints; i++) {
        SNewcamdConn *c = (SNewcamdConn *)calloc(1, sizeof(SNewcamdConn));
        if (!c)
            break;
        c->idx = nconns;
        c->endpoint_idx = i;
        c->enabled = 1;
        c->state = NEWCAMD_STATE_DISCONNECTED;
        c->sock_id = -1;
        c->fd = -1;
        conns[nconns++] = c;
    }

    memset(&newcamd_ca_op, 0, sizeof(newcamd_ca_op));
    newcamd_ca_op.ca_init_dev = newcamd_ca_init_dev;
    newcamd_ca_op.ca_add_pmt = newcamd_ca_add_pmt;
    newcamd_ca_op.ca_del_pmt = newcamd_ca_del_pmt;
    newcamd_ca_id = add_ca(&newcamd_ca_op);

    newcamd_poller_sock =
        sockets_add(SOCK_TIMEOUT, NULL, -1, TYPE_UDP, NULL, NULL,
                    (socket_action)newcamd_poller);
    if (newcamd_poller_sock >= 0)
        sockets_timeout(newcamd_poller_sock, 1000);
    set_sockets_rtime(newcamd_poller_sock, -1000);

    LOG("newcamd: initialized, %d conn(s), ca_id=%d", nconns, newcamd_ca_id);
}

#pragma GCC diagnostic pop
#endif // !DISABLE_NEWCAMD
