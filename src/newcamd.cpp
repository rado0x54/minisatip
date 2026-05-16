/*
 * newcamd client for minisatip — see docs/NEWCAMD_PLAN.md
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 or later.
 *
 * Status: M2/M3 skeleton. Lifecycle (TCP connect, reconnect, CA-PMT plumbing,
 * ECM filter install, CW delivery) is real and exercised. The wire-level
 * crypto (3DES key derivation, login handshake framing, ECM/CW message
 * encryption) is marked TODO(newcamd-wire) and must be filled in against
 * a known-good reference (vdr-plugin-newcamd / oscam) before this client
 * will actually descramble.
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

#define DEFAULT_LOG LOG_NEWCAMD

#define NEWCAMD_DEFAULT_PORT 15050
#define NEWCAMD_CONNECT_RETRY_MS 5000
#define NEWCAMD_KEEPALIVE_IDLE_MS 60000
#define NEWCAMD_DEAD_MS 240000

#define MSG_CLIENT_2_SERVER_LOGIN 0xE0
#define MSG_CLIENT_2_SERVER_LOGIN_ACK 0xE1
#define MSG_CLIENT_2_SERVER_LOGIN_NAK 0xE2
#define MSG_CARD_DATA_REQ 0xE4
#define MSG_CARD_DATA 0xE5
#define MSG_KEEPALIVE 0xFB

static int newcamd_enabled = 0;
static char newcamd_host[100];
static int newcamd_port = NEWCAMD_DEFAULT_PORT;
static char newcamd_user[64];
static char newcamd_pass[64];
static uint8_t newcamd_deskey[NEWCAMD_DESKEY_LEN];
static uint16_t newcamd_caids[MAX_NEWCAMD_CAIDS];
static int newcamd_ncaids;

static SNewcamdConn *conns[MAX_NEWCAMD_CONNS];
static int nconns;

static SCA_op newcamd_ca_op;
static int newcamd_ca_id = -1;
static int newcamd_poller_sock = -1;

typedef struct struct_newcamd_key {
    int conn_idx;
    int pmt_id;
    int adapter;
    int ecm_pid;
    int filter_id;
} SNewcamdKey;

static SNewcamdKey *pmt_keys[MAX_NEWCAMD_CONNS * 64];
static int npmt_keys;

int newcamd_configured() { return newcamd_enabled; }

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

void parse_newcamd_opt(char *optarg) {
    // host:port:user:pass:deskey[:caid[,caid...]]
    char buf[512];
    safe_strncpy(buf, optarg);

    char *parts[6] = {NULL};
    int n = 0;
    char *p = buf;
    while (n < 6 && p) {
        parts[n++] = p;
        char *colon = strchr(p, ':');
        if (!colon)
            break;
        *colon = 0;
        p = colon + 1;
    }
    if (n < 5) {
        LOG("newcamd: bad --newcamd arg; expected "
            "host:port:user:pass:deskey[:caid[,caid...]]");
        return;
    }

    safe_strncpy(newcamd_host, parts[0]);
    newcamd_port = atoi(parts[1]);
    if (newcamd_port <= 0)
        newcamd_port = NEWCAMD_DEFAULT_PORT;
    safe_strncpy(newcamd_user, parts[2]);
    safe_strncpy(newcamd_pass, parts[3]);

    if (strlen(parts[4]) != NEWCAMD_DESKEY_LEN * 2 ||
        parse_hex(parts[4], newcamd_deskey, NEWCAMD_DESKEY_LEN) < 0) {
        LOG("newcamd: deskey must be %d hex chars", NEWCAMD_DESKEY_LEN * 2);
        return;
    }

    newcamd_ncaids = 0;
    if (n >= 6 && parts[5] && parts[5][0]) {
        char *caid_p = parts[5];
        while (caid_p && newcamd_ncaids < MAX_NEWCAMD_CAIDS) {
            char *comma = strchr(caid_p, ',');
            if (comma)
                *comma = 0;
            newcamd_caids[newcamd_ncaids++] =
                (uint16_t)strtoul(caid_p, NULL, 16);
            caid_p = comma ? comma + 1 : NULL;
        }
    }

    newcamd_enabled = 1;
    LOG("newcamd: configured %s:%d user=%s caids=%d", newcamd_host,
        newcamd_port, newcamd_user, newcamd_ncaids);
}

static SNewcamdConn *conn_for_caid(uint16_t caid) {
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->enabled && conns[i]->caid == caid)
            return conns[i];
    return NULL;
}

static void newcamd_close_conn(SNewcamdConn *c, const char *reason) {
    LOG("newcamd: closing conn for caid %04X (%s)", c->caid, reason);
    if (c->sock_id >= 0)
        sockets_del(c->sock_id);
    c->sock_id = -1;
    c->fd = -1;
    c->state = NEWCAMD_STATE_DISCONNECTED;
    memset(c->pending, 0, sizeof(c->pending));
}

static int newcamd_sock_close(sockets *s) {
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->sock_id == s->id) {
            conns[i]->fd = -1;
            conns[i]->sock_id = -1;
            conns[i]->state = NEWCAMD_STATE_DISCONNECTED;
            return 0;
        }
    return 0;
}

static int newcamd_sock_timeout(sockets *s) {
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->sock_id == s->id) {
            int64_t now = getTick();
            if (conns[i]->last_rx > 0 &&
                now - conns[i]->last_rx > NEWCAMD_DEAD_MS) {
                newcamd_close_conn(conns[i], "rx idle");
            }
            return 0;
        }
    return 0;
}

// TODO(newcamd-wire): real Triple-DES session key derivation.
// Reference: vdr-plugin-newcamd / oscam module_newcamd.c (key_*).
// The 14-byte configured deskey is expanded with parity to 16 bytes
// (DES_ede2 key1 || key2), then mixed with the server's 14 random
// "login key" bytes received on connect. This stub leaves session_key
// as the raw deskey + 2 zero bytes — it WILL NOT successfully
// authenticate against a real oscam.
[[maybe_unused]] static void derive_session_key(SNewcamdConn *c, const uint8_t *login_random,
                               int login_random_len) {
    (void)login_random;
    (void)login_random_len;
    memcpy(c->session_key, newcamd_deskey, NEWCAMD_DESKEY_LEN);
    c->session_key[14] = 0;
    c->session_key[15] = 0;
}

// TODO(newcamd-wire): real framing + Triple-DES-EDE2-CBC encrypt.
// For now this is a stub so the lifecycle compiles. Real implementation:
//   - prepend 3-byte (msg_id, len_hi, len_lo) header
//   - pad to 8-byte block
//   - 3DES-EDE2-CBC encrypt with c->session_key
//   - prepend 2-byte BE length
[[maybe_unused]] static int newcamd_send_msg(SNewcamdConn *c, uint8_t msg_id,
                            const uint8_t *payload, int len) {
    (void)c;
    (void)msg_id;
    (void)payload;
    (void)len;
    LOGM("newcamd: send_msg stub (msg %02X, len %d)", msg_id, len);
    return -1;
}

// TODO(newcamd-wire): real framing + decrypt.
[[maybe_unused]] static int newcamd_recv_msg(SNewcamdConn *c, uint8_t *out_msg_id,
                            uint8_t *out_payload, int max_len) {
    (void)c;
    (void)out_msg_id;
    (void)out_payload;
    (void)max_len;
    return -1;
}

[[maybe_unused]] static int newcamd_send_login(SNewcamdConn *c) {
    // TODO(newcamd-wire): build login payload:
    //   user '\0' crypt_md5(pass, "$1$abcdefgh$") '\0'
    // then newcamd_send_msg(c, MSG_CLIENT_2_SERVER_LOGIN, payload, len)
    LOG("newcamd: would send LOGIN for caid %04X user=%s", c->caid,
        newcamd_user);
    c->state = NEWCAMD_STATE_LOGIN_SENT;
    return 0;
}

[[maybe_unused]] static int newcamd_send_card_data_req(SNewcamdConn *c) {
    // TODO(newcamd-wire): newcamd_send_msg(c, MSG_CARD_DATA_REQ, NULL, 0)
    LOG("newcamd: would send CARD_DATA_REQ for caid %04X", c->caid);
    c->state = NEWCAMD_STATE_CARD_DATA_SENT;
    return 0;
}

static int newcamd_sock_reply(sockets *s) {
    // TODO(newcamd-wire): drain s->buf into framed/encrypted messages,
    // decrypt, dispatch:
    //   - first message (cleartext) on connect: 14-byte login random ->
    //     derive_session_key() then newcamd_send_login()
    //   - MSG_CLIENT_2_SERVER_LOGIN_ACK -> newcamd_send_card_data_req()
    //   - MSG_CARD_DATA -> state = READY
    //   - ECM reply -> match pending by seq, call send_cw()
    //   - MSG_KEEPALIVE -> reply with MSG_KEEPALIVE
    SNewcamdConn *c = NULL;
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->sock_id == s->id) {
            c = conns[i];
            break;
        }
    if (!c)
        return 0;
    c->last_rx = getTick();
    s->rlen = 0; // drain stub — real impl will parse and consume
    return 0;
}

static int newcamd_connect_one(SNewcamdConn *c) {
    int64_t now = getTick();
    if (c->state != NEWCAMD_STATE_DISCONNECTED)
        return 0;
    if (now - c->last_connect_attempt < NEWCAMD_CONNECT_RETRY_MS)
        return 0;
    c->last_connect_attempt = now;

    int fd = tcp_connect(newcamd_host, newcamd_port, NULL, 0);
    if (fd < 0) {
        LOG("newcamd: tcp connect %s:%d failed (caid %04X)", newcamd_host,
            newcamd_port, c->caid);
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
    sockets_timeout(sid, 5000);
    c->fd = fd;
    c->sock_id = sid;
    c->state = NEWCAMD_STATE_CONNECTING;
    c->last_rx = now;
    LOG("newcamd: connecting %s:%d for caid %04X", newcamd_host, newcamd_port,
        c->caid);
    return 0;
}

static int newcamd_poller(void *arg) {
    (void)arg;
    if (!newcamd_enabled)
        return 0;
    for (int i = 0; i < nconns; i++)
        if (conns[i] && conns[i]->enabled)
            newcamd_connect_one(conns[i]);
    return 0;
}

static int newcamd_ecm_cb(int filter_id, void *buf_v, int len, void *opaque) {
    uint8_t *b = (uint8_t *)buf_v;
    SNewcamdKey *k = (SNewcamdKey *)opaque;
    if (!k || k->filter_id != filter_id)
        return 0;
    SNewcamdConn *c = (k->conn_idx >= 0 && k->conn_idx < nconns)
                          ? conns[k->conn_idx]
                          : NULL;
    if (!c || c->state != NEWCAMD_STATE_READY)
        return 0;
    if (len < 3 || (b[0] != 0x80 && b[0] != 0x81))
        return 0;

    // TODO(newcamd-wire): build ECM request frame: 12-byte newcamd header
    //   (seq, sid, capid, pid, ...) + ECM section bytes; encrypt; send.
    //   Record pending[seq] = (pmt_id, parity, filter_id).
    c->seq++;
    LOGM("newcamd: ECM seq=%u caid=%04X pmt=%d parity=%d len=%d", c->seq,
         c->caid, k->pmt_id, b[0] & 1, len);
    return 0;
}

static SNewcamdKey *alloc_pmt_key() {
    for (int i = 0; i < (int)(sizeof(pmt_keys) / sizeof(pmt_keys[0])); i++)
        if (!pmt_keys[i]) {
            pmt_keys[i] = (SNewcamdKey *)calloc(1, sizeof(SNewcamdKey));
            if (i >= npmt_keys)
                npmt_keys = i + 1;
            return pmt_keys[i];
        }
    return NULL;
}

static void free_pmt_key(SNewcamdKey *k) {
    if (!k)
        return;
    if (k->filter_id >= 0)
        del_filter(k->filter_id);
    for (int i = 0; i < npmt_keys; i++)
        if (pmt_keys[i] == k) {
            pmt_keys[i] = NULL;
            break;
        }
    free(k);
}

static int newcamd_ca_add_pmt(adapter *ad, SPMT *pmt) {
    if (!newcamd_enabled)
        return TABLES_RESULT_ERROR_NORETRY;

    for (int i = 0; i < pmt->caids; i++) {
        SPMTCA *ca = pmt->ca[i];
        if (!ca)
            continue;
        SNewcamdConn *c = conn_for_caid(ca->id);
        if (!c)
            continue;
        if (c->state != NEWCAMD_STATE_READY) {
            LOG("newcamd: conn for caid %04X not ready (state %d), retry",
                ca->id, c->state);
            return TABLES_RESULT_ERROR_RETRY;
        }

        SNewcamdKey *k = alloc_pmt_key();
        if (!k)
            return TABLES_RESULT_ERROR_NORETRY;
        k->conn_idx = -1;
        for (int j = 0; j < nconns; j++)
            if (conns[j] == c) {
                k->conn_idx = j;
                break;
            }
        k->pmt_id = pmt->id;
        k->adapter = ad->id;
        k->ecm_pid = ca->pid;

        uint8_t flt[FILTER_SIZE] = {0x80};
        uint8_t msk[FILTER_SIZE] = {0xFE};
        k->filter_id = add_filter_mask(ad->id, ca->pid, (void *)newcamd_ecm_cb,
                                        k, FILTER_ADD_REMOVE | FILTER_CRC, flt,
                                        msk);
        if (k->filter_id < 0) {
            free_pmt_key(k);
            return TABLES_RESULT_ERROR_NORETRY;
        }
        pmt->opaque = k;
        LOG("newcamd: ca_add_pmt pmt=%d caid=%04X ecm_pid=%d filter=%d",
            pmt->id, ca->id, ca->pid, k->filter_id);
        return TABLES_RESULT_OK;
    }
    return TABLES_RESULT_ERROR_NORETRY;
}

static int newcamd_ca_del_pmt(adapter *ad, SPMT *pmt) {
    (void)ad;
    SNewcamdKey *k = (SNewcamdKey *)pmt->opaque;
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

void init_newcamd() {
    if (!newcamd_enabled)
        return;

    int want_caids = newcamd_ncaids;
    if (want_caids <= 0) {
        LOG("newcamd: no CAIDs configured, idle (will not bring up any conn)");
        return;
    }

    nconns = 0;
    for (int i = 0; i < want_caids && nconns < MAX_NEWCAMD_CONNS; i++) {
        SNewcamdConn *c = (SNewcamdConn *)calloc(1, sizeof(SNewcamdConn));
        if (!c)
            break;
        c->enabled = 1;
        c->state = NEWCAMD_STATE_DISCONNECTED;
        c->sock_id = -1;
        c->fd = -1;
        c->caid = newcamd_caids[i];
        conns[nconns++] = c;
    }

    memset(&newcamd_ca_op, 0, sizeof(newcamd_ca_op));
    newcamd_ca_op.ca_init_dev = newcamd_ca_init_dev;
    newcamd_ca_op.ca_add_pmt = newcamd_ca_add_pmt;
    newcamd_ca_op.ca_del_pmt = newcamd_ca_del_pmt;
    newcamd_ca_id = add_ca(&newcamd_ca_op);

    newcamd_poller_sock = sockets_add(SOCK_TIMEOUT, NULL, -1, TYPE_UDP, NULL,
                                       NULL, (socket_action)newcamd_poller);
    if (newcamd_poller_sock >= 0)
        sockets_timeout(newcamd_poller_sock, 1000);
    set_sockets_rtime(newcamd_poller_sock, -1000);

    LOG("newcamd: initialized, %d conn(s), ca_id=%d", nconns, newcamd_ca_id);
}

#endif // !DISABLE_NEWCAMD
