/*
 * newcamd client for minisatip — see docs/NEWCAMD_PLAN.md
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 or later.
 */

#ifndef DISABLE_NEWCAMD
#ifndef NEWCAMD_H
#define NEWCAMD_H

#include <stdint.h>

#define MAX_NEWCAMD_CONNS 8
#define MAX_NEWCAMD_CAIDS 8
#define MAX_NEWCAMD_PENDING 16
#define NEWCAMD_DESKEY_LEN 14
#define NEWCAMD_MSG_BUF 1024

#define NEWCAMD_STATE_DISCONNECTED 0
#define NEWCAMD_STATE_CONNECTING 1
#define NEWCAMD_STATE_LOGIN_SENT 2
#define NEWCAMD_STATE_CARD_DATA_SENT 3
#define NEWCAMD_STATE_READY 4

typedef struct struct_newcamd_pending {
    int in_use;
    uint16_t seq;
    int pmt_id;
    int filter_id;
    int parity;
    int64_t sent;
} SNewcamdPending;

typedef struct struct_newcamd_conn {
    int enabled;
    int state;
    int sock_id;
    int fd;
    uint16_t caid;
    uint16_t seq;
    int64_t last_rx;
    int64_t last_tx;
    int64_t last_connect_attempt;
    uint8_t session_key[16];
    uint8_t login_iv[16];
    SNewcamdPending pending[MAX_NEWCAMD_PENDING];
} SNewcamdConn;

void init_newcamd();
int newcamd_configured();
void parse_newcamd_opt(char *optarg);

#endif // NEWCAMD_H
#endif // !DISABLE_NEWCAMD
