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

#define MAX_NEWCAMD_ENDPOINTS 8
#define MAX_NEWCAMD_PENDING 32
#define NEWCAMD_DESKEY_LEN 14
#define NEWCAMD_MSG_SIZE 512
#define NEWCAMD_HDR_LEN 8

#define NEWCAMD_STATE_DISCONNECTED 0
#define NEWCAMD_STATE_CONNECTING 1
#define NEWCAMD_STATE_AWAITING_RAND 2
#define NEWCAMD_STATE_LOGIN_SENT 3
#define NEWCAMD_STATE_CARD_DATA_SENT 4
#define NEWCAMD_STATE_READY 5

void init_newcamd();
int newcamd_configured();
void parse_newcamd_opt(char *optarg);

#endif // NEWCAMD_H
#endif // !DISABLE_NEWCAMD
