#ifndef HDHOMERUN_H
#define HDHOMERUN_H

// DISABLE_HDHOMERUN is set by the build system (-include config.h in
// minisatip_lib; explicit -DDISABLE_HDHOMERUN in test targets).

#ifndef DISABLE_HDHOMERUN

#include "socketworks.h"

#define HDHR_MAX_CHANNELS 2000
#define HDHR_NAME_LEN 96
#define HDHR_URL_LEN 512
#define HDHR_DISCOVERY_PORT 65001

typedef struct hdhr_channel {
    int number;
    char name[HDHR_NAME_LEN];
    char url[HDHR_URL_LEN];
} hdhr_channel_t;

int hdhr_init(void);
int hdhr_handle_http(sockets *s, char **arg, int la);
int hdhr_udp_reply(sockets *s);

#endif // DISABLE_HDHOMERUN
#endif // HDHOMERUN_H
