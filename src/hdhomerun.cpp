/*
 * HDHomeRun tuner emulation for minisatip.
 *
 * Exposes the SiliconDust HDHomeRun HTTP control surface
 * (/discover.json, /lineup.json, /lineup_status.json, /device.xml,
 * /lineup.post) plus the UDP discovery responder on port 65001.
 * Channel inventory is read from an M3U file supplied via
 * --hdhomerun-channels. Per-request stream URLs are rewritten to
 * use whatever Host the client used to reach us, so callers always
 * get back URLs that resolve from their perspective.
 */

#include "config.h"

#ifndef DISABLE_HDHOMERUN

#include "hdhomerun.h"
#include "adapter.h"
#include "minisatip.h"
#include "opts.h"
#include "socketworks.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_LOG LOG_HTTP

static hdhr_channel_t hdhr_channels[HDHR_MAX_CHANNELS];
static int hdhr_channel_count = 0;
static uint32_t hdhr_device_id = 0;

// HDHomeRun discovery TLV tags
#define HDHR_TAG_DEVICE_TYPE 0x01
#define HDHR_TAG_DEVICE_ID 0x02
#define HDHR_TAG_TUNER_COUNT 0x10
#define HDHR_TAG_DEVICE_AUTH_BIN 0x29
#define HDHR_TAG_BASE_URL 0x2A
#define HDHR_TAG_DEVICE_AUTH 0x2B
#define HDHR_TYPE_DISCOVER_REQ 0x0002
#define HDHR_TYPE_DISCOVER_RPY 0x0003
#define HDHR_DEVICE_TYPE_TUNER 0x00000001

// IEEE 802.3 CRC32 table (polynomial 0xEDB88320, reflected)
static uint32_t hdhr_crc_table[256];
static int hdhr_crc_table_built = 0;

static void hdhr_build_crc_table(void) {
    if (hdhr_crc_table_built)
        return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        hdhr_crc_table[i] = c;
    }
    hdhr_crc_table_built = 1;
}

static uint32_t hdhr_crc32(const uint8_t *buf, int len) {
    hdhr_build_crc_table();
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
        crc = (crc >> 8) ^ hdhr_crc_table[(crc ^ buf[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

// Count physical adapter slots (frontends) — the right HDHR TunerCount.
// getAdaptersCount() sums per-delivery-system counters, so a dual-FE
// adapter that supports two delsys (e.g. WinTV-dualHD: DVB-T2 + DVB-C
// on each of its 2 FEs) would inflate to 4. Walking a[] gives the actual
// number of concurrent streams the device can serve.
static int active_tuner_count(void) {
    int n = 0;
    for (int i = 0; i < MAX_ADAPTERS; i++)
        if (a[i])
            n++;
    if (n < 1)
        n = 1;
    if (n > 16)
        n = 16;
    return n;
}

// Derive an 8-hex DeviceID from opts.uuid (which is stable across boots once
// generated). HDHomeRun DeviceIDs are nominally 32-bit; we hash the uuid
// string with FNV-1a so two minisatip instances on the same LAN with
// distinct UUIDs end up with distinct IDs.
static void hdhr_compute_device_id(void) {
    uint32_t h = 0x811C9DC5;
    const char *p = opts.uuid;
    while (*p) {
        h ^= (uint8_t)*p++;
        h *= 0x01000193;
    }
    // Avoid the well-known 0xFFFFFFFF wildcard.
    if (h == 0xFFFFFFFF)
        h = 0x10000000;
    hdhr_device_id = h;
}

static char *trim(char *s) {
    if (!s)
        return s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
                     e[-1] == '\n'))
        *--e = 0;
    return s;
}

static int hdhr_load_m3u(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG("HDHR: cannot open M3U %s: %s", path, strerror(errno));
        return -1;
    }
    char line[1024];
    char pending_name[HDHR_NAME_LEN] = {0};
    int have_pending = 0;
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char *t = trim(line);
        if (!*t)
            continue;
        if (t[0] == '#') {
            if (strncmp(t, "#EXTINF", 7) == 0) {
                char *comma = strchr(t, ',');
                if (comma) {
                    char *name = trim(comma + 1);
                    safe_strncpy(pending_name, name);
                    have_pending = 1;
                }
            }
            continue;
        }
        // non-comment, non-empty: URL line (only consume if preceded by EXTINF)
        if (!have_pending)
            continue;
        if (count >= HDHR_MAX_CHANNELS) {
            LOG("HDHR: M3U has more than %d channels; truncating",
                HDHR_MAX_CHANNELS);
            break;
        }
        hdhr_channels[count].number = count + 1;
        safe_strncpy(hdhr_channels[count].name, pending_name);
        safe_strncpy(hdhr_channels[count].url, t);
        count++;
        have_pending = 0;
    }
    fclose(f);
    hdhr_channel_count = count;
    struct stat st;
    if (stat(path, &st) == 0)
        opts.hdhr_m3u_mtime = st.st_mtime;
    LOG("HDHR: loaded %d channels from %s", count, path);
    return count;
}

static void hdhr_maybe_reload(void) {
    if (!opts.hdhr_playlist_path)
        return;
    struct stat st;
    if (stat(opts.hdhr_playlist_path, &st) != 0)
        return;
    if (st.st_mtime != opts.hdhr_m3u_mtime)
        hdhr_load_m3u(opts.hdhr_playlist_path);
}

// Extract host[:port] from the request. Returns whatever the client used
// to reach us so URLs in the lineup resolve from their perspective.
// Falls back to the locally-bound socket address + opts.http_port.
static void hdhr_get_request_host(char **arg, int la, sockets *s, char *out,
                                  int outsz) {
    char *hostval = NULL;
    for (int i = 0; i < la; i++) {
        if (arg[i] && strncasecmp("Host:", arg[i], 5) == 0) {
            hostval = header_parameter(arg, i);
            break;
        }
    }
    if (hostval) {
        char *t = trim(hostval);
        if (*t) {
            if (strchr(t, ':')) {
                snprintf(out, outsz, "%s", t);
            } else {
                snprintf(out, outsz, "%s:%u", t, opts.http_port);
            }
            return;
        }
    }
    char localip[64];
    if (s && get_sock_shost(s->sock, localip, sizeof(localip)))
        snprintf(out, outsz, "%s:%u", localip, opts.http_port);
    else
        snprintf(out, outsz, "127.0.0.1:%u", opts.http_port);
}

// Rewrite the scheme+host[:port] prefix of `src_url` to use `new_host`.
// If src_url doesn't have a recognisable scheme://, prefix it with
// http://<new_host> directly.
static void hdhr_rewrite_url(const char *src_url, const char *new_host,
                             char *out, int outsz) {
    const char *p = strstr(src_url, "://");
    if (!p) {
        snprintf(out, outsz, "http://%s%s%s", new_host,
                 src_url[0] == '/' ? "" : "/", src_url);
        return;
    }
    const char *path = strchr(p + 3, '/');
    if (!path)
        path = "/";
    snprintf(out, outsz, "http://%s%s", new_host, path);
}

static int json_escape(const char *src, char *dst, int dstsz) {
    int o = 0;
    for (const char *p = src; *p && o + 6 < dstsz; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            dst[o++] = '\\';
            dst[o++] = c;
        } else if (c == '\n') {
            dst[o++] = '\\';
            dst[o++] = 'n';
        } else if (c == '\r') {
            dst[o++] = '\\';
            dst[o++] = 'r';
        } else if (c == '\t') {
            dst[o++] = '\\';
            dst[o++] = 't';
        } else if (c < 0x20) {
            o += snprintf(dst + o, dstsz - o, "\\u%04x", c);
        } else {
            dst[o++] = c;
        }
    }
    dst[o] = 0;
    return o;
}

static int build_discover_json(const char *host, char *buf, int sz) {
    int ptr = 0;
    char name_esc[HDHR_NAME_LEN * 2];
    json_escape("minisatip", name_esc, sizeof(name_esc));
    strlcatf(buf, sz, ptr,
             "{"
             "\"FriendlyName\":\"%s\","
             "\"Manufacturer\":\"Silicondust\","
             "\"ManufacturerURL\":\"https://github.com/catalinii/minisatip\","
             "\"ModelNumber\":\"HDTC-2US\","
             "\"FirmwareName\":\"hdhomeruntc_atsc\","
             "\"FirmwareVersion\":\"%s\","
             "\"DeviceID\":\"%08X\","
             "\"DeviceAuth\":\"none\","
             "\"TunerCount\":%d,"
             "\"BaseURL\":\"http://%s\","
             "\"LineupURL\":\"http://%s/lineup.json\""
             "}",
             name_esc, version, hdhr_device_id, active_tuner_count(), host,
             host);
    return ptr;
}

static int build_lineup_json(const char *host, char *buf, int sz) {
    int ptr = 0;
    strlcatf(buf, sz, ptr, "[");
    for (int i = 0; i < hdhr_channel_count; i++) {
        char name_esc[HDHR_NAME_LEN * 2];
        char url[HDHR_URL_LEN + 128];
        json_escape(hdhr_channels[i].name, name_esc, sizeof(name_esc));
        hdhr_rewrite_url(hdhr_channels[i].url, host, url, sizeof(url));
        strlcatf(buf, sz, ptr,
                 "%s{\"GuideNumber\":\"%d\",\"GuideName\":\"%s\",\"URL\":\"%s\"}",
                 i == 0 ? "" : ",", hdhr_channels[i].number, name_esc, url);
    }
    strlcatf(buf, sz, ptr, "]");
    return ptr;
}

static int build_lineup_status_json(char *buf, int sz) {
    int ptr = 0;
    strlcatf(buf, sz, ptr,
             "{\"ScanInProgress\":0,\"ScanPossible\":1,"
             "\"Source\":\"Cable\",\"SourceList\":[\"Cable\"]}");
    return ptr;
}

static int build_device_xml(const char *host, char *buf, int sz) {
    int ptr = 0;
    char name_esc[HDHR_NAME_LEN * 2];
    // device.xml is XML not JSON, but the same escape avoids quotes/control
    // chars; HDHR clients tolerate this and the M3U-supplied names rarely
    // contain XML-significant characters.
    json_escape("minisatip", name_esc, sizeof(name_esc));
    strlcatf(buf, sz, ptr,
             "<?xml version=\"1.0\"?>"
             "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">"
             "<specVersion><major>1</major><minor>0</minor></specVersion>"
             "<URLBase>http://%s</URLBase>"
             "<device>"
             "<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>"
             "<friendlyName>%s</friendlyName>"
             "<manufacturer>Silicondust</manufacturer>"
             "<modelName>HDTC-2US</modelName>"
             "<modelNumber>HDTC-2US</modelNumber>"
             "<serialNumber></serialNumber>"
             "<UDN>uuid:%s</UDN>"
             "</device></root>",
             host, name_esc, opts.uuid);
    return ptr;
}

int hdhr_init(void) {
    hdhr_compute_device_id();
    hdhr_build_crc_table();
    if (opts.hdhr_playlist_path) {
        if (hdhr_load_m3u(opts.hdhr_playlist_path) < 0)
            return -1;
    }
    LOG("HDHR: initialised (DeviceID=%08X, tuners=%d, name=\"minisatip\")",
        hdhr_device_id, active_tuner_count());
    return 0;
}

static const char *JSON_HDR =
    "Content-Type: application/json; charset=utf-8\r\n"
    "Connection: close\r\n"
    "Access-Control-Allow-Origin: *";
static const char *XML_HDR = "Content-Type: text/xml; charset=utf-8\r\n"
                             "Connection: close\r\n"
                             "Access-Control-Allow-Origin: *";

int hdhr_handle_http(sockets *s, char **arg, int la) {
    if (!arg || !arg[1])
        return 0;
    const char *path = arg[1];
    // Strip query string for matching (e.g. /lineup.post?scan=start).
    char route[64];
    safe_strncpy(route, (char *)path);
    char *q = strchr(route, '?');
    if (q)
        *q = 0;

    int is_discover = !strcmp(route, "/discover.json");
    int is_lineup = !strcmp(route, "/lineup.json");
    int is_status = !strcmp(route, "/lineup_status.json");
    int is_devxml = !strcmp(route, "/device.xml");
    int is_post = !strcmp(route, "/lineup.post");
    if (!is_discover && !is_lineup && !is_status && !is_devxml && !is_post)
        return 0;

    hdhr_maybe_reload();
    char host[128];
    hdhr_get_request_host(arg, la, s, host, sizeof(host));

    if (is_post) {
        // Plex hits /lineup.post?scan=start when "rescan". We don't actually
        // scan — channels come from the M3U — but reply 200 so clients are
        // happy. Triggering a hot-reload here is a nice bonus.
        hdhr_maybe_reload();
        http_response(s, 200, (char *)JSON_HDR, (char *)"", 0, 0);
        return 1;
    }

    if (is_status) {
        char body[256];
        int len = build_lineup_status_json(body, sizeof(body));
        http_response(s, 200, (char *)JSON_HDR, body, 0, len);
        return 1;
    }

    if (is_discover) {
        char body[1024];
        int len = build_discover_json(host, body, sizeof(body));
        http_response(s, 200, (char *)JSON_HDR, body, 0, len);
        return 1;
    }

    if (is_devxml) {
        char body[1024];
        int len = build_device_xml(host, body, sizeof(body));
        http_response(s, 200, (char *)XML_HDR, body, 0, len);
        return 1;
    }

    // /lineup.json — can be large; allocate.
    int sz = 1024 + (HDHR_NAME_LEN * 2 + HDHR_URL_LEN + 128) * hdhr_channel_count;
    if (sz < 2048)
        sz = 2048;
    char *body = (char *)malloc(sz);
    if (!body) {
        http_response(s, 500, NULL, NULL, 0, 0);
        return 1;
    }
    int len = build_lineup_json(host, body, sz);
    http_response(s, 200, (char *)JSON_HDR, body, 0, len);
    free(body);
    return 1;
}

// --- UDP discovery on port 65001 ---
//
// Wire format (all multi-byte fields big-endian for header/TLV):
//   uint16 type | uint16 payload_len | payload bytes | uint32 CRC32
// CRC is IEEE 802.3 (poly 0xEDB88320, reflected), serialised little-endian.
// Discovery request type 0x0002 → reply type 0x0003.

static void hdhr_put_be16(uint8_t *buf, uint16_t v) {
    buf[0] = (v >> 8) & 0xFF;
    buf[1] = v & 0xFF;
}
static void hdhr_put_be32(uint8_t *buf, uint32_t v) {
    buf[0] = (v >> 24) & 0xFF;
    buf[1] = (v >> 16) & 0xFF;
    buf[2] = (v >> 8) & 0xFF;
    buf[3] = v & 0xFF;
}
static uint16_t hdhr_get_be16(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | buf[1];
}

int hdhr_udp_reply(sockets *s) {
    if (s->rlen < 4 + 4) // header + crc
        return 0;
    uint16_t type = hdhr_get_be16(s->buf);
    uint16_t plen = hdhr_get_be16(s->buf + 2);
    if (type != HDHR_TYPE_DISCOVER_REQ)
        return 0;
    if (4 + plen + 4 > s->rlen)
        return 0;
    // CRC validation kept lenient — some senders compute it differently.
    // (We still validate length; reject obvious garbage.)

    uint8_t pkt[64];
    int o = 0;
    o += 4; // type+len placeholder
    // Tag 0x01 DeviceType = 1 (tuner)
    pkt[o++] = HDHR_TAG_DEVICE_TYPE;
    pkt[o++] = 4;
    hdhr_put_be32(pkt + o, HDHR_DEVICE_TYPE_TUNER);
    o += 4;
    // Tag 0x02 DeviceID
    pkt[o++] = HDHR_TAG_DEVICE_ID;
    pkt[o++] = 4;
    hdhr_put_be32(pkt + o, hdhr_device_id);
    o += 4;
    // Tag 0x10 TunerCount (1 byte value, len 1)
    pkt[o++] = HDHR_TAG_TUNER_COUNT;
    pkt[o++] = 1;
    pkt[o++] = (uint8_t)active_tuner_count();

    int payload_len = o - 4;
    hdhr_put_be16(pkt, HDHR_TYPE_DISCOVER_RPY);
    hdhr_put_be16(pkt + 2, payload_len);

    uint32_t crc = hdhr_crc32(pkt, o);
    // Standard HDHR puts CRC little-endian.
    pkt[o++] = crc & 0xFF;
    pkt[o++] = (crc >> 8) & 0xFF;
    pkt[o++] = (crc >> 16) & 0xFF;
    pkt[o++] = (crc >> 24) & 0xFF;

    int wb = sendto(s->sock, pkt, o, MSG_NOSIGNAL, &s->sa.sa,
                    SOCKADDR_SIZE(s->sa));
    if (wb != o) {
        char ra[64];
        LOG("HDHR: incomplete discover reply to %s: %d/%d (%s)",
            get_sockaddr_host(s->sa, ra, sizeof(ra)), wb, o, strerror(errno));
    }
    return 0;
}

#endif // DISABLE_HDHOMERUN
