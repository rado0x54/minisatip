/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Userspace DVB adapter backend — exposes every supported USB DVB
 * device on the system as one or more minisatip adapters. Thin layer
 * over dvb-libusb's bridge-generic engines:
 *
 *   find_userspace_dvb_adapter → dvb_em28xx_discover_all() +
 *                                dvb_dib0700_discover_all()
 *                              → for each handle, allocate an adapter
 *                                slot and set callbacks (all common,
 *                                dispatch through handle->ops).
 *
 *   open / tune / get_signal / standby / close — board-agnostic;
 *     dispatch through handle->ops.
 *
 *   userspace_dvb_shutdown → dvb_*_shutdown() per engine (closes
 *     engines + USB devices).
 *
 * Per-engine board-specific knowledge (chip choices, GPIO sequence,
 * frontend count, USB IDs) lives in the engine library's boards.c.
 * Adding a new device =
 *   - same bridge family: a row + attach fn in the engine's boards.c.
 *   - new bridge family: a new dvb_<bridge>/ library + one extra
 *     discover() call below.
 */

#include "userspace_dvb.h"

#include "minisatip.h"
#include "opts.h"
#include "socketworks.h"
#include "utils/logging/logging.h"

#include "dvb_handle/dvb_handle.h"
#include "dvb_handle/dvb_debug.h"
#include "dvb_em28xx/dvb_em28xx.h"
#include "dvb_dib0700/dvb_dib0700.h"
#include <linuxdvbkpi/firmware_root.h>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <string>
#include <time.h>
#include <unistd.h>

namespace {

constexpr size_t TS_PACKET = 188;
constexpr size_t TS_STAGE_SIZE = 64 * 1024;
constexpr size_t DVB_ADAPTER_BUFFER = 1024 * 1024;

/* ---- Per-adapter context ---------------------------------------- *
 *
 * find_userspace_dvb_adapter writes the handle pointer into
 * g_state[i] when it publishes adapter i and sets ad->fn = i so
 * callbacks can look up by ad->fn.
 *
 * dvb_socket_read runs single-threaded per adapter — minisatip
 * serializes the adapter's reader thread — so stage/stage_len/
 * ts_locked/counters need no locking. */

struct adapter_state {
    dvb_frontend_handle_t *handle;          /* set at find_*_adapter */
    int                    dvr_fd;          /* engine's wake fd; -1 */

    /* TS resync state. Touched only from dvb_socket_read. */
    uint8_t               *stage;           /* malloc'd TS_STAGE_SIZE */
    size_t                 stage_len;
    bool                   ts_locked;

    uint64_t               bytes_pumped_since_log;
    uint64_t               bytes_dropped_since_log;
    uint64_t               calls_since_log;
    struct timespec        last_log_ts;
    bool                   first_chunk_logged;
};

adapter_state g_state[MAX_ADAPTERS];
int           g_state_count = 0;

adapter_state *state_for(adapter *ad) {
    if (!ad || ad->fn < 0 || ad->fn >= MAX_ADAPTERS) return nullptr;
    return &g_state[ad->fn];
}

adapter_state *state_for_fd(int fd) {
    for (int i = 0; i < g_state_count; i++) {
        if (g_state[i].dvr_fd == fd && g_state[i].handle) {
            return &g_state[i];
        }
    }
    return nullptr;
}

/* ---- Firmware DIR resolution ------------------------------------ *
 *
 * Every supported board's chip drivers (and dib0700 bridge) look up
 * firmware blobs via either request_firmware (chip drivers, resolved
 * through linuxdvbkpi) or by direct path (dib0700 bridge, resolved
 * by the engine). Set one canonical $FIRMWARE_DIR for the whole
 * process. */

const char *resolve_firmware_dir(void) {
    static const char *fallbacks[] = {
        "/usr/local/share/minisatip/firmware",
        "/usr/local/lib/firmware",
        "/usr/lib/firmware",
        "/lib/firmware",
        nullptr,
    };
    static thread_local std::string cached;

    const char *env = std::getenv("FIRMWARE_DIR");
    if (env && env[0]) { cached = env; return cached.c_str(); }
    /* Probe for any of the well-known firmware filenames our
     * supported boards need — if any one is present in a fallback
     * dir, treat that as the firmware root. */
    static const char *probes[] = {
        "dvb-demod-si2168-b40-01.fw",     /* em28xx WinTV-dualHD DVB */
        "dvb-usb-dib0700-1.20.fw",        /* dib0700 bridges */
        "dvb-demod-mn88472-02.fw",        /* xbox tuner demod */
        nullptr,
    };
    for (size_t i = 0; fallbacks[i]; i++) {
        for (size_t j = 0; probes[j]; j++) {
            std::string p = std::string(fallbacks[i]) + "/" + probes[j];
            if (access(p.c_str(), R_OK) == 0) {
                cached = fallbacks[i];
                return cached.c_str();
            }
        }
    }
    return nullptr;
}

/* ---- TS resync -------------------------------------------------- */

ssize_t find_ts_sync(const uint8_t *buf, size_t len) {
    if (len < TS_PACKET * 2) return -1;
    for (size_t i = 0; i + TS_PACKET < len; i++) {
        if (buf[i] == 0x47 && buf[i + TS_PACKET] == 0x47) {
            return (ssize_t)i;
        }
    }
    return -1;
}

size_t drain_stage(adapter_state *st, uint8_t *dst, size_t dst_cap) {
    if (dst_cap < TS_PACKET) return 0;
    size_t off = 0, bytes_out = 0;

    if (!st->ts_locked) {
        ssize_t at = find_ts_sync(st->stage, st->stage_len);
        if (at < 0) {
            if (st->stage_len > 2 * TS_PACKET) {
                size_t keep = 2 * TS_PACKET;
                st->bytes_dropped_since_log += st->stage_len - keep;
                memmove(st->stage, st->stage + st->stage_len - keep, keep);
                st->stage_len = keep;
            }
            return 0;
        }
        if (at > 0) {
            st->bytes_dropped_since_log += (size_t)at;
            memmove(st->stage, st->stage + at, st->stage_len - (size_t)at);
            st->stage_len -= (size_t)at;
        }
        st->ts_locked = true;
    }

    while (off + TS_PACKET <= st->stage_len &&
           bytes_out + TS_PACKET <= dst_cap) {
        if (st->stage[off] != 0x47) {
            size_t scan = off + 1, resync = SIZE_MAX;
            while (scan + TS_PACKET < st->stage_len) {
                if (st->stage[scan] == 0x47 &&
                    st->stage[scan + TS_PACKET] == 0x47) {
                    resync = scan;
                    break;
                }
                scan++;
            }
            if (resync == SIZE_MAX) {
                st->bytes_dropped_since_log += st->stage_len - off;
                st->stage_len = off;
                break;
            }
            st->bytes_dropped_since_log += (resync - off);
            memmove(st->stage + off, st->stage + resync,
                    st->stage_len - resync);
            st->stage_len -= (resync - off);
            continue;
        }

        size_t run_end = off + TS_PACKET;
        while (run_end + TS_PACKET <= st->stage_len &&
               st->stage[run_end] == 0x47 &&
               bytes_out + (run_end - off) + TS_PACKET <= dst_cap) {
            run_end += TS_PACKET;
        }
        size_t run_len = run_end - off;
        memcpy(dst + bytes_out, st->stage + off, run_len);
        bytes_out += run_len;
        off = run_end;
    }

    if (off > 0 && off < st->stage_len) {
        memmove(st->stage, st->stage + off, st->stage_len - off);
    }
    st->stage_len -= off;
    st->bytes_pumped_since_log += bytes_out;
    return bytes_out;
}

void maybe_log_rate(adapter_state *st) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec  - st->last_log_ts.tv_sec)  * 1000L
                    + (now.tv_nsec - st->last_log_ts.tv_nsec) / 1000000L;
    if (elapsed_ms < 1000) return;

    double mbps = (st->bytes_pumped_since_log * 8.0) / 1e6
                / (elapsed_ms / 1000.0);
    LOG("%s: %.2f Mbit/s aligned, %" PRIu64 " B dropped, %" PRIu64
        " calls in %.2f s | stage_len=%zu locked=%d",
        st->handle ? st->handle->display_name : "?",
        mbps, st->bytes_dropped_since_log, st->calls_since_log,
        elapsed_ms / 1000.0, st->stage_len, st->ts_locked ? 1 : 0);

    st->bytes_pumped_since_log  = 0;
    st->bytes_dropped_since_log = 0;
    st->calls_since_log         = 0;
    st->last_log_ts             = now;
}

int dvb_socket_read(int sock, void *buf, size_t len, sockets *ss, int *rv) {
    (void)ss;
    char drain[64];
    while (read(sock, drain, sizeof(drain)) > 0) { /* discard */ }

    adapter_state *st = state_for_fd(sock);
    if (!st || !st->handle) {
        *rv = 0; errno = EAGAIN; return 0;
    }
    st->calls_since_log++;

    size_t dst_cap = (len / TS_PACKET) * TS_PACKET;
    if (dst_cap == 0) {
        *rv = 0; errno = EAGAIN; return 0;
    }

    uint8_t *dst       = static_cast<uint8_t *>(buf);
    size_t   bytes_out = 0;
    while (bytes_out + TS_PACKET <= dst_cap) {
        bytes_out += drain_stage(st, dst + bytes_out, dst_cap - bytes_out);
        if (bytes_out >= dst_cap) break;
        size_t headroom = TS_STAGE_SIZE - st->stage_len;
        if (headroom == 0) break;
        int got = st->handle->ops->read_ts(st->handle->engine_state,
                                           st->stage + st->stage_len,
                                           headroom, /*timeout_ms=*/0);
        if (got <= 0) break;
        st->stage_len += static_cast<size_t>(got);
        if (!st->first_chunk_logged) {
            st->first_chunk_logged = true;
            clock_gettime(CLOCK_MONOTONIC, &st->last_log_ts);
        }
    }
    maybe_log_rate(st);
    if (bytes_out == 0) {
        *rv = 0; errno = EAGAIN; return 0;
    }
    *rv = static_cast<int>(bytes_out);
    return 1;
}

/* ---- Adapter callbacks ------------------------------------------ */

int dvb_open(adapter *ad) {
    adapter_state *st = state_for(ad);
    if (!st || !st->handle) {
        LOG("open(adapter %d): no handle for fn=%d", ad->id, ad->fn);
        return 1;
    }
    if (!ad->buf) {
        ad->buf = static_cast<unsigned char *>(
            malloc(DVB_ADAPTER_BUFFER + 1));
        if (!ad->buf) return 1;
    }
    if (!st->stage) {
        st->stage = static_cast<uint8_t *>(malloc(TS_STAGE_SIZE));
        if (!st->stage) return 1;
    }
    st->stage_len               = 0;
    st->ts_locked               = false;
    st->bytes_pumped_since_log  = 0;
    st->bytes_dropped_since_log = 0;
    st->calls_since_log         = 0;
    st->first_chunk_logged      = false;
    clock_gettime(CLOCK_MONOTONIC, &st->last_log_ts);

    /* The engine's wake-pipe read end is per-engine and shared across
     * every open/close cycle for the lifetime of the process (engines
     * are opened once at find_userspace_dvb_adapter). minisatip's
     * socket layer, though, takes ownership of `ad->dvr` and calls
     * close(2) on it during sockets_del — which would shut the
     * engine's pipe and silently kill USB streaming for every
     * subsequent open.
     *
     * Hand minisatip a `dup()` so its close hits a private fd; the
     * engine's wake_pipe stays alive. The dup is freshly assigned by
     * the kernel on each open, so no stale-fd reuse either. */
    int engine_fd = st->handle->ops->event_fd(st->handle->engine_state);
    if (engine_fd < 0) {
        LOG("open(adapter %d): engine event_fd unavailable", ad->id);
        return 1;
    }
    st->dvr_fd = dup(engine_fd);
    if (st->dvr_fd < 0) {
        LOG("open(adapter %d): dup(event_fd=%d) failed: %s",
            ad->id, engine_fd, strerror(errno));
        return 1;
    }
    /* ad->fe is the legacy /dev/dvb/adapterN/frontend0 fd. We don't
     * have one; minisatip's signal_thread skips ad->fe <= 0. */
    ad->dvr = st->dvr_fd;
    ad->fe  = st->dvr_fd;
    LOG("open(adapter %d): %s — engine fd=%d, dvr (dup)=%d",
        ad->id, st->handle->display_name, engine_fd, ad->dvr);
    return 0;
}

int dvb_post_init(adapter *ad) {
    sockets_setread(ad->sock, (void *)dvb_socket_read);
    return 0;
}

int dvb_close(adapter *ad) {
    adapter_state *st = state_for(ad);
    if (!st) return 0;
    if (st->handle && st->handle->ops->capture_stop) {
        pthread_mutex_lock(st->handle->bridge_lock);
        st->handle->ops->capture_stop(st->handle->engine_state);
        pthread_mutex_unlock(st->handle->bridge_lock);
    }
    st->dvr_fd = -1;
    ad->dvr    = -1;
    if (st->stage) { free(st->stage); st->stage = nullptr; }
    st->stage_len          = 0;
    st->ts_locked          = false;
    st->first_chunk_logged = false;
    return 0;
}

void dvb_free(adapter *ad) { (void)ad; }

int dvb_set_pid(adapter *ad, int pid) { return ad->id * 1000 + pid; }
int dvb_del_filters(adapter *ad, int fd, int pid) {
    (void)ad; (void)fd; (void)pid; return 0;
}
int dvb_commit(adapter *ad) { (void)ad; return 0; }

int dvb_get_signal(adapter *ad) {
    adapter_state *st = state_for(ad);
    if (!st || !st->handle) {
        ad->status = 0; ad->strength = ad->snr = ad->ber = 0;
        return 0;
    }
    dvb_status_t status = {};
    pthread_mutex_lock(st->handle->bridge_lock);
    int rc = st->handle->ops->get_status(st->handle->engine_state, &status);
    pthread_mutex_unlock(st->handle->bridge_lock);
    DVBDBG("userspace_dvb get_signal(aid=%d): rc=%d %c%c%c%c%c cnr=%d.%03d dB",
           ad->id, rc,
           status.has_signal  ? 'S' : '-',
           status.has_carrier ? 'C' : '-',
           status.has_viterbi ? 'V' : '-',
           status.has_sync    ? 'Y' : '-',
           status.has_lock    ? 'L' : '-',
           status.cnr_db_x1000 / 1000, abs(status.cnr_db_x1000) % 1000);
    if (rc < 0) {
        ad->status = 0; ad->strength = ad->snr = ad->ber = 0;
        return 0;
    }
    int s = 0;
    if (status.has_signal)  s |= 0x01;
    if (status.has_carrier) s |= 0x02;
    if (status.has_viterbi) s |= 0x04;
    if (status.has_sync)    s |= 0x08;
    if (status.has_lock)    s |= 0x10;
    ad->status = s;

    int32_t cnr = status.cnr_db_x1000;
    if (cnr < 0) cnr = 0;
    if (cnr > 40000) cnr = 40000;
    uint16_t pct255 = static_cast<uint16_t>((uint32_t)cnr * 255 / 40000);
    ad->snr      = pct255;
    ad->strength = pct255;
    ad->db  = static_cast<uint16_t>(status.cnr_db_x1000 / 100);
    ad->ber = 0;
    return 0;
}

int dvb_wakeup(adapter *ad, int fd, int voltage) {
    (void)ad; (void)fd; (void)voltage; return 0;
}

int dvb_standby(adapter *ad) {
    adapter_state *st = state_for(ad);
    if (!st || !st->handle) return 0;
    pthread_mutex_lock(st->handle->bridge_lock);
    st->handle->ops->capture_stop(st->handle->engine_state);
    pthread_mutex_unlock(st->handle->bridge_lock);
    st->stage_len          = 0;
    st->ts_locked          = false;
    st->first_chunk_logged = false;
    return 0;
}

int dvb_tune(int aid, transponder *tp) {
    adapter *ad = get_adapter(aid);
    if (!ad || !tp) return -1;
    adapter_state *st = state_for(ad);
    if (!st || !st->handle) return -1;

    dvb_tune_params_t p = {};
    p.delsys       = static_cast<uint32_t>(tp->sys);
    p.freq_hz      = static_cast<uint32_t>(tp->freq) * 1000u;
    p.bandwidth_hz = static_cast<uint32_t>(tp->bw);
    p.symbol_rate  = static_cast<uint32_t>(tp->sr);
    p.stream_id    = tp->plp_isi >= 0 ? tp->plp_isi : -1;

    DVBDBG("userspace_dvb tune(aid=%d): -> engine: delsys=%u freq=%u bw=%u "
           "sr=%u stream_id=%d", aid, p.delsys, p.freq_hz, p.bandwidth_hz,
           p.symbol_rate, p.stream_id);
    pthread_mutex_lock(st->handle->bridge_lock);
    int rc = st->handle->ops->tune(st->handle->engine_state, &p);
    pthread_mutex_unlock(st->handle->bridge_lock);
    DVBDBG("userspace_dvb tune(aid=%d): engine rc=%d", aid, rc);
    if (rc < 0) {
        LOG("tune(adapter %d): vtable tune failed: %d", aid, rc);
        return -1;
    }
    st->stage_len          = 0;
    st->ts_locked          = false;
    st->first_chunk_logged = false;
    LOG("tune(adapter %d): %u Hz, sys=%u, bw=%u, sr=%u",
        aid, p.freq_hz, p.delsys, p.bandwidth_hz, p.symbol_rate);
    return 0;
}

fe_delivery_system_t dvb_delsys(int aid, int fd, fe_delivery_system_t *sys) {
    (void)fd;
    adapter *ad = get_adapter(aid);
    if (!ad || !sys) return SYS_UNDEFINED;
    adapter_state *st = state_for(ad);
    if (!st || !st->handle) return SYS_UNDEFINED;
    size_t n = st->handle->supported_delsys_count;
    for (size_t i = 0; i < n && i < MAX_DELSYS; i++) {
        sys[i] = static_cast<fe_delivery_system_t>(
            st->handle->supported_delsys[i]);
    }
    return static_cast<fe_delivery_system_t>(st->handle->supported_delsys[0]);
}

std::string dvb_name(int aid, int fd) {
    (void)fd;
    adapter *ad = get_adapter(aid);
    if (!ad) return std::string("DVB");
    adapter_state *st = state_for(ad);
    if (!st || !st->handle) return std::string("DVB");
    return std::string(st->handle->display_name);
}

void populate_one(adapter *ad, int handle_index) {
    ad->pa = 0;
    ad->fn = handle_index;     /* state_for() looks up by fn */
    ad->type = ADAPTER_DVB;

    ad->open        = dvb_open;
    ad->post_init   = dvb_post_init;
    ad->close       = dvb_close;
    ad->free        = dvb_free;
    ad->set_pid     = dvb_set_pid;
    ad->del_filters = dvb_del_filters;
    ad->commit      = dvb_commit;
    ad->get_signal  = dvb_get_signal;
    ad->wakeup      = dvb_wakeup;
    ad->standby     = dvb_standby;
    ad->tune        = dvb_tune;
    ad->delsys      = dvb_delsys;
    ad->name        = dvb_name;
}

}  // namespace

/* ---- Public entry points ---------------------------------------- */

void find_userspace_dvb_adapter(adapter **a) {
    /* Plumb the firmware directory into linuxdvbkpi before any
     * engine open — chip drivers' request_firmware() resolves
     * through this. The dib0700 engine also reads $FIRMWARE_DIR
     * directly for its bridge ramcode upload. */
    const char *fw_dir = resolve_firmware_dir();
    if (fw_dir) {
        linuxdvbkpi_set_firmware_root(fw_dir);
    } else {
        LOG("userspace_dvb: no FIRMWARE_DIR set and no fallback path "
            "contains a known DVB blob — boards needing firmware "
            "will fail to open");
    }

    dvb_frontend_handle_t *handles[MAX_ADAPTERS] = {};
    int total = 0;
    total += dvb_em28xx_discover_all (&handles[total], MAX_ADAPTERS - total);
    total += dvb_dib0700_discover_all(&handles[total], MAX_ADAPTERS - total);

    if (total == 0) {
        LOG("userspace_dvb: no supported DVB devices found");
        return;
    }

    int populated = 0;
    for (int slot = 0; slot < MAX_ADAPTERS && populated < total; slot++) {
        if (a[slot]) continue;
        adapter *ad = adapter_alloc();
        if (!ad) break;
        populate_one(ad, populated);
        g_state[populated].handle = handles[populated];
        g_state[populated].dvr_fd = -1;
        a[slot] = ad;
        LOG("userspace_dvb: registered adapter slot=%d fn=%d (%s)",
            slot, populated, handles[populated]->display_name);
        populated++;
    }
    g_state_count = populated;
}

void userspace_dvb_shutdown(void) {
    /* Reverse order of discovery — same convention as the rest of
     * the stack. */
    dvb_dib0700_shutdown();
    dvb_em28xx_shutdown();
    for (int i = 0; i < g_state_count; i++) {
        g_state[i] = adapter_state{};
    }
    g_state_count = 0;
}
