/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Userspace DVB adapter backend — exposes every supported USB DVB
 * device on the system as one or more minisatip adapters. Thin layer
 * over dvb-libusb's bridge-generic engines:
 *
 *   find_userspace_dvb_adapter → dvb_em28xx_discover_all() +
 *                                dvb_dib0700_discover_all() +
 *                                dvb_dvbsky_discover_all()
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
#include "dvb_dvbsky/dvb_dvbsky.h"
#include "dvb_hotplug/dvb_hotplug.h"
#include <linuxdvbkpi/firmware_root.h>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
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

    /* Slot identity preserved across unplug/replug so the worker can
     * route a re-arrival of the same board back to this g_state slot
     * (and therefore the same SAT>IP adapter number). Set on first
     * fill; never cleared while a[i] for this fn is allocated. */
    dvb_hotplug_bridge_t   bridge;
    uint16_t               vid;
    uint16_t               pid;

    /* "device actually departed" flag, set by the LEFT handler or by
     * dvb_socket_read on read_ts -ENODEV. dvb_close reads it to
     * decide whether to clear ad->sys[]:
     *   true  → real unplug, drop delsys so SAT>IP tuner count
     *           updates and get_free_adapter stops picking this slot
     *   false → idle-timeout close with USB still plugged in, keep
     *           sys[] so the next RTSP SETUP can on-demand re-open
     *           via init_hw (adapter.cpp:738). */
    bool                   engine_dead;

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

/* Lock ordering: a_mutex -> ad->mutex -> g_state_mutex. g_state_mutex
 * MUST NOT be held when calling adapter_register / adapter_find_by_fn /
 * init_hw / close_adapter. Take it briefly to read or publish g_state[];
 * release before dispatching into adapter.cpp. */
SMutex g_state_mutex;

int hotplug_pipe_rd = -1;
int hotplug_pipe_wr = -1;
bool hotplug_active = false;

/* Count of in-flight ARRIVED worker threads. Incremented under
 * g_state_mutex by handle_arrived before pthread_create; decremented
 * by hotplug_worker on exit. userspace_dvb_shutdown drains this with
 * a bounded wait so workers stop touching g_state / a[] before we
 * tear the engines down. */
int g_workers_in_flight = 0;

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

    if (opts.firmware_dir && opts.firmware_dir[0]) {
        cached = opts.firmware_dir;
        return cached.c_str();
    }
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

    /* Return semantics, important to get right: minisatip's
     * select_and_execute() treats a 0 return as "read failed" and,
     * when the byte count is also 0, falls past the EAGAIN retry
     * counter and calls sockets_del() — i.e. our adapter's DVR fd
     * gets torn down for what should be a benign inter-transfer
     * gap. So whenever there's no actual error we return 1 (success)
     * with *rv = 0; the loop then sees rlen == 0, doesn't update
     * rtime, doesn't run the master action, and waits for the next
     * wake on the engine's event fd. */
    adapter_state *st = state_for_fd(sock);
    if (!st || !st->handle) {
        *rv = 0; return 1;
    }
    st->calls_since_log++;

    size_t dst_cap = (len / TS_PACKET) * TS_PACKET;
    if (dst_cap == 0) {
        *rv = 0; return 1;
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
        if (got == -ENODEV) {
            /* Device is gone: usbq returns -ENODEV when stopping is
             * set and the ring is drained. Mark the slot so dvb_close
             * knows to clear ad->sys[], then surface to the event
             * loop: read_ok=0 + rlen=0 falls through socketworks'
             * error path to sockets_del -> close_adapter. */
            LOG("read_ts on %s returned -ENODEV - device gone, tearing down",
                st->handle->display_name);
            {
                std::lock_guard<SMutex> lk(g_state_mutex);
                st->engine_dead = true;
            }
            *rv = 0;
            return 0;
        }
        if (got < 0) {
            /* Other negative — unknown / transient. Log once per call,
             * treat as "no data this iteration"; do NOT tear the slot
             * down (avoid silent disappearance on a buggy bridge or a
             * future error code we don't recognize yet). */
            LOG("read_ts on %s returned unexpected %d - treating as transient",
                st->handle->display_name, got);
            break;
        }
        if (got == 0) break;
        st->stage_len += static_cast<size_t>(got);
        if (!st->first_chunk_logged) {
            st->first_chunk_logged = true;
            clock_gettime(CLOCK_MONOTONIC, &st->last_log_ts);
        }
    }
    maybe_log_rate(st);
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

    /* Read the "device actually gone" flag up front so we can also
     * skip capture_stop on a dead USB device (the control transfer
     * would time out rather than respond). */
    bool dead;
    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        dead = st->engine_dead;
    }

    if (!dead && st->handle && st->handle->ops->capture_stop) {
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

    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        st->engine_dead = false;
        /* Only release the handle on real departure. Idle-timeout
         * closes keep handle alive so the next get_free_adapter ->
         * init_hw -> dvb_open succeeds — this is the lazy-adapter
         * pattern the rest of minisatip uses. */
        if (dead) st->handle = nullptr;
    }

    if (dead) {
        /* Real unplug: drop delsys so the slot stops being advertised
         * (getAdaptersCount counts on delsys_match) and
         * get_free_adapter (adapter.cpp:738) stops picking this slot
         * to re-open. The next ARRIVED runs init_hw which
         * re-populates sys[] via ad->delsys (adapter.cpp:300-301). */
        memset(ad->sys, 0, sizeof(ad->sys));
    }
    return 0;
}

void dvb_free(adapter *ad) { (void)ad; }

int dvb_is_present(adapter *ad) {
    adapter_state *st = state_for(ad);
    if (!st) return 0;
    std::lock_guard<SMutex> lk(g_state_mutex);
    return st->handle != nullptr ? 1 : 0;
}

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
    ad->is_present  = dvb_is_present;
}

/* ---- Hotplug plumbing ------------------------------------------- *
 *
 * Slot assignment policy:
 *   A g_state slot's (bridge, vid, pid) is sticky for the process
 *   lifetime once first populated. On a LEFT, st->handle is cleared
 *   but the identity stays; the next ARRIVED for the same
 *   (bridge, vid, pid) reuses this slot, keeping the SAT>IP adapter
 *   number stable across re-plugs of the same board model. */

/* Resolve (bus, devaddr) -> (vid, pid) for a startup-discovered handle
 * by scanning the bridge's present-USB list. The discover_all path
 * doesn't expose VID:PID directly; scan_present is libusb-only (no
 * device claim) and cheap. */
int scan_bridge_vidpid(dvb_hotplug_bridge_t bridge,
                       uint8_t bus, uint8_t devaddr,
                       uint16_t *vid_out, uint16_t *pid_out) {
    dvb_present_board_t entries[MAX_ADAPTERS] = {};
    int n = 0;
    switch (bridge) {
        case DVB_HOTPLUG_BRIDGE_EM28XX:
            n = dvb_em28xx_scan_present (entries, MAX_ADAPTERS); break;
        case DVB_HOTPLUG_BRIDGE_DIB0700:
            n = dvb_dib0700_scan_present(entries, MAX_ADAPTERS); break;
        case DVB_HOTPLUG_BRIDGE_DVBSKY:
            n = dvb_dvbsky_scan_present (entries, MAX_ADAPTERS); break;
        default: return -1;
    }
    for (int i = 0; i < n; i++) {
        if (entries[i].bus_number == bus &&
            entries[i].device_address == devaddr) {
            unsigned v = 0, p = 0;
            if (sscanf(entries[i].vidpid, "%x:%x", &v, &p) != 2) return -1;
            *vid_out = static_cast<uint16_t>(v);
            *pid_out = static_cast<uint16_t>(p);
            return 0;
        }
    }
    return -1;
}

/* Publish a single dvb_frontend_handle_t as an adapter. Reuses any
 * matching free slot (same bridge + vid + pid + handle == nullptr) so
 * a re-plug lands in the original SAT>IP adapter slot; falls back to
 * a fresh slot when none matches. Returns the a[] index, or -1.
 *
 * call_init_hw=false at startup (init_all_hw will sweep all a[] slots);
 * call_init_hw=true from the hotplug worker (init_all_hw has already
 * completed). */
int register_handle(dvb_frontend_handle_t *handle,
                    dvb_hotplug_bridge_t bridge,
                    uint16_t vid, uint16_t pid,
                    bool call_init_hw) {
    int fn = -1;
    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        /* Prefer reusing the same-identity vacated slot. */
        for (int i = 0; i < g_state_count; i++) {
            if (g_state[i].handle == nullptr &&
                g_state[i].bridge == bridge &&
                g_state[i].vid    == vid &&
                g_state[i].pid    == pid) {
                fn = i;
                break;
            }
        }
        if (fn < 0) {
            if (g_state_count >= MAX_ADAPTERS) {
                LOG("hotplug: g_state full, cannot register %s",
                    handle->display_name);
                return -1;
            }
            fn = g_state_count;
            g_state[fn]        = adapter_state{};
            g_state[fn].dvr_fd = -1;
            g_state[fn].bridge = bridge;
            g_state[fn].vid    = vid;
            g_state[fn].pid    = pid;
            g_state_count++;
        }
        g_state[fn].handle = handle;
    }

    int ai = adapter_find_by_fn(fn);
    if (ai < 0) {
        adapter *ad = adapter_alloc();
        if (!ad) {
            std::lock_guard<SMutex> lk(g_state_mutex);
            g_state[fn].handle = nullptr;
            return -1;
        }
        populate_one(ad, fn);
        ai = adapter_register(ad);
        if (ai < 0) {
            delete ad;
            std::lock_guard<SMutex> lk(g_state_mutex);
            g_state[fn].handle = nullptr;
            LOG("hotplug: no free a[] slot for %s", handle->display_name);
            return -1;
        }
        LOG("userspace_dvb: registered adapter slot=%d fn=%d (%s) %04x:%04x",
            ai, fn, handle->display_name, vid, pid);
    } else {
        LOG("hotplug: re-attached fn=%d a[%d] (%s) %04x:%04x",
            fn, ai, handle->display_name, vid, pid);
    }

    if (call_init_hw) {
        int rc = init_hw(ai);
        if (rc != 0 && rc != 2)
            LOG("hotplug: init_hw(%d) returned %d", ai, rc);
    }
    return ai;
}

struct hotplug_worker_args {
    dvb_hotplug_event_t ev;
};

void worker_done() {
    std::lock_guard<SMutex> lk(g_state_mutex);
    if (g_workers_in_flight > 0) g_workers_in_flight--;
}

void *hotplug_worker(void *p) {
    auto *args = static_cast<hotplug_worker_args *>(p);
    dvb_hotplug_event_t ev = args->ev;
    delete args;

    /* libusb fires one ARRIVED per already-plugged device when we
     * register with LIBUSB_HOTPLUG_ENUMERATE. Dedup those against
     * the slots already populated by startup discover_all. */
    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        for (int i = 0; i < g_state_count; i++) {
            if (g_state[i].handle &&
                g_state[i].handle->bus_number     == ev.bus &&
                g_state[i].handle->device_address == ev.devaddr) {
                /* Drop counter inline; can't use worker_done()
                 * because we're already holding g_state_mutex. */
                if (g_workers_in_flight > 0) g_workers_in_flight--;
                return nullptr;
            }
        }
    }

    dvb_frontend_handle_t *handles[MAX_ADAPTERS] = {};
    int n = 0;
    switch (ev.bridge) {
        case DVB_HOTPLUG_BRIDGE_EM28XX:
            n = dvb_em28xx_open_by_addr (ev.bus, ev.devaddr,
                                         handles, MAX_ADAPTERS); break;
        case DVB_HOTPLUG_BRIDGE_DIB0700:
            n = dvb_dib0700_open_by_addr(ev.bus, ev.devaddr,
                                         handles, MAX_ADAPTERS); break;
        case DVB_HOTPLUG_BRIDGE_DVBSKY:
            n = dvb_dvbsky_open_by_addr (ev.bus, ev.devaddr,
                                         handles, MAX_ADAPTERS); break;
        default: break;
    }
    if (n <= 0) {
        LOG("hotplug: open_by_addr(bus=%u devaddr=%u bridge=%d) -> %d",
            ev.bus, ev.devaddr, (int)ev.bridge, n);
        worker_done();
        return nullptr;
    }
    for (int i = 0; i < n; i++) {
        register_handle(handles[i], ev.bridge, ev.vid, ev.pid,
                        /*call_init_hw=*/true);
    }
    worker_done();
    return nullptr;
}

void handle_arrived(const dvb_hotplug_event_t &ev) {
    LOG("hotplug: ARRIVED %04x:%04x bus=%u devaddr=%u bridge=%d",
        ev.vid, ev.pid, ev.bus, ev.devaddr, (int)ev.bridge);
    auto *args = new hotplug_worker_args{ev};
    /* Increment BEFORE pthread_create so a fast shutdown can't miss
     * the worker. Decrement at worker exit (or on create failure). */
    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        g_workers_in_flight++;
    }
    pthread_t tid;
    if (pthread_create(&tid, nullptr, hotplug_worker, args) != 0) {
        LOG("hotplug: pthread_create failed for ARRIVED");
        delete args;
        worker_done();
        return;
    }
    pthread_detach(tid);
}

void handle_left(const dvb_hotplug_event_t &ev) {
    /* Multi-frontend boards (e.g. WinTV-dualHD) register one g_state
     * slot per frontend, all sharing the same (bus, devaddr). On LEFT
     * we must mark + close every one of them — if the active-reader
     * sibling races in via -ENODEV first, this loop still cleans up
     * the remaining idle siblings whose sys[] would otherwise stay
     * advertised forever. */
    int matched[MAX_ADAPTERS];
    int n_matched = 0;
    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        for (int i = 0; i < g_state_count && n_matched < MAX_ADAPTERS; i++) {
            if (g_state[i].handle &&
                g_state[i].handle->bus_number     == ev.bus &&
                g_state[i].handle->device_address == ev.devaddr) {
                /* Mark BEFORE close_adapter so dvb_close sees the flag. */
                g_state[i].engine_dead = true;
                matched[n_matched++] = i;
            }
        }
    }
    if (n_matched == 0) return;   /* not one of ours */

    for (int k = 0; k < n_matched; k++) {
        int fn = matched[k];
        int ai = adapter_find_by_fn(fn);
        bool was_enabled = (ai >= 0 && a[ai] && a[ai]->enabled);
        LOG("hotplug: LEFT bus=%u devaddr=%u fn=%d a=%d enabled=%d",
            ev.bus, ev.devaddr, fn, ai, was_enabled);

        if (was_enabled) {
            /* close_adapter -> ad->close() -> dvb_close reads
             * engine_dead and clears ad->sys[]. The reader thread may
             * race in via -ENODEV from read_ts; close_adapter is
             * idempotent under ad->mutex (adapter.cpp:386-389). */
            close_adapter(ai);
        } else {
            /* Idle slot — dvb_close isn't going to run. Do the
             * equivalent work here. Take ad->mutex around sys[] —
             * init_hw mutates it under the same lock, and even if
             * today both paths run on the main event-loop thread we
             * shouldn't rely on that scheduling invariant. */
            if (ai >= 0 && a[ai]) {
                std::lock_guard<SMutex> alk(a[ai]->mutex);
                memset(a[ai]->sys, 0, sizeof(a[ai]->sys));
            }
            std::lock_guard<SMutex> lk(g_state_mutex);
            if (fn < g_state_count) {
                g_state[fn].handle      = nullptr;
                g_state[fn].engine_dead = false;
            }
        }
    }
}

int hotplug_event_action(sockets *ss) {
    (void)ss;
    dvb_hotplug_event_t ev;
    while (dvb_hotplug_pop(&ev) == 1) {
        if (ev.kind == DVB_HOTPLUG_ARRIVED) handle_arrived(ev);
        else if (ev.kind == DVB_HOTPLUG_LEFT) handle_left(ev);
    }
    return 0;
}

dvb_hotplug_bridge_t bridge_of_discover(int handle_idx,
                                        int em_n, int dib_n) {
    if (handle_idx < em_n)            return DVB_HOTPLUG_BRIDGE_EM28XX;
    if (handle_idx < em_n + dib_n)    return DVB_HOTPLUG_BRIDGE_DIB0700;
    return DVB_HOTPLUG_BRIDGE_DVBSKY;
}

}  // namespace

/* ---- Public entry points ---------------------------------------- */

void find_userspace_dvb_adapter(adapter **a) {
    (void)a;   /* adapter_register manages a[] under a_mutex. */

    /* Plumb the firmware directory into linuxdvbkpi before any
     * engine open — chip drivers' request_firmware() resolves
     * through this. The dib0700 engine reads $FIRMWARE_DIR directly
     * for its bridge ramcode upload, so we also setenv() the resolved
     * path so it sees the same root the user supplied via
     * --firmware-dir or the fallback probe. */
    const char *fw_dir = resolve_firmware_dir();
    if (fw_dir) {
        linuxdvbkpi_set_firmware_root(fw_dir);
        setenv("FIRMWARE_DIR", fw_dir, 1);
    } else {
        LOG("userspace_dvb: no FIRMWARE_DIR set and no fallback path "
            "contains a known DVB blob — boards needing firmware "
            "will fail to open");
    }

    dvb_frontend_handle_t *handles[MAX_ADAPTERS] = {};
    int em_n  = dvb_em28xx_discover_all (&handles[0],         MAX_ADAPTERS);
    int dib_n = dvb_dib0700_discover_all(&handles[em_n],
                                         MAX_ADAPTERS - em_n);
    int sky_n = dvb_dvbsky_discover_all (&handles[em_n + dib_n],
                                         MAX_ADAPTERS - em_n - dib_n);
    int total = em_n + dib_n + sky_n;

    for (int k = 0; k < total; k++) {
        dvb_hotplug_bridge_t b = bridge_of_discover(k, em_n, dib_n);
        uint16_t vid = 0, pid = 0;
        if (scan_bridge_vidpid(b, handles[k]->bus_number,
                                  handles[k]->device_address,
                                  &vid, &pid) != 0) {
            LOG("userspace_dvb: scan_present couldn't resolve VID:PID "
                "for %s (bus=%u devaddr=%u) - hotplug may miss re-plug",
                handles[k]->display_name,
                handles[k]->bus_number, handles[k]->device_address);
        }
        register_handle(handles[k], b, vid, pid, /*call_init_hw=*/false);
    }

    if (total == 0) {
        LOG("userspace_dvb: no supported DVB devices found at startup "
            "- hotplug stays armed so devices plugged in later are picked up");
    }

    /* Hotplug wakeup pipe. Non-blocking on both ends (the byte-write
     * runs on usbq's libusb event thread and must not stall). */
    int p[2];
    if (pipe(p) != 0) {
        LOG("userspace_dvb: pipe() for hotplug wake failed: %s",
            strerror(errno));
        return;
    }
    int rflags = fcntl(p[0], F_GETFL);
    int wflags = fcntl(p[1], F_GETFL);
    fcntl(p[0], F_SETFL, (rflags < 0 ? 0 : rflags) | O_NONBLOCK);
    fcntl(p[1], F_SETFL, (wflags < 0 ? 0 : wflags) | O_NONBLOCK);

    int rc = dvb_hotplug_init(p[1]);
    if (rc != 0) {
        LOG("userspace_dvb: dvb_hotplug_init failed (%d) - hotplug disabled",
            rc);
        close(p[0]);
        close(p[1]);
        return;
    }
    int sid = sockets_add(p[0], NULL, -1, TYPE_TCP,
                          (socket_action)hotplug_event_action,
                          NULL, NULL);
    if (sid < 0) {
        LOG("userspace_dvb: sockets_add for hotplug pipe failed");
        dvb_hotplug_shutdown();
        close(p[0]);
        close(p[1]);
        return;
    }
    hotplug_pipe_rd = p[0];
    hotplug_pipe_wr = p[1];
    hotplug_active = true;
    LOG("userspace_dvb: hotplug armed (pipe r=%d w=%d, sock=%d)",
        hotplug_pipe_rd, hotplug_pipe_wr, sid);
}

void userspace_dvb_shutdown(void) {
    if (hotplug_active) {
        /* Stop new events first so no new workers spawn during the drain. */
        dvb_hotplug_shutdown();
        hotplug_active = false;
    }

    /* Drain in-flight ARRIVED workers (bounded). Workers touch g_state
     * and call into adapter.cpp; running engine shutdown while they
     * dereference handles would be a use-after-free. 5 s ceiling is
     * generous — firmware upload is the slow path and tops out under
     * 3 s on the supported boards. */
    const int max_wait_ms = 5000;
    const int step_ms     = 50;
    for (int waited = 0; waited < max_wait_ms; waited += step_ms) {
        int in_flight;
        {
            std::lock_guard<SMutex> lk(g_state_mutex);
            in_flight = g_workers_in_flight;
        }
        if (in_flight == 0) break;
        struct timespec ts = { 0, step_ms * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    {
        std::lock_guard<SMutex> lk(g_state_mutex);
        if (g_workers_in_flight > 0)
            LOG("userspace_dvb: shutdown with %d hotplug worker(s) still in "
                "flight - proceeding anyway", g_workers_in_flight);
    }

    if (hotplug_pipe_wr >= 0) { close(hotplug_pipe_wr); hotplug_pipe_wr = -1; }
    if (hotplug_pipe_rd >= 0) { close(hotplug_pipe_rd); hotplug_pipe_rd = -1; }
    /* Reverse order of discovery — same convention as the rest of
     * the stack. */
    dvb_dvbsky_shutdown();
    dvb_dib0700_shutdown();
    dvb_em28xx_shutdown();
    for (int i = 0; i < g_state_count; i++) {
        g_state[i] = adapter_state{};
    }
    g_state_count = 0;
}
