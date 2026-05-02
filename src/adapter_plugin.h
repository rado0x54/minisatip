/*
 * Copyright (C) 2026 minisatip contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef MINISATIP_ADAPTER_PLUGIN_H
#define MINISATIP_ADAPTER_PLUGIN_H

/*
 * Adapter-plugin ABI.
 *
 * Lets vendor-specific tuner backends ship as shared libraries
 * (.so / .dylib) that minisatip dlopens at startup, instead of
 * needing to be compiled into the minisatip binary.
 *
 * Motivation: minisatip's stock LINUXDVB backend reads from
 * /dev/dvb/adapter*, which doesn't exist on macOS or on Synology
 * DSM 7+ (kernel DVB removed). A plugin backend can drive USB
 * tuners directly via libusb, exposing them as standard SAT>IP
 * adapters without requiring kernel-side support.
 *
 * Design summary:
 *
 *   - Plugins live as separate .so/.dylib files in a configurable
 *     directory (`--plugin-dir DIR`, default ${PREFIX}/lib/minisatip/plugins/).
 *   - Each plugin exports exactly one symbol with default visibility:
 *         const struct minisatip_plugin *minisatip_plugin_register(void);
 *   - At startup, after CLI parsing and before init_all_hw(), the
 *     loader scans the plugin directory, dlopens each entry,
 *     resolves minisatip_plugin_register, and validates abi_version.
 *   - On success, the loader calls plugin->find_adapters(a), which
 *     walks the global adapter array `a[MAX_ADAPTERS]`, allocates
 *     slots via adapter_alloc(), and populates them. This is the
 *     same shape the in-tree backends (find_satip_adapter,
 *     find_netcv_adapter, ...) use.
 *   - Plugins call back into minisatip's API directly (adapter_alloc,
 *     LOG, etc.) via runtime symbol resolution — minisatip is linked
 *     with -rdynamic so plugins see its symbols.
 *   - On clean exit, plugin->shutdown() is called once per plugin
 *     after all adapters owned by the plugin have had their free()
 *     callbacks invoked.
 *
 * ABI versioning: bump MINISATIP_PLUGIN_ABI_VERSION whenever this
 * struct or the implicit symbol-call surface (adapter_alloc, etc.)
 * changes incompatibly. The loader rejects plugins whose
 * abi_version doesn't match. Plugins compile against the version
 * present in the headers they were built against; mismatched
 * plugins are skipped with a log message, not silently ignored.
 */

#define MINISATIP_PLUGIN_ABI_VERSION 1

/* Full definition of `adapter` (the struct plugins populate) lives
 * here. Pulling it in from adapter_plugin.h keeps the include order
 * for plugins simple — they include just this header and get
 * everything they need. The cost is dragging adapter.h's transitive
 * deps (minisatip.h, dvb.h, std::string via <string>) into plugin
 * TUs, which is acceptable for an in-tree-style plugin model. */
#include "adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

struct minisatip_plugin {
    /* MUST equal MINISATIP_PLUGIN_ABI_VERSION at compile time of the
     * plugin. The loader rejects mismatches. */
    int abi_version;

    /* Short identifier — printable, no whitespace, used in log lines.
     *   examples: "sundtek-pro3", "rtl28xxu", "em28xx-userland"
     * Must remain valid for the lifetime of the loaded library. */
    const char *name;

    /* Free-form version string for the plugin itself (NOT minisatip).
     * Conventionally SemVer ("1.0.0", "0.2.1-rc3"). Logged at startup
     * so users can identify mismatches. May be NULL. */
    const char *version;

    /*
     * Discovery callback. Called once at startup, after the plugin
     * has been validated. Mirrors the in-tree find_*_adapter()
     * functions: walks `a` (size MAX_ADAPTERS), allocates new
     * adapters via adapter_alloc(), and slots them into free entries
     * (those where a[i] == NULL).
     *
     * For each adapter the plugin populates, it MUST set:
     *   ad->pa, ad->fn   — parent / frontend numbers (usually local
     *                      indexes within the plugin)
     *   ad->type         — typically ADAPTER_DVB; reuse an existing
     *                      enum value rather than inventing one
     *   ad->open / ad->close / ad->free / ad->tune / ad->set_pid /
     *   ad->del_filters / ad->commit / ad->get_signal /
     *   ad->wakeup / ad->standby / ad->delsys / ad->name
     *
     * Returns the number of adapters the plugin populated (>= 0).
     * 0 is valid and means "I'm here but found no devices to claim";
     * the loader logs but does not unload the plugin in that case
     * (devices may hot-plug later).
     */
    int (*find_adapters)(adapter **a);

    /*
     * Optional. Called once at clean exit, after every adapter this
     * plugin populated has had its free() callback invoked. Lets the
     * plugin tear down library-wide state (libusb context, threads,
     * cached descriptors, etc.). May be NULL.
     */
    void (*shutdown)(void);
};

/*
 * The single symbol every plugin shared library must export with
 * default visibility (no -fvisibility=hidden games on this name).
 *
 * The loader dlopens the plugin, calls dlsym(handle,
 * "minisatip_plugin_register"), and validates the returned struct.
 *
 * The returned pointer must remain valid for the lifetime of the
 * loaded library — typically pointing to a `static const` instance.
 * The loader does NOT free it.
 */
const struct minisatip_plugin *minisatip_plugin_register(void);

#ifdef __cplusplus
}
#endif

#endif /* MINISATIP_ADAPTER_PLUGIN_H */
