/*
 * Copyright (C) 2026 minisatip contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "adapter_plugin.h"

#include "adapter.h"
#include "minisatip.h"
#include "opts.h"
#include "utils.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#define DEFAULT_LOG LOG_GENERAL

/*
 * Loaded-plugin state. We keep a small static table so we can call
 * shutdown() on each plugin at clean-exit time.
 */
struct loaded_plugin {
    const struct minisatip_plugin *plugin;
    void *dl_handle;
};

#define MAX_LOADED_PLUGINS 16
static struct loaded_plugin g_loaded[MAX_LOADED_PLUGINS];
static int g_loaded_count = 0;

/* Returns 1 if `name` ends in ".so" or ".dylib", 0 otherwise. */
static int has_plugin_extension(const char *name) {
    size_t len = strlen(name);
    if (len > 3 && strcmp(name + len - 3, ".so") == 0) {
        return 1;
    }
    if (len > 6 && strcmp(name + len - 6, ".dylib") == 0) {
        return 1;
    }
    return 0;
}

/*
 * Try to load and register a single plugin file. Returns the number
 * of adapters the plugin populated (>= 0) on success; on any failure
 * (couldn't dlopen, missing symbol, ABI mismatch), logs and returns
 * -1. Continues even if some plugins fail; one bad plugin should not
 * stop discovery of others.
 */
static int try_load_one_plugin(const char *path, adapter **a) {
    if (g_loaded_count >= MAX_LOADED_PLUGINS) {
        LOG("plugin: refusing to load %s, MAX_LOADED_PLUGINS (%d) reached",
            path, MAX_LOADED_PLUGINS);
        return -1;
    }

    /* RTLD_NOW catches missing symbols up front rather than at first
     * call — more diagnostic.
     * RTLD_LOCAL keeps the plugin's symbols out of the global namespace
     * so two plugins can't accidentally collide. */
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        LOG("plugin: dlopen(%s) failed: %s", path, dlerror());
        return -1;
    }

    /* Clear any prior dlerror, then resolve the entry symbol. */
    dlerror();
    typedef const struct minisatip_plugin *(*register_fn_t)(void);
    register_fn_t reg = (register_fn_t)dlsym(h, "minisatip_plugin_register");
    const char *err = dlerror();
    if (!reg || err) {
        LOG("plugin: %s missing minisatip_plugin_register: %s", path,
            err ? err : "(null)");
        dlclose(h);
        return -1;
    }

    const struct minisatip_plugin *p = reg();
    if (!p) {
        LOG("plugin: %s minisatip_plugin_register() returned NULL", path);
        dlclose(h);
        return -1;
    }

    if (p->abi_version != MINISATIP_PLUGIN_ABI_VERSION) {
        LOG("plugin: %s ABI mismatch (plugin says %d, host expects %d) — "
            "skipping",
            path, p->abi_version, MINISATIP_PLUGIN_ABI_VERSION);
        dlclose(h);
        return -1;
    }

    if (!p->name || !p->find_adapters) {
        LOG("plugin: %s incomplete (name=%s, find_adapters=%p) — skipping",
            path, p->name ? p->name : "(null)", (void *)p->find_adapters);
        dlclose(h);
        return -1;
    }

    LOG("plugin: loaded %s name=%s version=%s", path, p->name,
        p->version ? p->version : "?");

    int n = p->find_adapters(a);
    if (n < 0) {
        LOG("plugin: %s find_adapters returned %d, treating as 0", p->name, n);
        n = 0;
    }
    LOG("plugin: %s populated %d adapter(s)", p->name, n);

    g_loaded[g_loaded_count].plugin = p;
    g_loaded[g_loaded_count].dl_handle = h;
    g_loaded_count++;

    return n;
}

/*
 * Walk the configured plugin directory, sorting entries by name for
 * deterministic load order. For each .so/.dylib found, attempt to
 * load + register. Total adapters added is the sum over all plugins.
 *
 * Called from find_adapters() in adapter.cpp once per process.
 */
int load_plugin_adapters(adapter **a) {
    const char *dir = opts.plugin_dir;
    if (!dir || !*dir) {
        return 0; /* feature off */
    }

    /* Friendly diagnostic: directory existence is informational, not fatal. */
    struct stat st;
    if (stat(dir, &st) != 0) {
        LOG("plugin: directory %s does not exist (errno=%d) — feature off",
            dir, errno);
        return 0;
    }
    if (!S_ISDIR(st.st_mode)) {
        LOG("plugin: %s exists but is not a directory — feature off", dir);
        return 0;
    }

    DIR *d = opendir(dir);
    if (!d) {
        LOG("plugin: opendir(%s) failed (errno=%d)", dir, errno);
        return 0;
    }

    /* Collect entries first so we can sort them — deterministic load
     * order makes "which plugin claimed adapter 0" predictable across
     * runs and across machines. */
    char *names[MAX_LOADED_PLUGINS];
    int n_names = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n_names < MAX_LOADED_PLUGINS) {
        if (de->d_name[0] == '.') {
            continue; /* skip dotfiles, ".", ".." */
        }
        if (!has_plugin_extension(de->d_name)) {
            continue;
        }
        names[n_names++] = strdup(de->d_name);
    }
    closedir(d);

    /* simple bubble — N <= MAX_LOADED_PLUGINS = 16 */
    for (int i = 0; i < n_names - 1; i++) {
        for (int j = 0; j < n_names - 1 - i; j++) {
            if (strcmp(names[j], names[j + 1]) > 0) {
                char *t = names[j];
                names[j] = names[j + 1];
                names[j + 1] = t;
            }
        }
    }

    int total = 0;
    char path[1024];
    for (int i = 0; i < n_names; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        int n = try_load_one_plugin(path, a);
        if (n > 0) {
            total += n;
        }
        free(names[i]);
    }

    LOG("plugin: scan of %s complete — %d plugin(s) loaded, %d adapter(s) "
        "registered",
        dir, g_loaded_count, total);
    return total;
}

/*
 * Called once at clean exit. Walks loaded plugins in reverse order,
 * calls each one's optional shutdown() hook, and dlcloses the
 * library.
 *
 * Adapter free() callbacks are invoked separately by minisatip's
 * normal adapter teardown path before this is reached.
 */
void unload_plugin_adapters(void) {
    while (g_loaded_count > 0) {
        g_loaded_count--;
        struct loaded_plugin *lp = &g_loaded[g_loaded_count];
        if (lp->plugin && lp->plugin->shutdown) {
            lp->plugin->shutdown();
        }
        if (lp->dl_handle) {
            dlclose(lp->dl_handle);
        }
        lp->plugin = NULL;
        lp->dl_handle = NULL;
    }
}
