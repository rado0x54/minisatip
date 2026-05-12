/*
 * Userspace DVB adapter backend (libusb-based).
 *
 * Discovery and shutdown entry points for the in-tree adapter backend
 * that talks to USB DVB tuners via dvb-libusb. Compiled and linked
 * only when -DUSERSPACE_DVB=ON; the call sites in adapter.cpp are
 * gated by DISABLE_USERSPACE_DVB.
 */

#ifndef MINISATIP_USERSPACE_DVB_H
#define MINISATIP_USERSPACE_DVB_H

#include "adapter.h"

void find_userspace_dvb_adapter(adapter **a);
void userspace_dvb_shutdown(void);

#endif
