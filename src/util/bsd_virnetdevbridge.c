/*
 * Copyright (C) 2007-2012 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetdevbridge.h"
#include "virterror_internal.h"
#include "util.h"
#include "virfile.h"
#include "command.h"
#include "memory.h"
#include "intprops.h"
#include "logging.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_bridgevar.h>


#define VIR_FROM_THIS VIR_FROM_NONE


#ifdef SIOCBRADDBR
static int virNetDevSetupControlFull(const char *ifname,
                                     struct ifreq *ifr,
                                     int domain,
                                     int type)
{
    int fd;

    if (ifname && ifr) {
        memset(ifr, 0, sizeof(*ifr));

        if (virStrcpyStatic(ifr->ifr_name, ifname) == NULL) {
            virReportSystemError(ERANGE,
                                 _("Network interface name '%s' is too long"),
                                 ifname);
            return -1;
        }
    }

    if ((fd = socket(domain, type, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot open network interface control socket"));
        return -1;
    }

    if (virSetInherit(fd, false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot set close-on-exec flag for socket"));
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    return fd;
}


static int virNetDevSetupControl(const char *ifname,
                                 struct ifreq *ifr)
{
    return virNetDevSetupControlFull(ifname, ifr, AF_PACKET, SOCK_DGRAM);
}
#endif

#ifdef __linux__
# define SYSFS_NET_DIR "/sys/class/net"
/*
 * Bridge parameters can be set via sysfs on newish kernels,
 * or by  ioctl on older kernels. Perhaps we could just use
 * ioctl for every kernel, but its not clear what the long
 * term lifespan of the ioctl interface is...
 */
static int virNetDevBridgeSet(const char *brname,
                              const char *paramname,  /* sysfs param name */
                              unsigned long value,    /* new value */
                              int fd,                 /* control socket */
                              struct ifreq *ifr)      /* pre-filled bridge name */
{
    char *path = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/%s/bridge/%s", SYSFS_NET_DIR, brname, paramname) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virFileExists(path)) {
        char valuestr[INT_BUFSIZE_BOUND(value)];
        snprintf(valuestr, sizeof(valuestr), "%lu", value);
        if (virFileWriteStr(path, valuestr, 0) < 0) {
            virReportSystemError(errno,
                                 _("Unable to set bridge %s %s"), brname, paramname);
            goto cleanup;
        }
    } else {
        unsigned long paramid;
        if (STREQ(paramname, "stp_state")) {
            paramid = BRCTL_SET_BRIDGE_STP_STATE;
        } else if (STREQ(paramname, "forward_delay")) {
            paramid = BRCTL_SET_BRIDGE_FORWARD_DELAY;
        } else {
            virReportSystemError(EINVAL,
                                 _("Unable to set bridge %s %s"), brname, paramname);
            goto cleanup;
        }
        unsigned long args[] = { paramid, value, 0, 0 };
        ifr->ifr_data = (char*)&args;
        if (ioctl(fd, SIOCDEVPRIVATE, ifr) < 0) {
            virReportSystemError(errno,
                                 _("Unable to set bridge %s %s"), brname, paramname);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    VIR_FREE(path);
    return ret;
}


static int virNetDevBridgeGet(const char *brname,
                              const char *paramname,  /* sysfs param name */
                              unsigned long *value,   /* current value */
                              int fd,                 /* control socket */
                              struct ifreq *ifr)      /* pre-filled bridge name */
{
    char *path = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/%s/bridge/%s", SYSFS_NET_DIR, brname, paramname) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virFileExists(path)) {
        char *valuestr;
        if (virFileReadAll(path, INT_BUFSIZE_BOUND(unsigned long),
                           &valuestr) < 0)
            goto cleanup;

        if (virStrToLong_ul(valuestr, NULL, 10, value) < 0) {
            virReportSystemError(EINVAL,
                                 _("Unable to get bridge %s %s"),
                                 brname, paramname);
            VIR_FREE(valuestr);
            goto cleanup;
        }
        VIR_FREE(valuestr);
    } else {
        struct __bridge_info info;
        unsigned long args[] = { BRCTL_GET_BRIDGE_INFO, (unsigned long)&info, 0, 0 };
        ifr->ifr_data = (char*)&args;
        if (ioctl(fd, SIOCDEVPRIVATE, ifr) < 0) {
            virReportSystemError(errno,
                                 _("Unable to get bridge %s %s"), brname, paramname);
            goto cleanup;
        }

        if (STREQ(paramname, "stp_state")) {
            *value = info.stp_enabled;
        } else if (STREQ(paramname, "forward_delay")) {
            *value = info.forward_delay;
        } else {
            virReportSystemError(EINVAL,
                                 _("Unable to get bridge %s %s"), brname, paramname);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    VIR_FREE(path);
    return ret;
}
#endif /* __linux__ */


/**
 * virNetDevBridgeCreate:
 * @brname: the bridge name
 *
 * This function register a new bridge
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevBridgeCreate(const char *brname)
{
    virCommandPtr cmd = NULL;
    int ret = -1;

    cmd = virCommandNew(IFCONFIG_PATH);
    virCommandAddArgList(cmd, brname, "create", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevBridgeDelete:
 * @brname: the bridge name
 *
 * Remove a bridge from the layer.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int virNetDevBridgeDelete(const char *brname)
{
    virCommandPtr cmd = NULL;
    int ret = -1;

    cmd = virCommandNew(IFCONFIG_PATH);
    virCommandAddArgList(cmd, brname, "destroy", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevBridgeAddPort:
 * @brname: the bridge name
 * @ifname: the network interface name
 *
 * Adds an interface to a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    int s;
    int ret = -1;
    struct ifdrv ifd;
    struct ifbreq req;

    VIR_WARN("Adding iface %s to bridge %s", ifname, brname);
    memset(&req, 0, sizeof(req));
    memset(&ifd, 0, sizeof(ifd));
    strlcpy(req.ifbr_ifsname, ifname, sizeof(req.ifbr_ifsname));
    strlcpy(ifd.ifd_name, brname, sizeof(ifd.ifd_name));

    ifd.ifd_cmd = BRDGADD;
    ifd.ifd_len = sizeof(req);
    ifd.ifd_data = &req;

    s = socket(AF_LOCAL, SOCK_DGRAM, 0);

    if (ioctl(s, SIOCSDRVSPEC, &ifd) < 0) {
        virReportSystemError(errno,
                             _("Unable to add bridge %s port %s"), brname, ifname);
         goto cleanup;
    }

    ret = 0;
cleanup:
    close(s);
    return ret;
}

/**
 * virNetDevBridgeRemovePort:
 * @brname: the bridge name
 * @ifname: the network interface name
 *
 * Removes an interface from a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
{
    int s;
    int ret = -1;
    struct ifdrv ifd;
    struct ifbreq req;

    VIR_WARN("Removing iface %s from bridge %s", ifname, brname);
    memset(&req, 0, sizeof(req));
    memset(&ifd, 0, sizeof(ifd));
    strlcpy(req.ifbr_ifsname, ifname, sizeof(req.ifbr_ifsname));
    strlcpy(ifd.ifd_name, brname, sizeof(ifd.ifd_name));

    ifd.ifd_cmd = BRDGDEL;
    ifd.ifd_len = sizeof(req);
    ifd.ifd_data = &req;

    s = socket(AF_LOCAL, SOCK_DGRAM, 0);

    if (ioctl(s, SIOCSDRVSPEC, &ifd) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s port %s"), brname, ifname);
         goto cleanup;
    }

    ret = 0;
cleanup:
    close(s);
    return ret;
}


#ifdef __linux__
/**
 * virNetDevBridgeSetSTPDelay:
 * @brname: the bridge name
 * @delay: delay in milliseconds
 *
 * Set the bridge forward delay
 *
 * Returns 0 in case of success or -1 on failure
 */

int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeSet(brname, "forward_delay", MS_TO_JIFFIES(delay),
                             fd, &ifr);

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevBridgeGetSTPDelay:
 * @brname: the bridge device name
 * @delayms: the forward delay in milliseconds
 *
 * Retrives the forward delay for the bridge device @brname
 * storing it in @delayms. The forward delay is only meaningful
 * if STP is enabled
 *
 * Returns 0 on success, -1 on error+
 */
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delayms)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    unsigned long i;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeGet(brname, "forward_delay", &i,
                             fd, &ifr);
    *delayms = JIFFIES_TO_MS(i);

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevBridgeSetSTP:
 * @brname: the bridge name
 * @enable: 1 to enable, 0 to disable
 *
 * Control whether the bridge participates in the spanning tree protocol,
 * in general don't disable it without good reasons.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevBridgeSetSTP(const char *brname,
                          bool enable)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeSet(brname, "stp_state", enable ? 1 : 0,
                             fd, &ifr);

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevBridgeGetSTP:
 * @brname: the bridge device name
 * @enabled: returns the STP state
 *
 * Determine the state of the spanning tree protocol on
 * the device @brname, returning the state in @enabled
 *
 * Returns 0 on success, -1 on error
 */
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enabled)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    unsigned long i;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeGet(brname, "stp_state", &i,
                             fd, &ifr);
    *enabled = i ? true : false;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else /* !__linux__ */
int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
{
    int s;
    struct ifdrv ifd;
    struct ifbrparam param;
    int ret = -1;

    VIR_WARN("brname = %s, delay = %d", brname, delay);

    delay = delay < 4 ? 4 : delay;

    memset(&ifd, 0, sizeof(ifd));
    strlcpy(ifd.ifd_name, brname, sizeof(ifd.ifd_name));

    param.ifbrp_fwddelay = ((u_long)delay) & 0xff;

    ifd.ifd_cmd = BRDGSFD;
    ifd.ifd_len = sizeof(param);
    ifd.ifd_data = &param;

    s = socket(AF_LOCAL, SOCK_DGRAM, 0);

    if (ioctl(s, SIOCSDRVSPEC, &ifd) < 0) {
        virReportSystemError(errno,
                             _("Unable to set STP delay on %s"), brname);
         goto cleanup;
    }

    ret = 0;
cleanup:
    close(s);
    return ret;
}

int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delay ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP delay on %s on this platform"),
                         brname);
    return -1;
}

int virNetDevBridgeSetSTP(const char *brname, bool enable)

{
    /*XXX
     * It's not clear so far to how set STP flag on the bridge
     * as Linux sets STP over the bridge and FreeBSD allows
     * setting STP flag only per each device in the bridge.
     * At the time when this call happens, there are no
     * interfaces in the bridge yet. */
    VIR_WARN("Setting STP on %s to %d", brname, enable ? 1 : 0);

    return 0;
}
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP on %s on this platform"),
                         brname);
    return -1;
}
#endif /* __linux__ */