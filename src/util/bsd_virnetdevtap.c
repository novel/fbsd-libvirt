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

#include "virmacaddr.h"
#include "virnetdevtap.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevopenvswitch.h"
#include "virterror_internal.h"
#include "virfile.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "util.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#ifdef __linux__
# include <linux/if_tun.h>    /* IFF_TUN, IFF_NO_PI */
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

/**
 * virNetDevProbeVnetHdr:
 * @tapfd: a tun/tap file descriptor
 *
 * Check whether it is safe to enable the IFF_VNET_HDR flag on the
 * tap interface.
 *
 * Setting IFF_VNET_HDR enables QEMU's virtio_net driver to allow
 * guests to pass larger (GSO) packets, with partial checksums, to
 * the host. This greatly increases the achievable throughput.
 *
 * It is only useful to enable this when we're setting up a virtio
 * interface. And it is only *safe* to enable it when we know for
 * sure that a) qemu has support for IFF_VNET_HDR and b) the running
 * kernel implements the TUNGETIFF ioctl(), which qemu needs to query
 * the supplied tapfd.
 *
 * Returns 1 if VnetHdr is supported, 0 if not supported
 */
#ifdef IFF_VNET_HDR
static int
virNetDevProbeVnetHdr(int tapfd)
{
# if defined(IFF_VNET_HDR) && defined(TUNGETFEATURES) && defined(TUNGETIFF)
    unsigned int features;
    struct ifreq dummy;

    if (ioctl(tapfd, TUNGETFEATURES, &features) != 0) {
        VIR_INFO("Not enabling IFF_VNET_HDR; "
                 "TUNGETFEATURES ioctl() not implemented");
        return 0;
    }

    if (!(features & IFF_VNET_HDR)) {
        VIR_INFO("Not enabling IFF_VNET_HDR; "
                 "TUNGETFEATURES ioctl() reports no IFF_VNET_HDR");
        return 0;
    }

    /* The kernel will always return -1 at this point.
     * If TUNGETIFF is not implemented then errno == EBADFD.
     */
    if (ioctl(tapfd, TUNGETIFF, &dummy) != -1 || errno != EBADFD) {
        VIR_INFO("Not enabling IFF_VNET_HDR; "
                 "TUNGETIFF ioctl() not implemented");
        return 0;
    }

    VIR_INFO("Enabling IFF_VNET_HDR");

    return 1;
# else
    (void) tapfd;
    VIR_INFO("Not enabling IFF_VNET_HDR; disabled at build time");
    return 0;
# endif
}
#endif


/**
 * virNetDevTapCreate:
 * @ifname: the interface name
 * @tapfd: file descriptor return value for the new tap device
 * @flags: OR of virNetDevTapCreateFlags. Only one flag is recognized:
 *
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_PERSIST
 *     - The device will persist after the file descriptor is closed
 *
 * Creates a tap interface.
 * If the @tapfd parameter is supplied, the open tap device file descriptor
 * will be returned, otherwise the TAP device will be closed. The caller must
 * use virNetDevTapDelete to remove a persistent TAP device when it is no
 * longer needed.
 *
 * Returns 0 in case of success or -1 on failure.
 */
int virNetDevTapCreate(char **ifname,
                       int *tapfd,
                       unsigned int flags)
{
    int s;
    struct ifreq ifr;
    int ret = -1;

    s = socket(AF_LOCAL, SOCK_DGRAM, 0);
    if (s < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create socket"));
        return -1;
    }

    VIR_WARN("%s: ifname = %s", __func__, NULLSTR(*ifname));


    memset(&ifr, 0, sizeof(ifr));

    if (virStrcpyStatic(ifr.ifr_name, "tap") == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             *ifname);
        goto cleanup;

    }

    if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to create tap device %s"),
                             NULLSTR(*ifname));
        goto cleanup;
    }

    VIR_WARN("%s: new ifname = %s", __func__,
                 ifr.ifr_name);
#if 0

    if ((flags & VIR_NETDEV_TAP_CREATE_PERSIST) &&
        (errno = ioctl(fd, TUNSETPERSIST, 1))) {
        virReportSystemError(errno,
                             _("Unable to set tap device %s to persistent"),
                             NULLSTR(*ifname));
        goto cleanup;
    }
#endif
    VIR_FREE(*ifname);

    if (!(*ifname = strdup(ifr.ifr_name))) {
        virReportOOMError();
        goto cleanup;
    }

    if (tapfd) {
        char *dev_prefix = "/dev/";
        char *dev_path;
        int dev_path_len = strlen(dev_prefix) +  strlen(*ifname) + 1;

        dev_path = malloc(dev_path_len * sizeof(char));
        snprintf(dev_path, dev_path_len, "%s%s", dev_prefix, *ifname);

        *tapfd = open(dev_path, O_RDWR);

        if (dev_path)
            free(dev_path);
    }

    ret = 0;
cleanup:
    if (ret < 0)
        VIR_FORCE_CLOSE(s);

    return ret;
}


int virNetDevTapDelete(const char *ifname)
{
    int s;
    struct ifreq ifr;
    int ret = -1;

    s = socket(AF_LOCAL, SOCK_DGRAM, 0);
    if (s < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create socket"));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             ifname);
        goto cleanup;

    }

    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove tap device %s"),
                             ifname);
        goto cleanup;
    }

    ret = 0;
cleanup:
    close(s);
    return ret;
}

/**
 * virNetDevTapCreateInBridgePort:
 * @brname: the bridge name
 * @ifname: the interface name (or name template)
 * @macaddr: desired MAC address
 * @tapfd: file descriptor return value for the new tap device
 * @virtPortProfile: bridge/port specific configuration
 * @flags: OR of virNetDevTapCreateFlags:

 *   VIR_NETDEV_TAP_CREATE_IFUP
 *     - Bring the interface up
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE
 *     - Set this interface's MAC as the bridge's MAC address
 *   VIR_NETDEV_TAP_CREATE_PERSIST
 *     - The device will persist after the file descriptor is closed
 *
 * This function creates a new tap device on a bridge. @ifname can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @ifname.
 * If the @tapfd parameter is supplied, the open tap device file descriptor
 * will be returned, otherwise the TAP device will be closed. The caller must
 * use virNetDevTapDelete to remove a persistent TAP device when it is no
 * longer needed.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const virMacAddrPtr macaddr,
                                   const unsigned char *vmuuid,
                                   int *tapfd,
                                   virNetDevVPortProfilePtr virtPortProfile,
                                   virNetDevVlanPtr virtVlan,
                                   unsigned int flags)
{
    virMacAddr tapmac;

    if (virNetDevTapCreate(ifname, tapfd, flags) < 0)
        return -1;

    /* We need to set the interface MAC before adding it
     * to the bridge, because the bridge assumes the lowest
     * MAC of all enslaved interfaces & we don't want it
     * seeing the kernel allocate random MAC for the TAP
     * device before we set our static MAC.
     */
    virMacAddrSet(&tapmac, macaddr);
    if (!(flags & VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE)) {
        if (macaddr->addr[0] == 0xFE) {
            /* For normal use, the tap device's MAC address cannot
             * match the MAC address used by the guest. This results
             * in "received packet on vnetX with own address as source
             * address" error logs from the kernel.
             */
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unable to use MAC address starting with "
                             "reserved value 0xFE - '%02X:%02X:%02X:%02X:%02X:%02X' - "),
                           macaddr->addr[0], macaddr->addr[1],
                           macaddr->addr[2], macaddr->addr[3],
                           macaddr->addr[4], macaddr->addr[5]);
            goto error;
        }
        tapmac.addr[0] = 0xFE; /* Discourage bridge from using TAP dev MAC */
    }

    if (virNetDevSetMAC(*ifname, &tapmac) < 0)
        goto error;

    /* We need to set the interface MTU before adding it
     * to the bridge, because the bridge will have its
     * MTU adjusted automatically when we add the new interface.
     */
    if (virNetDevSetMTUFromDevice(*ifname, brname) < 0)
        goto error;

    if (virtPortProfile) {
        if (virNetDevOpenvswitchAddPort(brname, *ifname, macaddr, vmuuid,
                                        virtPortProfile, virtVlan) < 0) {
            goto error;
        }
    } else {
        if (virNetDevBridgeAddPort(brname, *ifname) < 0)
            goto error;
    }

    if (virNetDevSetOnline(*ifname, !!(flags & VIR_NETDEV_TAP_CREATE_IFUP)) < 0)
        goto error;

    return 0;

 error:
    if (tapfd)
        VIR_FORCE_CLOSE(*tapfd);

    return -1;
}
