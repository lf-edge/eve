/******************************************************************************
 * COPYRIGHT (c) 2019 Schweitzer Engineering Laboratories, Inc.
 *
 * This file is provided under a BSD license. The text of the BSD license
 * is provided below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this software
 * may be distributed under the terms of the GNU General Public License ("GPL")
 * version 2, in which case the provisions of the GPL apply INSTEAD OF those
 * given above.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * SEL Opensource <opensource@selinc.com>
 * Schweitzer Engineering Laboratories, Inc.
 * 2350 NE Hopkins Court, Pullman, WA 99163
 ******************************************************************************
 * Provides Access to the network interface
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* kern-specific macros */

#include <linux/errno.h>       /* error codes */
#include <linux/ethtool.h>     /* ethtool interface */
#include <linux/if_ether.h>    /* ethernet definitions */
#include <linux/if_vlan.h>     /* VLAN */
#include <linux/interrupt.h>   /* IRQ interface */
#include <linux/firmware.h>    /* firmware data */
#include <linux/jiffies.h>     /* jiffies counter */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */
#include <linux/workqueue.h>   /* workqueues */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0))
#include <linux/netdev_features.h>  /* net device features */
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0))
#include <uapi/linux/sockios.h>  /* socket ioctls */
#else
#include <linux/sockios.h>      /* socket ioctls */
#endif

#include "netdev.h"             /* netdevice interface */
#include "netdev_isr.h"         /* netdevice interrupt interface */
#include "netdev_rx.h"          /* netdevice rx interface */
#include "netdev_tx.h"          /* netdevice tx interface */
#include "sel_hw.h"             /* mac interface */
#include "sel_phy.h"            /* phy interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_mii.h"      /* mii interface */
#include "sel3390e4_ethtool.h"  /* ethtool interface */
#include "sel3390e4_hw.h"       /* mac interface */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */
#include "sel3390e4_sfp.h"      /* sfp interface */

/* Default Tracing Level ( 0 > debug > 32 ) */
#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV|NETIF_MSG_PROBE|NETIF_MSG_LINK)

/* IOCTL used to upgrade device firmware. IOCTL takes the path to
 * a binary file contained in /lib/firmware/ (ex. sel3390e4/test.rbf)
 */
static u32 const IOCTL_SEL3390E4_UPGRADE_FW = (SIOCDEVPRIVATE + 1);

/* IOCTL used to upgrade device r/w flash storage. IOCTL takes the path to
 * a binary file contained in /lib/firmware/ (ex. sel3390e4/test.rbf)
 */
static u32 const IOCTL_SEL3390E4_UPGRADE_RW = (SIOCDEVPRIVATE + 2);

/* Max length of binary file paths */
#define SEL3390E4_FIRMWARE_FILENAME_LEN 64U

/* Supported Interrupts */
static u32 const SEL3390E4_SUPPORTED_IMASKS =
	(IEVENT_RXF  |
	 IEVENT_TXF  |
	 IEVENT_STAT |
	 IEVENT_SFP  |
	 IEVENT_LINK);

/* NOR flash MAC address offsets */
static enum sel3390e4_nvm_rw_storage_offsets const NVM_MAC_ADDR_OFFSETS[] = {
	NVM_RW_ADDR_MAC_1,
	NVM_RW_ADDR_MAC_2,
	NVM_RW_ADDR_MAC_3,
	NVM_RW_ADDR_MAC_4
};

/**
 * sel3390e4_open() - Called when the net device transitions to the up state
 *
 * @netdev: net device object
 *
 * Return: 0 if successful, otherwise appropriate negative error code
 */
static int sel3390e4_open(struct net_device *netdev)
{
	int err = 0;
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	netdev_vdbg(netdev, "--> %s\n", __func__);

	/* Start up the device */

	err = sel3390e4_up(mac);

	netdev_vdbg(netdev, "<-- %s\n", __func__);

	return err;
}

/**
 * sel3390e4_close() - Called when the net device transitions to the down state
 *
 * @netdev: net device object
 *
 * Return: 0 always.
 */
static int sel3390e4_close(struct net_device *netdev)
{
	netdev_vdbg(netdev, "--> %s\n", __func__);

	sel3390e4_down(netdev_priv(netdev));

	netdev_vdbg(netdev, "<-- %s\n", __func__);

	return 0;
}

/**
 * sel3390e4_set_mac() - Set the net device mac address
 *
 * @netdev:     the net device object
 * @mac_addr:  the mac address to set
 *
 * The mac address is also set in hardware here as well
 *
 * Return: 0 if successful, otherwise appropriate negative error code
 */
static int sel3390e4_set_mac(struct net_device *netdev, void *mac_addr)
{
	struct sockaddr *addr = mac_addr;
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	if (addr == NULL) {
		return -EINVAL;
	}

	if (!is_valid_ether_addr(addr->sa_data)) {
		return -EADDRNOTAVAIL;
	}

	memcpy(netdev->dev_addr, addr->sa_data, ETH_ALEN);

	return sel_set_hw_mac_addr(mac->hw_mac, netdev->dev_addr, ETH_ALEN);
}

/**
 * sel3390e4_set_rx_mode() - Adjust network device receive packet filter
 *
 * @netdev: net device object
 */
static void sel3390e4_set_rx_mode(struct net_device *netdev)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	netdev_vdbg(netdev, "--> %s\n", __func__);

	if ((netdev->flags & IFF_PROMISC) != 0) {
		/* Enable promiscuous mode */
		sel_enable_promiscuous_mode(mac->hw_mac);
	} else {
		/* Disable promiscuous mode */
		sel_disable_promiscuous_mode(mac->hw_mac);
	}

	if ((netdev->flags & IFF_ALLMULTI) == IFF_ALLMULTI) {
		/* Enable multicast for all addresses */
		sel_enable_multicast(mac->hw_mac);
	} else if ((netdev->flags & IFF_MULTICAST) == IFF_MULTICAST) {
		/* Set up the multicast list in hardware*/
		sel_write_mc_addr_list(
			mac->hw_mac,
			netdev);
	} else {
		/* Disable multicast for all addresses */
		sel_disable_multicast(mac->hw_mac);
	}

	netdev_vdbg(netdev, "<-- %s\n", __func__);
}

/**
 * sel3390e4_get_stats() - Return device stats
 *
 * @netdev: net device object
 *
 * Return: device statistics
 */
static struct net_device_stats *sel3390e4_get_stats(struct net_device *netdev)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	sel3390e4_update_device_stats(mac);

	return &mac->stats;
}

/**
 * sel3390e4_change_mtu() - Set a new MTU for a net device
 *
 * @netdev:  the net device to configure
 * @new_mtu: the mtu to set
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int sel3390e4_change_mtu(struct net_device *netdev, int new_mtu)
{
	if ((new_mtu < ETH_ZLEN) || (new_mtu > ETH_DATA_LEN)) {
		/* The MTU must be greater or equal the minimum packet length
		 * and less than or equal to the max packet length (sans FCS)
		 */
		return -EINVAL;
	}

	netdev->mtu = new_mtu;

	return 0;
}

/**
 * sel3390e4_ioctl() - Process IOCTL requests
 *
 * @netdev: net device object
 * @ifr:    network device input data descriptor
 * @cmd:    the IOCTL command
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int sel3390e4_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	int err = -EIO;
	struct sel3390e4_mac *mac = netdev_priv(netdev);

#ifndef __VMKLNX__
	char filename[SEL3390E4_FIRMWARE_FILENAME_LEN];
	struct firmware const *fw;
#endif

	if ((cmd == IOCTL_SEL3390E4_UPGRADE_FW) || (cmd == IOCTL_SEL3390E4_UPGRADE_RW)) {
#ifndef __VMKLNX__
		if (copy_from_user(
			filename,
			ifr->ifr_data,
			SEL3390E4_FIRMWARE_FILENAME_LEN) < SEL3390E4_FIRMWARE_FILENAME_LEN) {

			err = request_firmware(&fw, filename, &mac->board->pdev->dev);
			if (!err) {
				if (cmd == IOCTL_SEL3390E4_UPGRADE_FW) {
					err =
						sel3390e4_update_flash(
							mac->board,
							FLASH_IMAGE_FUNCTIONAL,
							fw->data,
							fw->size,
							&mac->board->nvm_lock);
				} else {
					err =
						sel3390e4_update_flash(
							mac->board,
							FLASH_RW,
							fw->data,
							fw->size,
							&mac->board->nvm_lock);
				}

				release_firmware(fw);
			}
		}
#endif /* !defined(__VMKLNX__) */
	} else {
		err = sel3390e4_mii_generic_ioctl(&mac->mii_if, if_mii(ifr), cmd, NULL);
	}

	return err;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/**
 * sel3390e4_netpoll() - Polling Interrupt
 *
 * @netdev: net device object
 *
 * Used by things like netconsole to send skbs without having to
 * re-enable interrupts. It's not called while the interrupt routine
 * is executing.
 */
static void sel3390e4_netpoll(struct net_device *netdev)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	struct sel3390e4_board *board = mac->board;

	sel_disable_irq(mac->hw_mac, ~0U,  &mac->imask_lock);
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)) || defined(__VMKLNX__))
	sel3390e4_intr(board->pdev->irq, netdev);
#else
	sel3390e4_intr(board->pdev->irq, netdev, NULL);
#endif
	sel_enable_irq(mac->hw_mac, SEL3390E4_SUPPORTED_IMASKS, &mac->imask_lock);
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31))

/* Management hooks for the SEL3390 network devices */
static struct net_device_ops const sel3390e4_netdev_ops = {
	.ndo_open               = sel3390e4_open,
	.ndo_stop               = sel3390e4_close,
	.ndo_start_xmit         = sel3390e4_xmit_frame,
	.ndo_set_rx_mode        = sel3390e4_set_rx_mode,
	.ndo_set_mac_address    = sel3390e4_set_mac,
#ifdef RHEL_RELEASE_CODE
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5))
	.ndo_change_mtu_rh74    = sel3390e4_change_mtu,
#else
	.ndo_change_mtu         = sel3390e4_change_mtu,
#endif
#else
	.ndo_change_mtu         = sel3390e4_change_mtu,
#endif
	.ndo_tx_timeout         = sel3390e4_tx_timeout,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_get_stats          = sel3390e4_get_stats,
	.ndo_do_ioctl           = sel3390e4_ioctl,

#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller    = sel3390e4_netpoll,
#endif
};

#endif

/**
 * sel3390e4_up() - Initialize and start the network interface
 *
 * @mac: net device context
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
int sel3390e4_up(struct sel3390e4_mac *mac)
{
	int err;

	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	/* Explicitly set the link state as down */
	netif_carrier_off(mac->netdev);

	/* Allocate the receive memory */
	err = sel3390e4_alloc_receive_memory(mac);
	if (err) {
		netif_err(mac, ifup, mac->netdev,
			"[ERROR] Failed to allocate receive memory.\n");
		goto all_done;
	}

	/* Allocate the transmit memory */
	err = sel3390e4_alloc_transmit_memory(mac);
	if (err) {
		netif_err(mac, ifup, mac->netdev,
			"[ERROR] Failed to allocate transmit memory.\n");
		goto err_rx_clean_list;
	}

	/* Initialize the hardware */
	err =
		sel_hw_init(
			mac->hw_mac,
			(u64)mac->base_rx_bd_dma_addr,
			(u64)mac->base_tx_bd_dma_addr,
			mac->netdev->dev_addr,
			ETH_ALEN);
	if (err) {
		netif_err(mac, ifup, mac->netdev,
			"[ERROR] Hardware initialization error.\n");
		goto err_tx_clean_list;
	}

	/* Attach the shared PCI interrupt to this net device */
	err = request_irq(
		mac->board->pdev->irq,
		sel3390e4_intr,
		IRQF_SHARED,
		mac->netdev->name, mac->netdev);
	if (err) {
		goto err_tx_clean_list;
	}

	/* Start up the PHY */
	sel_phy_power_up(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* Reset the PHY to a known configuration */
	sel_phy_reset(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* Setup the PHY with required settings */
	sel_phy_setup(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* Reset receive filter (multicast list, promiscuous mode, etc) */
	sel3390e4_set_rx_mode(mac->netdev);

	/* Start the receiver */
	sel_start_receiver(mac->hw_mac);

	/* Start accepting transmit packets */
	netif_wake_queue(mac->netdev);

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)) || defined(__VMKLNX__))
	/* Enable NAPI polling */
	napi_enable(&mac->napi);
#endif

	/* Disable and re-initialize any attached SFPs */
	sel3390e4_sfp_disable(mac);
	sel3390e4_sfp_detect(mac);

	/* Detect link state since interrupts have not
	 * yet been enabled
	 */
	sel3390e4_mii_check_link(&mac->mii_if);

	/* Enable interrupts */
	sel_enable_irq(mac->hw_mac, SEL3390E4_SUPPORTED_IMASKS, &mac->imask_lock);

	goto all_done;

err_tx_clean_list:

	sel3390e4_free_transmit_memory(mac);

err_rx_clean_list:

	sel3390e4_free_receive_memory(mac);

all_done:

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);

	return err;
}

/**
 * sel3390e4_down() - Shutdown the network interface
 *
 * @mac: net device context
 */
void sel3390e4_down(struct sel3390e4_mac *mac)
{
	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	/* Disable interrupts */
	sel_disable_irq(mac->hw_mac, ~0U, &mac->imask_lock);

	/* Disable the attached SFP (if any) */
	sel3390e4_sfp_disable(mac);

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)) || defined(__VMKLNX__))
	/* disable NAPI polling */
	napi_disable(&mac->napi);
#endif

	/* Stop the transmit queue */
	if (!netif_queue_stopped(mac->netdev)) {
		/* Same as netif_stop_queue, except it guarantees that
		 * xmit function is not running on any other processors
		 */
		netif_tx_disable(mac->netdev);
	}

	/* Stop the receiver */
	sel_stop_receiver(mac->hw_mac);

	/* Stop the watchdog timer */
	del_timer_sync(&mac->watchdog_timer);

	/* Reset the PHY to a known configuration */
	sel_phy_reset(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* Stop and power down the PHY */
	sel_phy_power_down(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* Free the IRQ */
	free_irq(mac->board->pdev->irq, mac->netdev);

	/* Reset hardware */
	sel_hw_reset(mac->hw_mac);

	/* Free the transmit and receive memory */
	sel3390e4_free_receive_memory(mac);
	sel3390e4_free_transmit_memory(mac);

	/* Explicitly set the link state as down */
	netif_carrier_off(mac->netdev);

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);
}

/**
 * sel3390e4_unregister_net_devices() - Unregister all the netdevices
 *
 * @board: pci device context
 */
void sel3390e4_unregister_net_devices(struct sel3390e4_board *board)
{
	int i;

	/* unregister all the net devices */

	for (i = 0; i < board->num_macs; ++i) {
		struct net_device *netdev = board->macs[i]->netdev;

		/* If we made it to registration, netdev
		 * won't ever be NULL
		 */
		if (netdev != NULL) {
			unregister_netdev(netdev);
		}
	}
}

/**
 * sel3390e4_register_net_devices() - Register all the netdevices
 *
 * @board: pci device context
 *
 * Return: 0 if successful, otherwise negative error code
 */
int sel3390e4_register_net_devices(struct sel3390e4_board *board)
{
	int err = 0;
	int i;

	/* Register the net devices */
	for (i = 0; i < board->num_macs; ++i) {
		/* Let's reset the device before we register it */
		sel_hw_reset(board->macs[i]->hw_mac);

		err = register_netdev(board->macs[i]->netdev);
		if (err) {
			break;
		}
	}

	if (err) {
		sel3390e4_unregister_net_devices(board);
	}

	return err;
}

/**
 * sel3390e4_free_net_devices() - Free all the netdevices
 *
 * @board: pci device context
 */
void sel3390e4_free_net_devices(struct sel3390e4_board *board)
{
	int i;

	for (i = 0; i < board->num_macs; i++) {
		struct net_device *netdev = board->macs[i]->netdev;

		if (netdev != NULL) {
			free_netdev(netdev);
		}
	}
}

/**
 * sel3390e4_allocate_net_devices() - Allocate and setup all the netdevices
 *
 * @board: pci device context
 *
 * Return: 0 if successful, otherwise negative error code
 */
int sel3390e4_allocate_net_devices(struct sel3390e4_board *board)
{
	int err = 0;
	int i;
	struct sel3390e4_mac *mac;
	unsigned char mac_addr[ETH_ALEN];
	struct net_device *netdev;

	/* Allocate a net_device for each of the MACs
	 * and a context for each net device
	 */
	for (i = 0; i < board->num_macs; i++) {
		netdev = alloc_etherdev(sizeof(struct sel3390e4_mac));
		if (netdev == NULL) {
			err = -ENOMEM;
			break;
		}

		/* Retrieve the allocated context */
		mac = netdev_priv(netdev);

		/* Set the transmit timeout */
		netdev->watchdog_timeo = SEL3390E4_TX_TIMEOUT;

		/* Initialize the transmit work_queue item.
		 * This work_queue is scheduled
		 * by the net_dev tx_timeout function
		 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20) || defined(__VMKLNX__))
		INIT_WORK(&mac->tx_timeout_task, sel3390e4_tx_timeout_task);
#else
		INIT_WORK(&mac->tx_timeout_task, sel3390e4_tx_timeout_task, mac);
#endif

		/* Initialize watchdog timer used to allocate rx buffers */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
		init_timer(&mac->watchdog_timer);
		mac->watchdog_timer.function = sel3390e4_rx_watchdog;
		mac->watchdog_timer.data = (unsigned long)mac;
#else
		timer_setup(&mac->watchdog_timer, sel3390e4_rx_watchdog, 0);
#endif

		spin_lock_init(&mac->tx_lock);
		spin_lock_init(&mac->rx_lock);
		spin_lock_init(&mac->imask_lock);

		mac->num_rx_bds = SEL3390E4_NUM_RX_BDS;
		mac->num_tx_bds = SEL3390E4_NUM_TX_BDS;

		/* Setup netif messaging flags, use default */
		mac->msg_enable = netif_msg_init(-1, DEFAULT_MSG_ENABLE);

		/* Set up features
		 * Our hardware supports scatter/gather (NETIF_F_SG), however,
		 * it must support some form of checksum offloading in order
		 * for the kernel to hand us scatttered packets. The kernel
		 * behaves this way because if it has to make a pass over a
		 * fragmented packet to calculate the checksum, it might as
		 * well copy the data and coalesce the packet at the same
		 * time. Thus, it needs to support either IP checksuming
		 * (NETIF_F_IP_CSUM) or all checksums (NETIF_F_HW_CSUM)
		 * as well.
		 */
		netdev->features = NETIF_F_SG;

		if (board->pci_using_dac) {
			/* 64-bit DMA is enabled, so the driver can safely handle
			 * packets placed in high memory.
			 */
			netdev->features |= NETIF_F_HIGHDMA;
		}

		/* Set up the net_device operations */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31))
		netdev->open               = sel3390e4_open;
		netdev->stop               = sel3390e4_close;
		netdev->hard_start_xmit    = sel3390e4_xmit_frame;
		netdev->set_multicast_list = sel3390e4_set_rx_mode;
		netdev->set_mac_address    = sel3390e4_set_mac;
		netdev->change_mtu         = sel3390e4_change_mtu;
		netdev->tx_timeout         = sel3390e4_tx_timeout;
		netdev->get_stats          = sel3390e4_get_stats;
		netdev->do_ioctl           = sel3390e4_ioctl;
#ifdef CONFIG_NET_POLL_CONTROLLER
		netdev->poll_controller    = sel3390e4_netpoll;
#endif

#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)) */
		netdev->netdev_ops = &sel3390e4_netdev_ops;
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)) */

		/* Set up the ethtool operations */
		sel3390e4_set_ethtool_ops(netdev);

		/* Set the PCI device as the parent of the net device. */
		SET_NETDEV_DEV(netdev, &board->pdev->dev);

#ifdef __VMKLNX__
		/* Make this netdevice a Pseudo-NIC.
		 * We do this in VMware since multi-port devices are
		 * expected to be multi-function devices under VMware. By
		 * setting the device as a Pseudo-NIC, VMware creates
		 * the net_device as a "virtual" device when register_netdev
		 * is called, and board->num_macs number of devices show up
		 * under ESXi and are all opened. If we don't do this, ESXi
		 * only opens the last device created, thus limiting us to
		 * having only one port. I have not yet seen any adverse
		 * effects to having the devices be "virtual" devices. These
		 * steps are recommended by VMware in the DDK documentation.
		 */
		netdev->pdev->netdev = NULL;
		netdev->pdev_pseudo = netdev->pdev;
		netdev->pdev = NULL;
		netdev->features |= NETIF_F_PSEUDO_REG;

		/* We give the device a name with the "" so the kernel
		 * can replace it with a respectable name, such as vmnic0.
		 */
		strcpy(netdev->name, "");

#else /* !defined(__VMKLNX__) */
		/* We give the device a name with the "%d" so the kernel
		 * can replace it with a respectable name, such as eth0.
		 */
		strcpy(netdev->name, "eth%d");
#endif /* __VMKLNX__ */

		/* Register the NAPI polling operation */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)) || defined(__VMKLNX__))
		netif_napi_add(
			netdev,
			&mac->napi,
			sel3390e4_poll,
			SEL3390E4_NAPI_WEIGHT);
#else
		netdev->poll = sel3390e4_poll;
		netdev->weight = SEL3390E4_NAPI_WEIGHT;
#endif

		/* Assign this mac a base address */
		mac->hw_mac = (struct sel3390e4_hw_mac *)(
			(unsigned char *)board->hw_macs
				+ (i*SEL3390E4_MAC_REG_SIZE));

		/* Store a copy of the net device in the
		 * net device context itself
		 */
		mac->netdev = netdev;

		/* Store the PCI device context in the net device context */
		mac->board = board;

		/* Set ID to port number to differentiate
		 * each of the net devices
		 */
		netdev->dev_id = i;

		/* Add this net device context to the list
		 * of net device contexts
		 * in the PCI device context
		 */
		board->macs[i] = mac;

		/* Get/Set the MAC address */
		(void)sel_get_mac_addr(
			board->hw_nvm,
			NVM_MAC_ADDR_OFFSETS[i],
			mac_addr,
			ETH_ALEN,
			&board->nvm_lock);
		if (!is_valid_ether_addr(mac_addr)) {
			/* invalid MAC address from flash, use all 0s */
			memset(mac_addr, 0, ETH_ALEN);
		}

		memcpy(netdev->dev_addr, mac_addr, ETH_ALEN);
		memcpy(netdev->perm_addr, mac_addr, ETH_ALEN);
	}

	if (err) {
		sel3390e4_free_net_devices(board);
	}

	return err;
}


