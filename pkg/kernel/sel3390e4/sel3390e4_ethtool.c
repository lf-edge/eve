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
 * Ethtool Interface
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* kern-specific macros */

#include <asm/delay.h>         /* delays */
#include <asm/io.h>            /* iowrites */
#include <linux/delay.h>       /* delays */
#include <linux/errno.h>       /* error codes */
#include <linux/ethtool.h>     /* ethtool interface */
#include <linux/if_ether.h>    /* ethernet definitions */
#include <linux/firmware.h>    /* firmware data */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/skbuff.h>      /* skb allocations */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

#include "netdev.h"             /* netdev interface */
#include "netdev_rx.h"          /* netdevice rx interface */
#include "netdev_tx.h"          /* netdevice tx interface */
#include "nor_hw_ctrl.h"        /* NOR flash library */
#include "sel_hw.h"             /* hw interface */
#include "sel_phy.h"            /* phy interface */
#include "sel3390e4_mii.h"      /* mii interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_ethtool.h"  /* ethtool interface */
#include "sel3390e4_hw.h"       /* hw interface */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
/**
 * ethtool_get_ksettings() - Get various device settings
 *
 * @netdev: net device object
 * @ks:    the ksettings to get
 *
 * Return: 0 if successful, otherwise an appropriate negative error code
 */
static int ethtool_get_ksettings(
	struct net_device *netdev,
	struct ethtool_link_ksettings *ks
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	return sel3390e4_mii_ethtool_gksettings(&mac->mii_if, ks);
}

/**
 * ethtool_set_ksettings() - Set various device settings
 *
 * @netdev: net device object
 * @ks:    the ksettings to set
 *
 * Return: 0 if successful, otherwise an appropriate negative error code
 */
static int ethtool_set_ksettings(
	struct net_device *netdev,
	const struct ethtool_link_ksettings *ks
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	return sel3390e4_mii_ethtool_sksettings(&mac->mii_if, ks);
}

#else
/**
 * ethtool_get_settings() - Get various device settings
 *
 * @netdev: net device object
 * @cmd:    the command to execute
 *
 * Return: 0 if successful, otherwise an appropriate negative error code
 */
static int ethtool_get_settings(
	struct net_device *netdev,
	struct ethtool_cmd *cmd
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	return sel3390e4_mii_ethtool_gset(&mac->mii_if, cmd);
}

/**
 * ethtool_set_settings() - Set various device settings
 *
 * @netdev: net device object
 * @cmd:    the command to execute
 *
 * Return: 0 if successful, otherwise an appropriate negative error code
 */
static int ethtool_set_settings(
	struct net_device *netdev,
	struct ethtool_cmd *cmd
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	return sel3390e4_mii_ethtool_sset(&mac->mii_if, cmd);
}
#endif

/**
 * ethtool_get_drvinfo() - Set ethtool driver information
 *
 * @netdev: net device object
 * @info:   driver information for ethtool
 */
static void ethtool_get_drvinfo(
	struct net_device *netdev,
	struct ethtool_drvinfo *info
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	char build_id_string[15];

	/* Get the firmware version */
	sprintf(
		build_id_string, 
		"%d.%d.%d.%d", 
		((mac->board->build_id >> 24) & 0xFF),
		((mac->board->build_id  >> 16) & 0xFF),
		((mac->board->build_id >> 8) & 0xFF),
		(mac->board->build_id & 0xFF));

	strlcpy(info->driver, SEL3390E4_DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, SEL3390E4_DRV_VERSION, sizeof(info->version));
	strlcpy(info->fw_version, build_id_string, sizeof(info->fw_version));
	strlcpy(
		info->bus_info,
		pci_name(mac->board->pdev),
		sizeof(info->bus_info));
}

/**
 * ethtool_get_regs_len() - Get the length of the hardware register memory
 *
 * @netdev: net device object
 *
 * Return: the size of the register memory
 */
static int ethtool_get_regs_len(struct net_device *netdev)
{
	return SEL3390E4_MAC_REG_SIZE;
}

/**
 * ethtool_get_regs() - Dump the internal hardware registers
 *
 * @netdev: net device object
 * @regs:   ethtool specific information
 * @p:      output buffer for device registers
 */
static void ethtool_get_regs(
	struct net_device *netdev,
	struct ethtool_regs *regs,
	void *p
	)
{
	u32 i = 0;
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	u32 *buff = p;

	memset(buff, 0, SEL3390E4_MAC_REG_SIZE);

	for (i = 0; i < SEL3390E4_NUM_MAC_REGISTERS; ++i) {
		buff[i] = ioread32((u32 *)mac->hw_mac + i);
	}
}

/**
 * ethtool_get_msglevel() - Get the currently set message tracing level
 *
 * @netdev: net device object
 *
 * Return: the message level set
 */
static u32 ethtool_get_msglevel(struct net_device *netdev)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	return mac->msg_enable;
}

/**
 * ethtool_set_msglevel() - Set a new message tracing level
 *
 * @netdev: net device object
 * @value:  the message level to set
 */
static void ethtool_set_msglevel(struct net_device *netdev, u32 value)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	mac->msg_enable = value;
}

/**
 * ethtool_nway_reset() - Restart Autonegotiation
 *
 * @netdev: net device object
 *
 * Return: 0 if successful, otherwise appropriate negative error code
 */
static int ethtool_nway_reset(struct net_device *netdev)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	return sel3390e4_mii_nway_restart(&mac->mii_if);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32))

/**
 * ethtool_flash_device() - Flash Peripheral Firmware Image
 *
 * @netdev: net device object
 * @eflash: input flash parameters
 *
 * This function brings down all net device interfaces before
 * beginning device programming, and brings them up again
 * when done (if they were previously running).
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
static int ethtool_flash_device(
	struct net_device *netdev,
	struct ethtool_flash *eflash
	)
{
	int err;
	int i;
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	struct sel3390e4_board *board = mac->board;
	struct firmware const *fw;

	/* Bring down all the devices since we are
	 * about to upgrade the firmware
	 */
	for (i = 0; i < board->num_macs; i++) {
		if (netif_running(board->macs[i]->netdev)) {
			sel3390e4_down(board->macs[i]);
		}
	}

	err = request_firmware(&fw, eflash->data, &board->pdev->dev);

	if (!err) {
		err = 
			sel3390e4_update_flash(
				board, 
				FLASH_IMAGE_FUNCTIONAL, 
				fw->data, 
				fw->size,
				&board->nvm_lock);

		release_firmware(fw);
	}

	/* Bring back up all the net devices now that
	 * we are done upgrading the firmware
	 */
	for (i = 0; i < board->num_macs; i++) {
		if (netif_running(board->macs[i]->netdev)) {
			(void)sel3390e4_up(board->macs[i]);
		}
	}

	return err;
}

#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)) */

/**
 * ethtool_get_ringparam() - Get the current RX/TX ring parameters
 *
 * @netdev: net device object
 * @ring:   ring parameters output buffer
 */
static void ethtool_get_ringparam(
	struct net_device *netdev,
	struct ethtool_ringparam *ring
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	ring->rx_max_pending = SEL3390E4_MAX_NUM_RX_BDS;
	ring->tx_max_pending = SEL3390E4_MAX_NUM_TX_BDS;

	ring->rx_pending = mac->num_rx_bds;
	ring->tx_pending = mac->num_tx_bds;
}

/**
 * ethtool_set_ringparam() - Set new RX/TX ring parameters
 *
 * @netdev: net device object
 * @ring:   ring parameters input buffer
 *
 * Return: 0 if successful, otherwise appropriate negative error code
 */
static int ethtool_set_ringparam(
	struct net_device *netdev,
	struct ethtool_ringparam *ring
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	if ((ring->rx_mini_pending > 0) || (ring->rx_jumbo_pending > 0)) {
		/* Prevent the user from changing the minimum rxbds and
		 * anything concerning jumbo frames, since they aren't supported.
		 */
		return -EINVAL;
	}

	if (netif_running(netdev)) {
		sel3390e4_down(mac);
	}

	mac->num_rx_bds = max(ring->rx_pending, (u32)SEL3390E4_MIN_NUM_RX_BDS);
	mac->num_rx_bds = min(mac->num_rx_bds, (u32)SEL3390E4_MAX_NUM_RX_BDS);
	mac->num_tx_bds = max(ring->tx_pending, (u32)SEL3390E4_MIN_NUM_TX_BDS);
	mac->num_tx_bds = min(mac->num_tx_bds, (u32)SEL3390E4_MAX_NUM_TX_BDS);

	if (netif_running(netdev)) {
		(void)sel3390e4_up(mac);
	}

	return 0;
}

/* eth_tool ETH_SS_TEST strings */
static char const SEL3390E4_GSTRINGS_TEST[][ETH_GSTRING_LEN] = {
	"Link test      (on/offline)",
	"Loopback test  (offline)"
};
#define SEL3390E4_TEST_LEN ARRAY_SIZE(SEL3390E4_GSTRINGS_TEST)

/**
 * sel3390e4_loopback_test() - Loopback Test
 *
 * @mac: net device context
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
static int sel3390e4_loopback_test(struct sel3390e4_mac *mac)
{
	int err;
	struct sk_buff *skb;

	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	/* Allocate the receive memory */
	err = sel3390e4_alloc_receive_memory(mac);
	if (err) {
		goto all_done;
	}

	/* Allocate the transmit memory */
	err = sel3390e4_alloc_transmit_memory(mac);
	if (err) {
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
		goto err_tx_clean_list;
	}

	/* Start up the PHY */
	sel_phy_power_up(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* Enable MAC Loopback */
	sel_read_mod_write(
		&mac->hw_mac->mac.mac_config,
		MCCFG_LOOP,
		0);

	/* Start the receiver */
	sel_start_receiver(mac->hw_mac);

	/* Create the SKB */
	skb = netdev_alloc_skb(mac->netdev, ETH_DATA_LEN + NET_IP_ALIGN);
	if (skb == NULL) {
		err = -ENOMEM;
		goto err_tx_clean_list;
	}

	/* Align IP header */
	skb_reserve(skb, NET_IP_ALIGN);

	skb_put(skb, ETH_DATA_LEN);
	memset(skb->data, 0xAE, ETH_DATA_LEN);

	/* Transmit the packet */
	(void)sel3390e4_xmit_frame(skb, mac->netdev);

	/* Sleep to allow time for the packet to be sent */
	msleep(10);

	/* Sync the DMA so we have the updated contents */
	pci_dma_sync_single_for_cpu(
		mac->board->pdev,
		le64_to_cpu(mac->base_rx_bd[mac->rx_to_clean].rx_data_buff_ptr),
		SEL3390E4_RX_BUFF_LEN,
		PCI_DMA_FROMDEVICE);

	if (memcmp(
		mac->rx_skb[mac->rx_to_clean]->data,
		skb->data,
		ETH_DATA_LEN)) {
		err = -EIO;
	}

	sel_stop_receiver(mac->hw_mac);

	/* Power down the PHY */
	sel_phy_power_down(mac->hw_mac, mac->mii_if.phy_id, &mac->board->mdio_lock);

	/* re-init hardware */
	sel_hw_reset(mac->hw_mac);

err_tx_clean_list:

	sel3390e4_free_transmit_memory(mac);

err_rx_clean_list:

	sel3390e4_free_receive_memory(mac);

all_done:

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);

	return err;
}

/**
 * ethtool_diag_test() - Perform device diagnostics tests
 *
 * @netdev: net device object
 * @test:   contains test params
 * @data:   output test results
 */
static void ethtool_diag_test(
	struct net_device *netdev,
	struct ethtool_test *test,
	u64 *data
	)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	struct ethtool_link_ksettings ks;
#else
	struct ethtool_cmd cmd;
#endif
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	int i;

	memset(data, 0, SEL3390E4_TEST_LEN * sizeof(u64));

	data[0] = !sel3390e4_mii_link_ok(&mac->mii_if);

	if ((test->flags & ETH_TEST_FL_OFFLINE) != 0) {
		/* save speed, duplex & autoneg settings
		 * if this fails, there isn't anything we can do
		 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
		(void)sel3390e4_mii_ethtool_gksettings(&mac->mii_if, &ks);
#else
		(void)sel3390e4_mii_ethtool_gset(&mac->mii_if, &cmd);
#endif

		/* Bring down the net device interface */
		if (netif_running(netdev)) {
			sel3390e4_down(mac);
		}

		data[1] = sel3390e4_loopback_test(mac);

		/* restore speed, duplex & autoneg settings
		 * if this fails, there isn't anything we can do
		 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
		(void)sel3390e4_mii_ethtool_sksettings(&mac->mii_if, &ks);
#else
		(void)sel3390e4_mii_ethtool_sset(&mac->mii_if, &cmd);
#endif

		/* Bring back up the net device interface */
		if (netif_running(netdev)) {
			(void)sel3390e4_up(mac);
		}

		/* We need to sleep here so that subsequent calls to
		 * ethtool test will get an accurate value for the
		 * link test. If we don't sleep here, then a subsequent
		 * test could be called before a link is detected by the
		 * PHY. It was found in testing that 3 seconds is a
		 * sufficient sleep time.
		 */
		msleep_interruptible(3000);
	}

	for (i = 0; i < SEL3390E4_TEST_LEN; i++) {
		test->flags |= (data[i] ? ETH_TEST_FL_FAILED : 0);
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))

/**
 * ethtool_set_phys_id() - Identify physical devices
 *
 * @netdev: net device object to identify
 * @state:  the state to set the LEDs to
 *
 * It is initially called with the argument ETHTOOL_ID_ACTIVE,
 * and must either activate asynchronous updates and return zero, return
 * a negative error or return a positive frequency for synchronous
 * indication (e.g. 1 for one on/off cycle per second).  If it returns
 * a frequency then it will be called again at intervals with the
 * argument ETHTOOL_ID_ON or ETHTOOL_ID_OFF and should set the state of
 * the indicator accordingly. Finally, it is called with the argument
 * ETHTOOL_ID_INACTIVE and must deactivate the indicator.
 *
 * Return: > 0 if successful, otherwise appropriate negative return value
 */
static int ethtool_set_phys_id(
	struct net_device *netdev,
	enum ethtool_phys_id_state state
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	struct led_settings led_settings = {0};
	int err = 0;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		/* We return a postive value which will indicate the
		 * frequency at which this function is called with
		 * ETHTOOL_ID_ON and ETHTOOL_ID_OFF.
		 * (e.g. 2 for 2 on/off cycle per second)
		 */
		return 2;

	case ETHTOOL_ID_ON:
		led_settings.led_colors = DIAG_COLOR_ALL;
		led_settings.led_mode = DIAG_DIRECT_CONTROL;
		break;

	case ETHTOOL_ID_OFF:
		led_settings.led_colors = DIAG_COLOR_NONE;
		led_settings.led_mode = DIAG_DIRECT_CONTROL;
		break;

	case ETHTOOL_ID_INACTIVE:
		led_settings.led_mode = DIAG_NORMAL;
		break;

	default:
		/* This line should never be hit */
		BUG();
	}

	err = sel_diag_set_leds(mac->board->hw_diag, led_settings, netdev->dev_id);

	return err;
}

#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)) */

/**
 * ethtool_phys_id() - Identify physical devices
 *
 * @netdev: net device object to identify
 * @data:   the number of times to blink the led
 *
 * Return: > 0 if successful, otherwise appropriate negative return value
 */
static int ethtool_phys_id(
	struct net_device *netdev,
	u32 data
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	struct led_settings led_settings = {0};
	int i;

	if (data == 0) {
		/* We return a postive value which will indicate the
		 * frequency at which this function is called with
		 * ETHTOOL_ID_ON and ETHTOOL_ID_OFF.
		 * (e.g. 2 for 2 on/off cycle per second if 0 was given)
		 */
		data = 2;
	}

	for (i = 0; i < (data * 2); i++) {
		led_settings.led_mode = DIAG_DIRECT_CONTROL;

		if ((i & 1) == 0) {
			led_settings.led_colors = DIAG_COLOR_ALL;
		} else {
			led_settings.led_colors = DIAG_COLOR_NONE;
		}

		(void)sel_diag_set_leds(mac->board->hw_diag, led_settings, netdev->dev_id);

		/* Sleeps in user context shouldn't ever really be
		 * blocking sleeps. We want other processes to be able to
		 * run if needed, thus we allow the sleep to be interrupted
		 * by a high priority task. Usually, however, we won't be
		 * interrupted, and the lights will flash at a constant rate.
		 */
		if (msleep_interruptible(500)) {
			break;
		}
	}

	led_settings.led_mode = DIAG_NORMAL;
	(void)sel_diag_set_leds(mac->board->hw_diag, led_settings, netdev->dev_id);

	return 0;
}

#endif /* (LINUX_VERSION_CODE) */

/* eth_tool ETH_SS_STATS strings */
static char const SEL3390E4_GSTRINGS_STATS[][ETH_GSTRING_LEN] = {
	"rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors",
	"tx_errors", "rx_dropped", "tx_dropped", "multicast", "collisions",
	"rx_length_errors", "rx_over_errors", "rx_crc_errors",
	"rx_frame_errors", "rx_fifo_errors", "rx_missed_errors",
	"tx_aborted_errors", "tx_carrier_errors", "tx_fifo_errors",
	"tx_heartbeat_errors", "tx_window_errors",
	/* device-specific stats */
	"out_packets", "out_frag_packets", "restart_frames",
	"excessive_collisions", "in_packets",
	"in_crc_err", "in_buff_ovf", "in_runt_packets",
	"in_64_packets", "in_64_127_packets", "in_128_255_packets",
	"in_256_511_packets", "in_512_1023_packets", "in_1024_1518_packets",
	"jumbo_packets", "in_broadcast_packets", "in_multicast_packets",
	"in_unicast_packets", "in_misses", "in_promiscuous_only_packets",
	"out_discards", "in_discards", "out_octets", "in_octets"
};
#define SEL3390E4_NET_STATS_LEN 21
#define SEL3390E4_STATS_LEN ARRAY_SIZE(SEL3390E4_GSTRINGS_STATS)
#define SEL3390E4_DEVICE_STATS_LEN 24

/**
 * ethtool_get_self_test_count() - Return the number of strings that
 * get_strings will return
 *
 * @netdev: net device object
 *
 * Return: the number of self tests
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
static int ethtool_get_self_test_count(struct net_device *netdev)
{
	return SEL3390E4_TEST_LEN;
}

/**
 * ethtool_get_stats_count() - Return the number of statistics obtained
 *
 * @netdev: net device object
 *
 * Return: the number of stats returned
 */
static int ethtool_get_stats_count(struct net_device *netdev)
{
	return SEL3390E4_STATS_LEN;
}

#else
/**
 * ethtool_get_sset_count() - Return the number of strings that
 * get_strings will return
 *
 * @netdev: net device object
 * @sset:   the string set being queried
 *
 * Return: the number of strings returned, or -EOPNOTSUPP if invalid sset
 */
static int ethtool_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_TEST:
		return SEL3390E4_TEST_LEN;

	case ETH_SS_STATS:
		return SEL3390E4_STATS_LEN;

	default:
		return -EOPNOTSUPP;
	}
}
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)) */

/**
 * ethtool_get_ethtool_stats() - Return extended statistics about the device
 *
 * @netdev: net device object
 * @stats:  unused parameter
 * @data:   output statistics
 */
static void ethtool_get_ethtool_stats(
	struct net_device *netdev,
	struct ethtool_stats *stats,
	u64 *data
	)
{
	u32 i;
	u32 j = 0;
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	sel3390e4_update_device_stats(mac);

	/* Retrive and store device stats that we support */
	for (i = 0; i < SEL3390E4_NET_STATS_LEN; i++) {
		data[i] = ((unsigned long *)&mac->stats)[i];
	}

	/* Device Specific Stats */
	for (; i < (SEL3390E4_NET_STATS_LEN + SEL3390E4_DEVICE_STATS_LEN); i++) {
		data[i] = ((u64 *)&mac->device_stats)[j];
		j++;
	}
}

/*
 * ethtool_get_strings() - Return a set of strings that describe this device
 *
 * @netdev:    net device object
 * @stringset: the string set requested
 * @data:      null terminated strings
 */
static void ethtool_get_strings(
	struct net_device *netdev,
	u32 stringset,
	u8 *data)
{
	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(
			data,
			*SEL3390E4_GSTRINGS_TEST,
			sizeof(SEL3390E4_GSTRINGS_TEST));
		break;

	case ETH_SS_STATS:
		memcpy(
			data,
			*SEL3390E4_GSTRINGS_STATS,
			sizeof(SEL3390E4_GSTRINGS_STATS));
		break;

	default:
		/* This line should never be hit */
		BUG();
	}
}

/* Supported ethtool operations */
static struct ethtool_ops sel3390e4_ethtool_ops = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	.get_link_ksettings     = ethtool_get_ksettings,
	.set_link_ksettings     = ethtool_set_ksettings,
#else
	.get_settings           = ethtool_get_settings,
	.set_settings           = ethtool_set_settings,
#endif
	.get_drvinfo            = ethtool_get_drvinfo,
	.get_regs_len           = ethtool_get_regs_len,
	.get_regs               = ethtool_get_regs,
	.get_msglevel           = ethtool_get_msglevel,
	.set_msglevel           = ethtool_set_msglevel,
	.nway_reset             = ethtool_nway_reset,
	.get_link               = ethtool_op_get_link, /* standard func */
	.get_ringparam          = ethtool_get_ringparam,
	.set_ringparam          = ethtool_set_ringparam,
	.self_test              = ethtool_diag_test,
	.get_strings            = ethtool_get_strings,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32))
	.flash_device           = ethtool_flash_device,
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	.set_phys_id            = ethtool_set_phys_id,
#else
	.phys_id                = ethtool_phys_id,
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0))
	.get_ts_info            = ethtool_op_get_ts_info,  /* standard func */
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	.self_test_count        = ethtool_get_self_test_count,
	.get_stats_count        = ethtool_get_stats_count,
#else
	.get_sset_count         = ethtool_get_sset_count,
#endif

	.get_ethtool_stats      = ethtool_get_ethtool_stats,
};

/**
 * sel3390e4_set_ethtool_ops() - initialize ethtool ops
 *
 * @netdev: net device object
 */
void sel3390e4_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &sel3390e4_ethtool_ops;
}
