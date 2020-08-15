/******************************************************************************
 * COPYRIGHT (c) 2014 Schweitzer Engineering Laboratories, Inc.
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
 * Provides Access to the SEL3390E4 Hardware
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* printk */

#include <asm/atomic.h>        /* atomic operations */
#include <asm/delay.h>         /* delays */
#include <asm/io.h>            /* iowrites */
#include <linux/delay.h>       /* delays */
#include <linux/errno.h>       /* error codes */
#include <linux/interrupt.h>   /* IRQ interface */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

#include "nor_hw_ctrl.h"        /* nor interface */
#include "sel_hw.h"             /* hw interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_ethtool.h"  /* ethtool interface */
#include "sel3390e4_hw.h"       /* hw interface */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */
#include "sel3390e4_mii.h"      /* mii interface */

/**
 * sel3390e4_hw_reset_all_macs() - Reset every MAC on this device
 *
 * @board: pci device context
 */
void sel3390e4_hw_reset_all_macs(struct sel3390e4_board *board)
{
	u8 i;
	for (i = 0; i < board->num_macs; i++) {
		sel_hw_reset(board->macs[i]->hw_mac);
	}
}

/**
 * sel3390e4_update_flash() - Program binary data to flash
 *
 * @board:            pci device context
 * @section_to_write: section to write in flash
 * @buffer:           ptr to data buffer
 * @buffer_size:      size of data buffer
 * @nvm_lock:         nvm_lock nor flash lock
 *
 * Nothing must be accessing hardware while an upgrade is in progress.
 *
 * Return: 0 if successful, otherwise appropriate negative error code
 */
int sel3390e4_update_flash(
	struct sel3390e4_board *board,
	enum flash_image_section section_to_write,
	u8 const *buffer,
	u32 buffer_size,
	spinlock_t *nvm_lock
	)
{
	int err;
	struct led_settings led_settings = {0};
	u32 bytes_processed = 0;

	BUG_ON(board->pdev == NULL);

	if (buffer == NULL) {
		return -EINVAL;
	}

	if (!atomic_dec_and_test(&board->firmware_upgrade_in_progress)) {
		/* flash update is already in progress */
		atomic_inc(&board->firmware_upgrade_in_progress);
		return -EBUSY;
	}

	dev_info(
		&board->pdev->dev,
		"Starting flash update.\n");

	/* We turn the LEDs on in ALARM MODE at the start of
	 * and upgrade process, and return them to NORMAL mode
	 * when the upgrade is complete, or an error occurs.
	 */

	led_settings.led_mode = DIAG_ALARM_STATE;
	led_settings.led_colors = DIAG_COLOR_ALL;
	(void)sel_diag_set_leds(board->hw_diag, led_settings, 0);

	err =
		dump_file_to_flash(
			board->hw_nvm,
			section_to_write,
			buffer,
			buffer_size,
			&bytes_processed,
			nvm_lock);

	led_settings.led_mode = DIAG_NORMAL;
	(void)sel_diag_set_leds(board->hw_diag, led_settings, 0);

	if (!err) {
		dev_info(
			&board->pdev->dev,
			"Successfully updated flash. Reboot may be required.\n");
	} else {
		dev_err(
			&board->pdev->dev,
			"[ERROR] Failed to update flash.\n");
	}

	/* flash update no longer in progress */
	atomic_inc(&board->firmware_upgrade_in_progress);

	return err;
}

/**
 * sel3390e4_update_device_stats() - Update Device Stats
 *
 * @mac: PCI device context
 *
 * TX/RX total packets/bytes sent/received are updated by the driver in
 * the RX and TX datapaths, and don't use the device stats. Stats are
 * stored in the device context. This function cannot be called higher
 * than software interrupt context.
 */
void sel3390e4_update_device_stats(struct sel3390e4_mac *mac)
{
	mac->device_stats.out_packets +=
		ioread32(&mac->hw_mac->stats.out_packets);
	mac->device_stats.out_frag_packets +=
		ioread32(&mac->hw_mac->stats.out_frag_packets);
	mac->device_stats.restart_frames +=
		ioread32(&mac->hw_mac->stats.restart_frames);
	mac->device_stats.excessive_collisions +=
		ioread32(&mac->hw_mac->stats.excessive_collisions);
	mac->device_stats.in_packets +=
		ioread32(&mac->hw_mac->stats.in_packets);
	mac->device_stats.in_crc_err +=
		ioread32(&mac->hw_mac->stats.in_crc_err);
	mac->device_stats.in_buff_ovf +=
		ioread32(&mac->hw_mac->stats.in_buff_ovf);
	mac->device_stats.in_runt_packets +=
		ioread32(&mac->hw_mac->stats.in_runt_packets);
	mac->device_stats.in_64_packets +=
		ioread32(&mac->hw_mac->stats.in_64_packets);
	mac->device_stats.in_65_127_packets +=
		ioread32(&mac->hw_mac->stats.in_65_127_packets);
	mac->device_stats.in_128_255_packets +=
		ioread32(&mac->hw_mac->stats.in_128_255_packets);
	mac->device_stats.in_256_511_packets +=
		ioread32(&mac->hw_mac->stats.in_256_511_packets);
	mac->device_stats.in_512_1023_packets +=
		ioread32(&mac->hw_mac->stats.in_512_1023_packets);
	mac->device_stats.in_1024_1518_packets +=
		ioread32(&mac->hw_mac->stats.in_1024_1518_packets);
	mac->device_stats.jumbo_packets +=
		ioread32(&mac->hw_mac->stats.jumbo_packets);
	mac->device_stats.in_broadcast_packets +=
		ioread32(&mac->hw_mac->stats.in_broadcast_packets);
	mac->device_stats.in_multicast_packets +=
		ioread32(&mac->hw_mac->stats.in_multicast_packets);
	mac->device_stats.in_unicast_packets +=
		ioread32(&mac->hw_mac->stats.in_unicast_packets);
	mac->device_stats.in_misses +=
		ioread32(&mac->hw_mac->stats.in_misses);
	mac->device_stats.in_promiscuous_only_packets +=
		ioread32(&mac->hw_mac->stats.in_promiscuous_only_packets);
	mac->device_stats.out_discards +=
		ioread32(&mac->hw_mac->stats.out_discards);
	mac->device_stats.in_discards +=
		ioread32(&mac->hw_mac->stats.in_discards);
	mac->device_stats.out_octets +=
		ioread32(&mac->hw_mac->stats.out_octets);
	mac->device_stats.in_octets +=
		ioread32(&mac->hw_mac->stats.in_octets);

	mac->stats.rx_errors =
		mac->device_stats.in_crc_err +
		mac->device_stats.in_buff_ovf +
		mac->device_stats.in_discards;

	mac->stats.tx_errors =
		mac->device_stats.out_frag_packets +
		mac->device_stats.out_discards;

	mac->stats.rx_dropped =
		mac->device_stats.in_crc_err +
		mac->device_stats.in_buff_ovf +
		mac->device_stats.in_runt_packets +
		mac->device_stats.jumbo_packets +
		mac->device_stats.in_discards;

	mac->stats.tx_dropped =
		mac->device_stats.out_discards;

	mac->stats.multicast = mac->device_stats.in_multicast_packets;
	mac->stats.collisions = mac->device_stats.excessive_collisions;

	mac->stats.rx_length_errors =
		mac->device_stats.in_runt_packets +
		mac->device_stats.jumbo_packets;
	mac->stats.rx_over_errors = mac->device_stats.in_buff_ovf;
	mac->stats.rx_crc_errors = mac->device_stats.in_crc_err;
	mac->stats.rx_frame_errors = 0;
	mac->stats.rx_fifo_errors = mac->device_stats.in_discards;

        /* This is not the missed counter from hardware.  This is actually
         * missed packets due to resource problems, which equates to
         * overflow errors in our card. */
	mac->stats.rx_missed_errors = mac->device_stats.in_buff_ovf;

	mac->stats.tx_aborted_errors = mac->device_stats.out_discards;
	mac->stats.tx_carrier_errors = 0;
	mac->stats.tx_fifo_errors = mac->device_stats.out_discards;
	mac->stats.tx_heartbeat_errors = 0;
	mac->stats.tx_window_errors = 0;

	mac->stats.rx_compressed = 0;
	mac->stats.tx_compressed = 0;
}
