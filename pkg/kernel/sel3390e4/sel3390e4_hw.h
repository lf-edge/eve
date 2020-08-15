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

#ifndef SEL3390E4_HW_H_INCLUDED
#define SEL3390E4_HW_H_INCLUDED

#include <linux/netdevice.h>   /* net device interface */
#include <linux/types.h>       /* types */

#include "nor_hw_ctrl.h"        /* nor interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_hw_regs.h"  /* hw data types */

/**
 * sel3390e4_hw_reset_all_macs() - Reset every MAC on this device
 *
 * @board: pci device context
 */
void sel3390e4_hw_reset_all_macs(struct sel3390e4_board *board);

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
	);

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
void sel3390e4_update_device_stats(struct sel3390e4_mac *mac);

#endif /* SEL3390E4_HW_H_INCLUDED */
