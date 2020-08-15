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
 * HW Interface
 ******************************************************************************
 */

#ifndef SEL_HW_H_INCLUDED
#define SEL_HW_H_INCLUDED

#include <linux/netdevice.h>
#include <linux/types.h>       /* types */

#include "sel3390e4_hw_regs.h"  /* hw register definitions */

/**
 * sel_write_flush() - Flush PCI writes
 *
 * @hw_mac: MAC base address register
 */
void sel_write_flush(struct sel3390e4_hw_mac *hw_mac);
/**
 * sel_read_mod_write() - Read/Modify/Write a device address
 *
 * @addr:       the address to modify
 * @set_bits:   the bits to set
 * @clear_bits: the bits to clear
 */
void sel_read_mod_write(
	void __iomem *addr,
	u32 set_bits,
	u32 clear_bits
	);

/**
 * sel3390e4_hw_reset() - Reset a MAC
 *
 * @hw_mac: MAC base address register
 */
void sel_hw_reset(struct sel3390e4_hw_mac *hw_mac);

/**
 * sel3390e4_diag_set_leds() - Set LEDs in hardware
 *
 * @hw_diag:      DIAG base address register
 * @led_settings: led settings
 * @port_number:  the port LED to configure
 *
 * Return: 0 if successful, otherwise -EINVAL
 */
int sel_diag_set_leds(
	struct sel3390e4_hw_diag *hw_diag,
	struct led_settings led_settings,
	u8 port_number
	);

/**
 * sel_get_mac_addr() - Get MAC address from flash
 *
 * @hw_nvm:      NOR base address register
 * @offset:      offset to read from flash
 * @buffer:      buffer to store 6-byte mac address
 * @buffer_size: size of destination buffer
 * @nvm_lock:    nvm_lock nor flash lock
 *
 * Return: 0 if successful, otherwise an appropriate error value
 */
int sel_get_mac_addr(
	u32 __iomem *hw_nvm,
	enum sel3390e4_nvm_rw_storage_offsets offset,
	u8 *buffer,
	u8 buffer_size,
	spinlock_t *nvm_lock
	);

/**
 * sel_enable_irq() - Enable interrupts related to a MAC
 *
 * @hw_mac:     MAC base address register
 * @imask:      the interrupt mask to set
 * @imask_lock: interrupt lock
 */
void sel_enable_irq(
	struct sel3390e4_hw_mac *hw_mac,
	u32 imask,
	spinlock_t *imask_lock
	);

/**
 * sel_disable_irq() - Disable interrupts related to a MAC
 *
 * @hw_mac:     MAC base address register
 * @imask:      the interrupt mask to clear
 * @imask_lock: interrupt lock
 *
 * This function requires the interrupt lock to be held.
 */
void sel_disable_irq(
	struct sel3390e4_hw_mac *hw_mac,
	u32 imask,
	spinlock_t *imask_lock
	);

/**
 * sel_set_hw_mac_addr() - Set the mac address directly in hardware
 *
 * @hw_mac:      MAC base address register
 * @mac_address: 6-byte mac address
 * @size:        size of input buffer
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
int sel_set_hw_mac_addr(
	struct sel3390e4_hw_mac *hw_mac,
	u8 *mac_address,
	u8 size
	);

/**
 * sel_hw_init() - Initialize a hardware mac
 *
 * @hw_mac:              MAC base address register
 * @base_rx_bd_dma_addr: base rxbd physical address
 * @base_tx_bd_dma_addr: base txbd physical address
 * @mac_address:         6-byte mac address
 * @mac_address_size:    size of input mac address (in bytes)
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
int sel_hw_init(
	struct sel3390e4_hw_mac *hw_mac,
	u64 base_rx_bd_dma_addr,
	u64 base_tx_bd_dma_addr,
	u8 *mac_address,
	u8 mac_address_size
	);

/**
 * sel_start_receiver() - Start the hardware receiver
 *
 * @hw_mac: MAC base address register
 */
void sel_start_receiver(struct sel3390e4_hw_mac *hw_mac);

/**
 * sel_stop_receiver() - Stop the hardware receiver
 *
 * @hw_mac: MAC base address register
 */
void sel_stop_receiver(struct sel3390e4_hw_mac *hw_mac);

/**
 * sel3390e4_write_mc_addr() - Set a new multicast list
 *
 * @hw_mac:                 MAC base address register
 * @netdev:                 OS's reference to our net device
 *
 * The hash table process used in the group hash filtering operates as follows.
 * The Ethernet controller maps any 48-bit destination address into one
 * of 256 bins, represented by the 256 bits in GADDR0 - 7. The eight
 * low-order bits of a 32-bit cyclic redundancy check (CRC) checksum of the
 * 48-bit DA field are used to index into the hash table.  The three
 * high order bits of this 8-bit field are used to select one of the eight
 * registers in the group hash table.  The low-order five bits select a bit
 * within the 32-bit register.  A value of 0 selects GADDR0 bit 0.
 */
void sel_write_mc_addr_list(
	struct sel3390e4_hw_mac *hw_mac,
	struct net_device *netdev
	);

/**
 * sel_enable_promiscuous_mode() - Enable promiscuous mode
 *
 * @hw_mac: MAC base address register
 */
void sel_enable_promiscuous_mode(struct sel3390e4_hw_mac *hw_mac);

/**
 * sel_disable_promiscuous_mode() - Disable promiscuous mode
 *
 * @hw_mac: MAC base address register
 */
void sel_disable_promiscuous_mode(struct sel3390e4_hw_mac *hw_mac);

/**
 * sel_enable_multicast() - Enable all multicast addresses
 *
 * @hw_mac: MAC base address register
 */
void sel_enable_multicast(struct sel3390e4_hw_mac *hw_mac);

/**
 * sel_disable_multicast() - Disable all multicast addresses
 *
 * @hw_mac: MAC base address register
 */
void sel_disable_multicast(struct sel3390e4_hw_mac *hw_mac);

#endif /* SEL_HW_H_INCLUDED */
