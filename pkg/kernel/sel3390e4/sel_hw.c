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

#include <linux/kernel.h>      /* kern-specific info */

#include <asm/delay.h>         /* delays */
#include <asm/byteorder.h>     /* byte ordering (le32_to_cpu) */
#include <asm/io.h>            /* iowrites */
#include <linux/crc32.h>       /* crc32 */
#include <linux/delay.h>       /* delays */
#include <linux/errno.h>       /* error codes */
#include <linux/netdevice.h>
#include <linux/spinlock.h>    /* locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>

#include "nor_hw_ctrl.h"       /* NOR flash library */
#include "sel_hw.h"            /* hw interface */
#include "sel3390e4_hw_regs.h" /* hw register definitions */

/**
 * sel_write_flush() - Flush PCI writes
 *
 * @hw_mac: MAC base address register
 */
void sel_write_flush(struct sel3390e4_hw_mac *hw_mac)
{
	/* Flush PCI writes by doing a benign read */
	(void)ioread32(&hw_mac->reserved_1[0]);
}


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
	)
{
	u32 data = 0;

	data = ioread32(addr);
	data |= set_bits;
	data &= ~clear_bits;
	iowrite32(data, addr);
}

/**
 * sel3390e4_hw_reset() - Reset a MAC
 *
 * @hw_mac: MAC base address register
 */
void sel_hw_reset(struct sel3390e4_hw_mac *hw_mac)
{
	/* flush */
	ioread32(&hw_mac->reserved_1[0]);

	iowrite32(MCCFG_SOFT_RESET, &hw_mac->mac.mac_config);

	udelay(10);

	/* flush */
	ioread32(&hw_mac->reserved_1[0]);

	/* Clear the MAC config register to complete the reset */
	iowrite32(0, &hw_mac->mac.mac_config);

	/* flush */
	sel_write_flush(hw_mac);
}

/* LED color offsets */
static u8 const LED_COLOR_MASKS[] = {
	DIAG_COLOR_OFFSET_1,
	DIAG_COLOR_OFFSET_2,
	DIAG_COLOR_OFFSET_3,
	DIAG_COLOR_OFFSET_4
};

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
	)
{
	int err = 0;
	u32 device_settings = 0;

	if (port_number > ARRAY_SIZE(LED_COLOR_MASKS)) {
		return -EINVAL;
	}

	switch (led_settings.led_mode) {
	case DIAG_NORMAL:
	case DIAG_DIRECT_CONTROL:
	case DIAG_DIRECT_CONTROL_BLINK:
	case DIAG_ALARM_STATE:

		device_settings = led_settings.led_mode;
		break;

	default:
		return -EINVAL;
	}

	/* We don't need to set the colors for an alarm state */
	if (led_settings.led_mode != DIAG_ALARM_STATE) {
		/* Set the port specific colors */
		device_settings |=
			((u32)led_settings.led_colors
				<< LED_COLOR_MASKS[port_number]);
	}

	iowrite32(device_settings, &hw_diag->led_ctrl);

	/* flush */
	ioread32(&hw_diag->reserved[0]);

	return err;
}

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
	)
{
	int err;
	int i;
	unsigned char temp_buffer[6];
	u32 number_bytes = 6;

	if ((buffer == NULL) || (buffer_size < 6)) {
		return -EINVAL;
	}

	memset(buffer, 0, 6);

	err =  dump_flash_rw_storage(
			hw_nvm,
			offset,
			temp_buffer,
			&number_bytes,
			nvm_lock
			);

	if (!err) {
		/*
		 * MAC addresses are stored in Little Endian form in hardware.
		 * We convert it to Big Endian in our buffer.
		 */
		for (i = 0; i < 6; ++i) {
			buffer[i] = temp_buffer[6 - 1 - i];
		}
	}

	return err;
}

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
	)
{
	unsigned long flags;

	spin_lock_irqsave(imask_lock, flags);

	sel_read_mod_write(
		&hw_mac->mac.imask,
		imask,
		0);

	/* flush */
	sel_write_flush(hw_mac);

	spin_unlock_irqrestore(imask_lock, flags);
}

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
	spinlock_t *imask_lock)
{
	unsigned long flags;

	spin_lock_irqsave(imask_lock, flags);

	sel_read_mod_write(
		&hw_mac->mac.imask,
		0,
		imask);

	/* flush */
	sel_write_flush(hw_mac);

	spin_unlock_irqrestore(imask_lock, flags);
}

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
	)
{
	u32 mac_1;
	u32 mac_2;

	if (size < 6) {
		return -EINVAL;
	}

	/* Clear the mac address register since we are changing the address */
	iowrite32(0, &hw_mac->mac.mac_stn_addr[1]);

	/* flush */
	ioread32(&hw_mac->reserved_1[0]);

	mac_1 = ((mac_address[5] << 24) |
		(mac_address[4] << 16) |
		(mac_address[3] << 8) |
		(mac_address[2] << 0));

	mac_2 = ((mac_address[1] << 24) |
		(mac_address[0] << 16));

	/* Set the mac valid bit now that we have a valid address */
	iowrite32(mac_1, &hw_mac->mac.mac_stn_addr[0]);
	iowrite32((mac_2 | MAC_STN_ADDR_MAC_VALID), &hw_mac->mac.mac_stn_addr[1]);

	/* flush */
	sel_write_flush(hw_mac);

	return 0;
}

/**
 * sel_hw_init() - Initialize a hardware mac
 *
 * @hw_mac:              MAC base address register
 * @base_rx_bd_dma_addr: base rxbd physical address
 * @base_tx_bd_dma_addr: base txbd physical address
 * @mac_address:         6-byte mac address
 * @mac_address_size:    size of input mac address (in bytes)
 *
 * Return: 0 if succesful, otherwise appropriate negative error value
 */
int sel_hw_init(
	struct sel3390e4_hw_mac *hw_mac,
	u64 base_rx_bd_dma_addr,
	u64 base_tx_bd_dma_addr,
	u8 *mac_address,
	u8 mac_address_size
	)
{
	/* Set the MAC addresses in hardware */
	sel_set_hw_mac_addr(hw_mac, mac_address, mac_address_size);

	if (mac_address == NULL) {
		return -ENOMEM;
	}

	/* Set base RXBD DMA address in hardware (64-bit address) */

	iowrite32(
		lower_32_bits(base_rx_bd_dma_addr),
		(__le32 *)&hw_mac->mac.rx_bd_base_addr);

	iowrite32(
		upper_32_bits(base_rx_bd_dma_addr),
		(__le32 *)&hw_mac->mac.rx_bd_base_addr + 1);

	/* Set base TXBD DMA address in hardware (64-bit address) */

	iowrite32(
		lower_32_bits(base_tx_bd_dma_addr),
		(__le32 *)&hw_mac->mac.tx_bd_base_addr);

	iowrite32(
		upper_32_bits(base_tx_bd_dma_addr),
		(__le32 *)&hw_mac->mac.tx_bd_base_addr + 1);

	/* Setup for frame transmission
	 * We always keep the transmitter on
	 */
	sel_read_mod_write(
		&hw_mac->mac.mac_config,
		MCCFG_TX_EN,
		0);

	/* Clear the graceful transmit stop bit */
	sel_read_mod_write(
		&hw_mac->mac.mac_config,
		0,
		MCCFG_GTS);

	return 0;
}

/**
 * sel_start_receiver() - Start the hardware receiver
 *
 * @hw_mac: MAC base address register
 */
void sel_start_receiver(struct sel3390e4_hw_mac *hw_mac)
{
	/* Clear QHLT which will start the receiver if it was stopped */
	sel_read_mod_write(
		&hw_mac->mac.rx_stat,
		RSTAT_QHLT,
		0);

	/* Enable the receiver */
	sel_read_mod_write(
		&hw_mac->mac.mac_config,
		MCCFG_RX_EN,
		0);

	/* flush */
	sel_write_flush(hw_mac);
}

/**
 * sel_stop_receiver() - Stop the hardware receiver
 *
 * @hw_mac: MAC base address register
 */
void sel_stop_receiver(struct sel3390e4_hw_mac *hw_mac)
{
	/* Stop the receiver */
	sel_read_mod_write(
		&hw_mac->mac.mac_config,
		0,
		MCCFG_RX_EN);

	/* flush */
	sel_write_flush(hw_mac);
}

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
	)
{
	u8 i;
	u8 hash_table_index;
	u32 group_address_bit;
	u32 group_address_reg;
	u32 group_address_values[NUM_GROUP_ADDR_REGS] = {0};
	u32 crc;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct dev_mc_list *hw_addr;
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
	struct dev_addr_list *hw_addr;
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)) */
	struct netdev_hw_addr *hw_addr;
#endif

	/* Set up the multicast list in hardware using a calculated CRC
	 * for each multicast address stored in the list
	 */
	netdev_for_each_mc_addr(hw_addr, netdev) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
		crc = crc32(0xFFFFFFFFu, hw_addr->dmi_addr, ETH_ALEN);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
		crc = crc32(0xFFFFFFFFu, hw_addr->da_addr, ETH_ALEN);
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)) */
		crc = crc32(0xFFFFFFFFu, hw_addr->addr, ETH_ALEN);
#endif
		crc = ~crc;

		/* Evaluate lower 8 bits */
		hash_table_index = (crc & 0xFFU);

		/* lower 5 bits represent bit number (0-31) */
		group_address_bit = (hash_table_index & 0x1FU);

		/* upper 3 bits represent register number (0-7) */
		group_address_reg = (hash_table_index >> 0x5U);

		/* Set bit in group address register */
		group_address_values[group_address_reg] |=
			(1 << group_address_bit);
	}

	/* write group addresses to HW */
	for (i = 0; i < NUM_GROUP_ADDR_REGS; i++) {
		iowrite32(
			group_address_values[i],
			&hw_mac->mac.group_addr[i]);
	}

	/* flush */
	sel_write_flush(hw_mac);
}

/**
 * sel_enable_promiscuous_mode() - Enable promiscuous mode
 *
 * @hw_mac: MAC base address register
 */
void sel_enable_promiscuous_mode(struct sel3390e4_hw_mac *hw_mac)
{
	sel_read_mod_write(&hw_mac->mac.rx_ctl, RX_CTRL_PROM, 0);
}

/**
 * sel_disable_promiscuous_mode() - Disable promiscuous mode
 *
 * @hw_mac: MAC base address register
 */
void sel_disable_promiscuous_mode(struct sel3390e4_hw_mac *hw_mac)
{
	sel_read_mod_write(&hw_mac->mac.rx_ctl, 0, RX_CTRL_PROM);
}

/**
 * sel_enable_multicast() - Enable all multicast addresses
 *
 * @hw_mac: MAC base address register
 */
void sel_enable_multicast(struct sel3390e4_hw_mac *hw_mac)
{
	u8 i;
	for (i = 0; i < NUM_GROUP_ADDR_REGS; i++) {
		iowrite32(~0U, &hw_mac->mac.group_addr[i]);
	}

	/* flush */
	sel_write_flush(hw_mac);
}

/**
 * sel_disable_multicast() - Disable all multicast addresses
 *
 * @hw_mac: MAC base address register
 */
void sel_disable_multicast(struct sel3390e4_hw_mac *hw_mac)
{
	u8 i;
	for (i = 0; i < NUM_GROUP_ADDR_REGS; i++) {
		iowrite32(0U, &hw_mac->mac.group_addr[i]);
	}

	/* flush */
	sel_write_flush(hw_mac);
}
