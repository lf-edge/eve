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
 * MII Interface
 ******************************************************************************
 */

#include <linux/kernel.h>      /* kern-specific info */

#include <asm/delay.h>         /* delays */
#include <asm/io.h>            /* iowrites */
#include <linux/delay.h>       /* delays */
#include <linux/errno.h>       /* error codes */
#include <linux/types.h>       /* types */

#include "sel_hw.h"            /* hw interface */
#include "sel_mii.h"           /* mii interface */
#include "sel3390e4_hw_regs.h" /* hw register definitions */

/**
 * sel_mii_wait_busy() - Wait for the MII bus to become available
 *
 * @hw_mac: MAC base address
 *
 * This function requires the MII lock to be held.
 */
static void sel_mii_wait_busy(struct sel3390e4_hw_mac *hw_mac)
{
	u32 mdio_ind = 0;

	/* Wait for device to become available */
	do {
		mdio_ind = ioread32(&hw_mac->mii_bus.ind);
		udelay(10);
	} while ((mdio_ind & MII_BUSY) != 0);
}

/**
 * sel_mii_read() - Read data from a specific phy register
 *
 * @hw_mac: MAC base address
 * @phy:    the phy address to read from
 * @reg:    the register to write to
 *
 *
 * This function requires the MII lock to be held.
 *
 * Return: the value read from the PHY
 */
u16 sel_mii_read(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 reg
	)
{
	u16 data = 0;
	u32 addr = 0;

	BUG_ON((phy & ~(0x1FU)) != 0);
	BUG_ON((reg & ~(0x1FU)) != 0);

	sel_mii_wait_busy(hw_mac);

	addr = (phy << MII_PHY_ADDR_OFFSET);
	addr |= reg;

	/* In current RTL, any of the MACs can control the MDIO bus.
	 * Thus, we can use any MAC. Here we always use MAC[0].
	 */

	/* Set the address we wish to read from */
	iowrite32(addr, &hw_mac->mii_bus.address);

	/* Setup read cycle */
	sel_read_mod_write(&hw_mac->mii_bus.comm, MII_READ_CYCLE, 0);

	/* Wait for the PHY to become available */
	sel_mii_wait_busy(hw_mac);

	/* Read the data returned */
	data = (u16)ioread32(&hw_mac->mii_bus.stat);

	/* Clear the read cycle */
	sel_read_mod_write(&hw_mac->mii_bus.comm, 0, MII_READ_CYCLE);

	/* flush */
	sel_write_flush(hw_mac);

	return data;
}

/**
 * sel_mii_write() - Write data to a specific phy register
 *
 * @hw_mac: MAC base address
 * @phy:    the phy address to write to
 * @reg:    the register to write to
 * @val:    the value to write
 *
 * This function requires the MII lock to be held.
 */
void sel_mii_write(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 reg,
	u16 val
	)
{
	u32 addr = 0;

	BUG_ON((phy & ~(0x1FU)) != 0);
	BUG_ON((reg & ~(0x1FU)) != 0);

	/* Wait for bus to become available */
	sel_mii_wait_busy(hw_mac);

	/* Perform write */

	addr = (phy << MII_PHY_ADDR_OFFSET);
	addr |= reg;
	iowrite32(addr, &hw_mac->mii_bus.address);
	iowrite32(val, &hw_mac->mii_bus.control);

	/* flush */
	sel_write_flush(hw_mac);
}

/**
 * sel_mii_read_mod_write() - Read/Modify/Write a PHY register
 *
 * @hw_mac:     MAC base address
 * @phy:        the phy address to modify
 * @reg:        the register to modify
 * @set_bits:   the bits to set in the register
 * @clear_bits: the bits to clear in the register
 *
 * This function requires the MII lock to be held.
 */
void sel_mii_read_mod_write(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 reg,
	u16 set_bits,
	u16 clear_bits
	)
{
	u32 addr = 0;
	u32 data = 0;

	BUG_ON((phy & ~(0x1FU)) != 0);
	BUG_ON((reg & ~(0x1FU)) != 0);

	sel_mii_wait_busy(hw_mac);

	/* Perform read and get data */

	addr = (phy << MII_PHY_ADDR_OFFSET);
	addr |= reg;

	iowrite32(addr, &hw_mac->mii_bus.address);

	sel_read_mod_write(&hw_mac->mii_bus.comm, MII_READ_CYCLE, 0); 

	sel_mii_wait_busy(hw_mac);

	data = ioread32(&hw_mac->mii_bus.stat);

	sel_read_mod_write(&hw_mac->mii_bus.comm, 0, MII_READ_CYCLE);

	/* Write the new data */

	data |= set_bits;
	data &= ~clear_bits;

	sel_mii_wait_busy(hw_mac);

	iowrite32(addr, &hw_mac->mii_bus.address);
	iowrite32(data, &hw_mac->mii_bus.control);

	/* flush */
	sel_write_flush(hw_mac);
}

/**
 * sel_mii_write_shadow_register() - Writes a shadow register
 *
 * @hw_mac:          MAC base address
 * @phy:             phy address
 * @shadow_register: the shadow register to access
 * @shadow_value:    the shadow value selection bits
 * @data:            the data to write to the register
 *
 * This function requires the MII lock to be held.
 */
void sel_mii_write_shadow_register(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 shadow_register,
	u16 shadow_value,
	u16 data
	)
{
	u16 data_to_write;

	/* set data to write to phy */
	data_to_write =
		(data | shadow_value | SHADOW_VALUE_GLOBAL_WRITE_BIT);

	/* Write the data to the register */
	sel_mii_write(
		hw_mac,
		phy,
		shadow_register,
		data_to_write);
}

/**
 * sel_mii_read_shadow_register() - Reads the specified shadow register
 *
 * @hw_mac:          MAC base address
 * @phy:             phy address
 * @shadow_register: the shadow register to access
 * @shadow_value:    the shadow value selection bits
 *
 *
 * This function requires the MII lock to be held.
 *
 * Return: the data read from the register
 */
u16 sel_mii_read_shadow_register(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 shadow_register,
	u16 shadow_value
	)
{
	u16 data;

	/* Write the shadow register to the PHY
	 * in order to retrieve the data for the register
	 */
	sel_mii_write(
		hw_mac,
		phy,
		shadow_register,
		shadow_value);

	/* Read the shadow register data */
	data =
		sel_mii_read(
			hw_mac,
			phy,
			shadow_register);

	/* data read must have the correct register bits set */
	BUG_ON((data & shadow_value) != shadow_value);

	return data;
}

/**
 * sel_mii_write_expansion_register() - write a PHY expansion register
 *
 * @hw_mac:             MAC base address
 * @phy:                phy address
 * @expansion_register: the PHY expansion register to access
 * @data:               the data to write to the register
 *
 * This function requires the MII lock to be held.
 */
void sel_mii_write_expansion_register(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 expansion_register,
	u16 data
	)
{
	/* Set the expansion register we wish to write to */
	sel_mii_write(
		hw_mac,
		phy,
		BROADCOM_EXPANSION_SECONDARY_SERDES_REGISTER,
		(PHY_EXPANSION_REGISTER_VALUE + expansion_register));

	/* Write the actual data */
	sel_mii_write(
		hw_mac,
		phy,
		BROADCOM_RESERVED_ONE_REGISTER,
		data);
}

