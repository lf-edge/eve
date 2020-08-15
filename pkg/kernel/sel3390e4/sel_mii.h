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

#ifndef SEL_MII_H_INCLUDED
#define SEL_MII_H_INCLUDED

#include <linux/types.h>        /* types */

#include "sel3390e4_hw_regs.h"  /* hw register definitions */

/**
 * sel_mii_read() - Read data from a specific phy register
 *
 * @hw_mac: MAC base address
 * @phy:    the phy address to read from
 * @reg:    the register to write to
 *
 * This function requires the MII lock to be held.
 *
 * Return: the value read from the PHY
 */
u16 sel_mii_read(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	u8 reg
	);

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
	);

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
	);

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
	);

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
	);

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
	);
	
#endif /* SEL_MII_H_INCLUDED */
