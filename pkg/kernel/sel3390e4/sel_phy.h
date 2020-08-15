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
 * PHY interface
 ******************************************************************************
 */

#ifndef SEL_PHY_H_INCLUDED
#define SEL_PHY_H_INCLUDED

#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>        /* types */

#include "sel3390e4_hw_regs.h"  /* hw register definitions */

/**
 * sel_phy_reset() - Reset the PHY to a known state
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 *
 * The PHY required settings are reset here as well.
 *
 * Return: 0 if successful, otherwise negative error code
 */
int sel_phy_reset(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);

/**
 * sel_phy_setup() - Set required settings in a PHY
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 *
 */
void sel_phy_setup(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);

/**
 * sel_phy_query_fiber_mode() - Query Fiber Mode
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 *
 * Return: > 0 if this is a fiber port, otherwise 0
 */
u8 sel_phy_query_fiber_mode(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);
	
/**
 * sel_phy_clear_rgmii_100base_fx_mode() - Clear RGMII-100Base-FX mode
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 */
void sel_phy_clear_rgmii_100base_fx_mode(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);

/**
 * sel_phy_set_rgmii_100base_fx_mode() - Set RGMII-100Base-FX mode
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 */
void sel_phy_set_rgmii_100base_fx_mode(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);

/**
 * sel_phy_power_down() - Power down a PHY
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 */
void sel_phy_power_down(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);

/**
 * sel_phy_power_up() - Power up a PHY
 *
 * @hw_mac:    MAC base address
 * @phy:       phy address
 * @mdio_lock: mii lock
 */
void sel_phy_power_up(
	struct sel3390e4_hw_mac *hw_mac,
	u8 phy,
	spinlock_t *mdio_lock
	);
	
#endif /* SEL_PHY_H_INCLUDED */

