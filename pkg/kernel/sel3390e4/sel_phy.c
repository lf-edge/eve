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

#include <linux/kernel.h>      /* kern-specific macros */

#include <asm/delay.h>         /* delays */
#include <asm/io.h>            /* iowrites */
#include <linux/delay.h>       /* delays */
#include <linux/errno.h>       /* error codes */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */

#include "sel_hw.h"            /* hw interface */
#include "sel_mii.h"           /* mii interface */
#include "sel_phy.h"           /* phy interface */
#include "sel3390e4_hw_regs.h" /* hw register definitions */

static u8 const SEL3390E4_RESET_WAIT_RETRIES = 8;

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
	)
{
	int err = 0;
	u8 timeout = 0;
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	sel_mii_read_mod_write(
		hw_mac,
		phy,
		PHY_CONTROL_REGISTER,
		CONTROL_REGISTER_SWRESET_MASK,
		0);

	while ((sel_mii_read(
			hw_mac,
			phy,
			PHY_CONTROL_REGISTER
			) & CONTROL_REGISTER_SWRESET_MASK) != 0) {

		if (timeout >= SEL3390E4_RESET_WAIT_RETRIES) {
			err = -EIO;
			break;
		}

		timeout++;

		udelay(10);
	};

	spin_unlock_irqrestore(mdio_lock, flags);

	return err;
}

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
	)
{
	u16 led_settings;
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	/* Enable out-of-band status */
	sel_mii_write_shadow_register(
		hw_mac,
		phy,
		BROADCOM_BASE_T_AUX_CONTROL_REGISTER,
		SHADOW_VALUE_BASE_T_MISC_CONTROL,
		MISC_CONTROL_REQUIRED_SETTINGS
		);

	/* Set required PHY CLK125 settings */
	sel_mii_write_shadow_register(
		hw_mac,
		phy,
		BROADCOM_BASE_T_SHADOW_REGISTER,
		SHADOW_VALUE_SPARE_CTRL_THREE,
		PHY_CLK_REQUIRED_SETTINGS
		);

	/* Set required SGMII settings */
	sel_mii_write_shadow_register(
		hw_mac,
		phy,
		BROADCOM_BASE_T_SHADOW_REGISTER,
		SHADOW_VALUE_SGMII_SLAVE,
		SGMII_SLAVE_REQUIRED_SETTINGS
		);

	spin_unlock_irqrestore(mdio_lock, flags);

	/* Set required LED settings */
	led_settings = sel_phy_query_fiber_mode(hw_mac, phy, mdio_lock) ?
		EXTERNAL_LED_ONE_FIBER_REQUIRED_SETTINGS:
		EXTERNAL_LED_ONE_COPPER_REQUIRED_SETTINGS;

	spin_lock_irqsave(mdio_lock, flags);

	sel_mii_write_shadow_register(
		hw_mac,
		phy,
		BROADCOM_BASE_T_SHADOW_REGISTER,
		SHADOW_VALUE_LED_SELECTOR_ONE,
		led_settings
		);

	/* We don't support 1Gbps Half Duplex, so don't advertise it */
	sel_mii_read_mod_write(
		hw_mac,
		phy,
		PHY_1000BASET_CONTROL_REGISTER,
		0,
		PHY_ADVERTISE_1000HALF);

	spin_unlock_irqrestore(mdio_lock, flags);
}

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
	)
{
	u8 data = 0;
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	data = sel_mii_read_shadow_register(
			hw_mac,
			phy,
			BROADCOM_BASE_T_SHADOW_REGISTER,
			SHADOW_VALUE_MODE_CONTROL);

	spin_unlock_irqrestore(mdio_lock, flags);

	/* Query whether this port is in copper or fiber mode
	 * This will never change as it is a hardware strapping
	 */
	return ((data & PHY_MODE_SELECT_MASK) == PHY_FIBER_MODE);
}

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
	)
{
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	/* 1. Clear 100Base-FX Mode */
	sel_mii_write_shadow_register(
		hw_mac,
		phy,
		BROADCOM_BASE_T_SHADOW_REGISTER,
		SHADOW_VALUE_100BASE_FX_CONTROL,
		0
		);

	spin_unlock_irqrestore(mdio_lock, flags);

	/* 2. Reset PHY */
	(void)sel_phy_reset(hw_mac, phy, mdio_lock);

	/* 3. Set PHY required settings */
	sel_phy_setup(hw_mac, phy, mdio_lock);
}

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
	)
{
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	/* The following steps are defined on page 75 of the
	 * Broadcom BCM5482SA2IFBG_0 specficiation
	 */

	/* 1. Place the device in RGMII-fiber mode
	 * This is done in hardware....
	 */

	/* 2. Set Loopback */

	sel_mii_write(
		hw_mac,
		phy,
		PHY_CONTROL_REGISTER,
		CONTROL_REGISTER_LOOPBACK_MASK);

	/* 3. Set 100Base-FX Mode */

	sel_mii_write_shadow_register(
		hw_mac,
		phy,
		BROADCOM_BASE_T_SHADOW_REGISTER,
		SHADOW_VALUE_100BASE_FX_CONTROL,
		PHY_ENABLE_100BASE_FX
		);

	/* 4. Pwr Down SerDes Rx Path */

	sel_mii_write_expansion_register(
		hw_mac,
		phy,
		BROADCOM_PHY_SERDES_CONTROL_REGISTER,
		0x0C3Bu /* defined in broadcom spec */
		);

	/* 5. Power-up and reset SerDes Rx Path */

	sel_mii_write_expansion_register(
		hw_mac,
		phy,
		BROADCOM_PHY_SERDES_CONTROL_REGISTER,
		0x0C3Au /* defined in broadcom spec */
		);

	/* 6. reset loopback to switch clock back to SerDes Rx clock */

	sel_mii_write(
		hw_mac,
		phy,
		PHY_CONTROL_REGISTER,
		0);

	spin_unlock_irqrestore(mdio_lock, flags);

	/* 7. Set LED settings */
	sel_phy_setup(hw_mac, phy, mdio_lock);
}

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
	)
{
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	sel_mii_read_mod_write(
		hw_mac,
		phy,
		PHY_CONTROL_REGISTER,
		CONTROL_REGISTER_PWRDWN_MASK,
		0);

	spin_unlock_irqrestore(mdio_lock, flags);
}

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
	)
{
	unsigned long flags;

	spin_lock_irqsave(mdio_lock, flags);

	sel_mii_read_mod_write(
		hw_mac,
		phy,
		PHY_CONTROL_REGISTER,
		0,
		CONTROL_REGISTER_PWRDWN_MASK);

	spin_unlock_irqrestore(mdio_lock, flags);
}

