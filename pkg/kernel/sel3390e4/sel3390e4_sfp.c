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
 * SFP interface
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* printk */

#include <linux/netdevice.h>   /* net device interface */

#include "sel_sfp.h"            /* sfp interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */
#include "sel3390e4_sfp.h"      /* sfp interfacace */

/**
 * sel3390e4_sfp_detect() - Detect, validate, and initialize an attached SFP
 *
 * @mac: net device context
 */
void sel3390e4_sfp_detect(struct sel3390e4_mac *mac)
{
	u8 sfp_connected;
	
	/* Only query for SFP connections if this is a fiber port */
	if (!mac->fiber_mode) {
		return;
	}
	
	sfp_connected =
		sel_sfp_detect(
			mac->hw_mac, 
			mac->mii_if.phy_id, 
			mac->netdev->dev_id, 
			&mac->sfp_part_number,
			&mac->board->sfp_lock,
			&mac->board->mdio_lock);

	if (sfp_connected != mac->sfp_connected) {
			mac->sfp_connected = sfp_connected;

			if (sfp_connected) {
				switch (mac->sfp_part_number) {
				case PART_NUM_100_BASE_FX:
				case PART_NUM_100_BASE_LX10:
					netdev_info(
						mac->netdev, 
						"100 Mbps SFP module connected.\n");
					break;

				case PART_NUM_1000_BASE_SX:
				case PART_NUM_1000_BASE_LX:
					netdev_info(
						mac->netdev, 
						"1000 Mbps SFP module connected.\n");
					break;

				default:
					BUG();
				}
			} else {
				netdev_info(mac->netdev, "SFP module disconnected.\n");
			}
	}
}

/**
 * sel3390e4_sfp_disable() - Disable an attached SFP
 *
 * @mac: net device context
 */
void sel3390e4_sfp_disable(struct sel3390e4_mac *mac)
{
	if (sel_sfp_disable(
		mac->hw_mac,
		mac->netdev->dev_id,
		&mac->board->sfp_lock)) {

		mac->sfp_connected = 0;

		netdev_info(mac->netdev, "SFP module disconnected.\n");
	}
}
