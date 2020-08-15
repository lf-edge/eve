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

#ifndef SEL_SFP_H_INCLUDED
#define SEL_SFP_H_INCLUDED

#include <linux/spinlock.h>     /* spin locks */
#include <linux/types.h>        /* types */

#include "sel3390e4_hw_regs.h"  /* hw register definitions */

/**
 * sel_sfp_disable() - Disable an attached SFP
 *
 * @hw_mac:   MAC base address
 * @port_num: port number
 * @sfp_lock: sfp spin lock
 *
 * Return: 1 if an SFP was disabled, otherwise 0.
 */
u8 sel_sfp_disable(
	struct sel3390e4_hw_mac *hw_mac,
	u8 port_num,
	spinlock_t *sfp_lock);

/**
 * sel_sfp_detect() - Detect, validate, and initialize an attached SFP
 *
 * @hw_mac:          MAC base address
 * @phy:             PHY address for this port
 * @port_num:        port number
 * @sfp_part_number: part number of connected/validated SFP
 * @sfp_lock:        sfp spin lock
 * @mdio_lock:       mii lock
 *
 * Return: 1 if SFP is connected/validated/enabled, otherwise 0.
 */
u8 sel_sfp_detect(
	struct sel3390e4_hw_mac *hw_mac, 
	u8 phy, 
	u8 port_num, 
	u32 *sfp_part_number,
	spinlock_t *sfp_lock,
	spinlock_t *mdio_lock);
	
#endif /* SEL_SFP_H_INCLUDED */

