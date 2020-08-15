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

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* kern-specific macros */

#include <linux/errno.h>       /* error codes */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

#include "sel_mii.h"           /* mii interface */
#include "sel_phy.h"           /* phy interface */
#include "sel3390e4.h"         /* 3390 definitions */
#include "sel3390e4_hw_regs.h" /* hw register definitions */
#include "sel3390e4_kcomp.h"   /* kernel compatability header */
#include "sel3390e4_mdio.h"    /* mdio interface */

/**
 * mii_if_read() - mii_if_info interface to read a PHY register
 *
 * @netdev: the net device object
 * @addr:   the phy address to read
 * @reg:    the register to read
 *
 * Return: the value read from the PHY
 */
static int mii_if_read(struct net_device *netdev, int addr, int reg)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	unsigned long flags;
	u16 data;

	spin_lock_irqsave(&mac->board->mdio_lock, flags);
	data = sel_mii_read(mac->hw_mac, (u8)addr, (u8)reg);
	spin_unlock_irqrestore(&mac->board->mdio_lock, flags);

	return data;
}

/**
 * mii_if_write() - mii_if_info interface to write a PHY register
 *
 * @netdev: the net device object
 * @addr:   the phy address to write
 * @reg:    the register to write
 * @val:    the data to write
 */
static void mii_if_write(struct net_device *netdev, int addr, int reg, int val)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	unsigned long flags;

	spin_lock_irqsave(&mac->board->mdio_lock, flags);
	sel_mii_write(mac->hw_mac, (u8)addr, (u8)reg, (u16)val);
	spin_unlock_irqrestore(&mac->board->mdio_lock, flags);
}

/**
 * sel3390e4_mdio_probe() - Setup the MII interface for all the net devices
 *
 * @board: pci device context
 *
 * This function can only be called after net device have been
 * allocated.
 */
void sel3390e4_mdio_probe(struct sel3390e4_board *board)
{
	int phy_addr;
	unsigned int i;

	for (i = 0; i < board->num_macs; i++) {
		phy_addr = SEL3390E4_PHY_ADDRS[i];

		/* Setup mii interface info */

		/* Set the PHY ID and PHY REG masks (both are 5 bits, thus
		 * both are 0x1F)
		 */
		board->macs[i]->mii_if.phy_id_mask = MII_REG_ADDR_MASK;
		board->macs[i]->mii_if.reg_num_mask = MII_REG_ADDR_MASK;

		/* Set the net device for this MII Interface */
		board->macs[i]->mii_if.dev = board->macs[i]->netdev;

		/* Set the read/write handlers */

		board->macs[i]->mii_if.mdio_read = mii_if_read;
		board->macs[i]->mii_if.mdio_write = mii_if_write;

		/* This is a Gigabit device, so it has gigabit registers */
		board->macs[i]->mii_if.supports_gmii = 1;

		/* Store the PHY address */
		board->macs[i]->mii_if.phy_id = phy_addr;

		/* We store whether this is a fiber/copper port since
		 * speed/duplex settings vary accordingly based off this.
		 */
		board->macs[i]->fiber_mode =
			sel_phy_query_fiber_mode(
				board->macs[i]->hw_mac,
				(u8)board->macs[i]->mii_if.phy_id,
				&board->mdio_lock);
	}
}


