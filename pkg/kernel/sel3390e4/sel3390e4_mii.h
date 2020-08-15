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
 *****************************************************************************
 * MII Interface (This mimics this kernel's mii library mii.c)
 *
 * We use our own MII functions since SFP support requires us to
 * set specific speeds based on the SFP that is connected. These functions
 * are pretty much exactly the same as those found in the linux kernel's
 * standard mii.c.
 *****************************************************************************
 */

#ifndef SEL3390E4_MII_H_INCLUDED
#define SEL3390E4_MII_H_INCLUDED

#include <linux/ethtool.h> /* ethtool library */
#include <linux/mii.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
/**
 * sel3390e4_mii_ethtool_gksettings() - get settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ks: ethtool ksettings
 *
 * Return: 0 always.
 */
int sel3390e4_mii_ethtool_gksettings(struct mii_if_info *mii, struct ethtool_link_ksettings *ks);

/**
 * sel3390e4_mii_ethtool_sksettings() - set settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ks: ethtool ksettings
 *
 * Return: 0 for success, negative on error.
 */
int sel3390e4_mii_ethtool_sksettings(struct mii_if_info *mii, const struct ethtool_link_ksettings *ks);

#else
/**
 * sel3390e4_mii_ethtool_gset() - get settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ecmd: requested ethtool_cmd
 *
 * Return: 0 for success, negative on error.
 */
int sel3390e4_mii_ethtool_gset(struct mii_if_info *mii, struct ethtool_cmd *ecmd);

/**
 * sel3390e4_mii_ethtool_sset() - set settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ecmd: requested ethtool_cmd
 *
 * Return: 0 for success, negative on error.
 */
int sel3390e4_mii_ethtool_sset(struct mii_if_info *mii, struct ethtool_cmd *ecmd);
#endif

/**
 * mii_check_gmii_support() - check if the MII supports Gb interfaces
 *
 * @mii: the MII interface
 *
 * Return: 1 if gmii is supported, else 0.
 */
int sel3390e4_mii_check_gmii_support(struct mii_if_info *mii);

/**
 * mii_link_ok() - is link status up/ok
 *
 * @mii: the MII interface
 *
 * Return: 1 if the MII reports link status up/ok, 0 otherwise.
 */
int sel3390e4_mii_link_ok(struct mii_if_info *mii);

/**
 * mii_nway_restart() - restart NWay (autonegotiation) for this interface
 *
 * @mii: the MII interface
 *
 * Return: 0 on success, negative on error.
 */
int sel3390e4_mii_nway_restart(struct mii_if_info *mii);

/**
 * mii_check_link() - check MII link status
 *
 * @mii: MII interface
 *
 * If the link status changed (previous != current), calls
 * netif_carrier_on() if current link status is Up, or calls
 * netif_carrier_off() if current link status is Down.
 */
void sel3390e4_mii_check_link(struct mii_if_info *mii);

/**
 * sel3390e4_mii_generic_ioctl() - MII ioctl interface
 *
 * @mii_if:        the MII interface
 * @mii_data:      MII ioctl data
 * @cmd:           MII ioctl command
 * @duplex_chg_out: ptr to duplex changed status if no error
 *
 * Return: 0 on success, negative on error.
 */
int sel3390e4_mii_generic_ioctl(
	struct mii_if_info *mii_if,
	struct mii_ioctl_data *mii_data, 
	int cmd,
	unsigned int *duplex_chg_out
	);

#endif /* SEL3390E4_MII_H_INCLUDED */

