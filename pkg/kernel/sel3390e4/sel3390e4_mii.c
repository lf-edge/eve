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

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>       /* kern-specific macros */

#include <linux/ethtool.h>      /* ethtool library */
#include <linux/mii.h>          /* mii registers */
#include <linux/netdevice.h>    /* net_device library */
#include <linux/types.h>        /* types */

#include "sel3390e4.h"          /* sel3390e4 types */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */
#include "sel3390e4_mii.h"      /* mii library */

/**
 * mii_get_an() - read auto-negotiation state
 *
 * @mii:  MII interface
 * @addr: the address to read (MII_ADVERTISE or MII_LPA)
 *
 * Return: the advertised speed
 */
static u32 mii_get_an(struct mii_if_info *mii, u16 addr)
{
	u32 result = 0;
	int advert;

	advert = mii->mdio_read(mii->dev, mii->phy_id, addr);

	if (advert & LPA_LPACK) {
		result |= ADVERTISED_Autoneg;
	}

	if (advert & ADVERTISE_10HALF) {
		result |= ADVERTISED_10baseT_Half;
	}

	if (advert & ADVERTISE_10FULL) {
		result |= ADVERTISED_10baseT_Full;
	}

	if (advert & ADVERTISE_100HALF) {
		result |= ADVERTISED_100baseT_Half;
	}

	if (advert & ADVERTISE_100FULL) {
		result |= ADVERTISED_100baseT_Full;
	}

	if (advert & ADVERTISE_PAUSE_CAP) {
		result |= ADVERTISED_Pause;
	}

	if (advert & ADVERTISE_PAUSE_ASYM) {
		result |= ADVERTISED_Asym_Pause;
	}

	return result;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
/**
 * sel3390e4_mii_ethtool_gksettings() - get settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ks: ethtool ksettings
 *
 * Return: 0 always.
 */
int sel3390e4_mii_ethtool_gksettings(struct mii_if_info *mii, struct ethtool_link_ksettings *ks)
{
	struct net_device *dev = mii->dev;
	struct sel3390e4_mac *mac = netdev_priv(dev);
	u16 bmcr;
	u16 bmsr;
	u16 ctrl1000 = 0;
	u16 stat1000 = 0;
	u16 lpa = 0;
	u32 nego;
	unsigned long flags;
	u32 supported = 0;
	u32 advertising = 0;

	ks->base.autoneg = AUTONEG_DISABLE;
	ks->base.duplex = DUPLEX_UNKNOWN;
	ks->base.speed = SPEED_UNKNOWN;

	/* PHY and MAC are logically in the same package */
	ks->base.transceiver = XCVR_INTERNAL;

	ks->base.phy_address = mii->phy_id;
	advertising = (ADVERTISED_TP | ADVERTISED_MII);

	if (mac->fiber_mode) {
		/* Fiber Settings */
		ks->base.autoneg = AUTONEG_DISABLE;
		spin_lock_irqsave(&mac->board->sfp_lock, flags);

		if (mac->sfp_connected && sel3390e4_mii_link_ok(mii)) {
			supported |= SUPPORTED_FIBRE | SUPPORTED_MII;
			advertising |= ADVERTISED_FIBRE;

			ks->base.duplex = DUPLEX_FULL;

			switch (mac->sfp_part_number) {
			case PART_NUM_100_BASE_FX:
			case PART_NUM_100_BASE_LX10:
				ks->base.speed = SPEED_100;
				supported |= SUPPORTED_100baseT_Full;
				advertising |= ADVERTISED_100baseT_Full;
				break;

			case PART_NUM_1000_BASE_SX:
			case PART_NUM_1000_BASE_LX:
				ks->base.speed = SPEED_1000;
				supported |= SUPPORTED_1000baseT_Full;
				advertising |= ADVERTISED_1000baseT_Full;
				break;

			default:
				/* We shouldn't reach this point
				 * since all connected SFPs that are 'validated'
				 * should have part numbers we expect
				 */
				BUG();
				break;
			}
		}
		spin_unlock_irqrestore(&mac->board->sfp_lock, flags);
	}
	else {
		/* Copper Settings */
		supported |= SUPPORTED_TP |
		             SUPPORTED_MII |
		             SUPPORTED_Autoneg |
			     SUPPORTED_10baseT_Half |
			     SUPPORTED_10baseT_Full |
			     SUPPORTED_100baseT_Half |
			     SUPPORTED_100baseT_Full;

		if (mii->supports_gmii) {
			/* Half Duplex 1Gbps is NOT supported */
			supported |= SUPPORTED_1000baseT_Full;

			ctrl1000 = mii->mdio_read(dev, mii->phy_id, MII_CTRL1000);
			stat1000 = mii->mdio_read(dev, mii->phy_id, MII_STAT1000);
		}

		bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);

		if (!sel3390e4_mii_link_ok(mii)) {
			ks->base.autoneg = AUTONEG_DISABLE;
			ks->base.duplex = DUPLEX_UNKNOWN;
			ks->base.speed = SPEED_UNKNOWN;
		} 
		else if (bmcr & BMCR_ANENABLE) {
			/* auto-negotiated. Determine speed / duplex */
			advertising |= ADVERTISED_Autoneg;
			ks->base.autoneg = AUTONEG_ENABLE;

			/* Check own advertised speed/duplex */
			advertising |= mii_get_an(mii, MII_ADVERTISE);
			if (ctrl1000 & ADVERTISE_1000FULL) {
				advertising |= ADVERTISED_1000baseT_Full;
			}

			/* Check link partners advertised speed/duplex */
			bmsr = mii->mdio_read(dev, mii->phy_id, MII_BMSR);
			if (bmsr & BMSR_ANEGCOMPLETE) {
				lpa = mii_get_an(mii, MII_LPA);
			}

			if (stat1000 & LPA_1000FULL) {
				lpa |= ADVERTISED_1000baseT_Full;
			}

			nego = advertising & lpa;

			if (nego & (ADVERTISED_1000baseT_Full |
				ADVERTISED_1000baseT_Half)) {
				ks->base.speed = SPEED_1000;
				ks->base.duplex = !!(nego & ADVERTISED_1000baseT_Full);
			} else if (nego & (ADVERTISED_100baseT_Full |
				ADVERTISED_100baseT_Half)) {
				ks->base.speed = SPEED_100;
				ks->base.duplex = !!(nego & ADVERTISED_100baseT_Full);
			} else {
				ks->base.speed = SPEED_10;
				ks->base.duplex = !!(nego & ADVERTISED_10baseT_Full);
			}
		}
		else {
			/* Not auto-negotiated */
			ks->base.autoneg = AUTONEG_DISABLE;

			ks->base.speed  =
				((bmcr & BMCR_SPEED1000) && (bmcr & BMCR_SPEED100) == 0) ?
				SPEED_1000 :
				((bmcr & BMCR_SPEED100) ? SPEED_100 : SPEED_10);
			ks->base.duplex = (bmcr & BMCR_FULLDPLX) ? DUPLEX_FULL : DUPLEX_HALF;
		}
	}

	ethtool_convert_legacy_u32_to_link_mode(ks->link_modes.supported,
					supported);
	ethtool_convert_legacy_u32_to_link_mode(ks->link_modes.advertising,
					advertising);

	mii->full_duplex = ks->base.duplex;

	/* ignore maxtxpkt, maxrxpkt for now */

	return 0;
}

/**
 * sel3390e4_mii_ethtool_sksettings() - set settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ks: ethtool ksettings
 *
 * Return: 0 for success, negative on error.
 */
int sel3390e4_mii_ethtool_sksettings(struct mii_if_info *mii, const struct ethtool_link_ksettings *ks)
{
	struct net_device *dev = mii->dev;
	struct sel3390e4_mac *mac = netdev_priv(dev);
	int err = 0;

	if (mac->fiber_mode) {
		/* Not allowed to set anything if this is a fiber port */
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ks->base.speed != SPEED_10) &&
		(ks->base.speed != SPEED_100) &&
		(ks->base.speed != SPEED_1000)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ks->base.duplex != DUPLEX_HALF) && (ks->base.duplex != DUPLEX_FULL)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ks->base.speed == SPEED_1000) && (ks->base.duplex == DUPLEX_HALF)) {
		/* 1Gbps Half Duplex is NOT supported */
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ks->base.port != PORT_MII) && (ks->base.port != PORT_TP)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if (ks->base.transceiver != XCVR_INTERNAL) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if (ks->base.phy_address != mii->phy_id) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ks->base.autoneg != AUTONEG_DISABLE) &&
		(ks->base.autoneg != AUTONEG_ENABLE)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ks->base.speed == SPEED_1000) && (!mii->supports_gmii)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	/* ignore supported, maxtxpkt, maxrxpkt */

	if (ks->base.autoneg == AUTONEG_ENABLE) {
		u32 requested_advertising;
		u32 bmcr;
		u32 advert;
		u32 tmp;
		u32 advert2 = 0;
		u32 tmp2 = 0;

		ethtool_convert_link_mode_to_legacy_u32(&requested_advertising,
						ks->link_modes.advertising);

		if ((requested_advertising &
			(ADVERTISED_10baseT_Half  |
			ADVERTISED_10baseT_Full   |
			ADVERTISED_100baseT_Half  |
			ADVERTISED_100baseT_Full  |
			ADVERTISED_1000baseT_Full)) == 0) {
			/* we support advertisement of 10/100/1000 Full/Half Duplex.
			 * However, we don't support 1Gbps Half Duplex, so if that's
			 * the only one requested, we error out. Otherwise, it's masked
			 * away below.
			 */
			err = -EINVAL;
			goto err_invalid_input;
		}

		/* advertise only what has been requested */
		advert = mii->mdio_read(dev, mii->phy_id, MII_ADVERTISE);
		tmp = (advert & ~(ADVERTISE_ALL | ADVERTISE_100BASE4));
		if (mii->supports_gmii) {
			advert2 = mii->mdio_read(dev, mii->phy_id, MII_CTRL1000);
			tmp2 = advert2 & ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);
		}

		if (requested_advertising & ADVERTISED_10baseT_Half) {
			tmp |= ADVERTISE_10HALF;
		}

		if (requested_advertising & ADVERTISED_10baseT_Full) {
			tmp |= ADVERTISE_10FULL;
		}

		if (requested_advertising & ADVERTISED_100baseT_Half) {
			tmp |= ADVERTISE_100HALF;
		}

		if (requested_advertising & ADVERTISED_100baseT_Full) {
			tmp |= ADVERTISE_100FULL;
		}

		if (mii->supports_gmii) {
			/* we only support 1Gbps FULL duplex */
			if (requested_advertising & ADVERTISED_1000baseT_Full) {
				tmp2 |= ADVERTISE_1000FULL;
			}
		}

		if (advert != tmp) {
			mii->mdio_write(dev, mii->phy_id, MII_ADVERTISE, tmp);
			mii->advertising = tmp;
		}

		if ((mii->supports_gmii) && (advert2 != tmp2)) {
			mii->mdio_write(dev, mii->phy_id, MII_CTRL1000, tmp2);
		}

		/* turn on auto negotiation, and force a renegotiate */
		bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);
		bmcr |= (BMCR_ANENABLE | BMCR_ANRESTART);
		mii->mdio_write(dev, mii->phy_id, MII_BMCR, bmcr);

		mii->force_media = 0;
	} else {
		u32 bmcr;
		u32 tmp;

		/* turn off auto negotiation, set speed and duplex */
		bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);
		tmp = (bmcr & ~(BMCR_ANENABLE | BMCR_SPEED100 |
			BMCR_SPEED1000 | BMCR_FULLDPLX));

		if (ks->base.speed == SPEED_1000) {
			tmp |= BMCR_SPEED1000;
		} else if (ks->base.speed == SPEED_100) {
			tmp |= BMCR_SPEED100;
		}

		if (ks->base.duplex == DUPLEX_FULL) {
			tmp |= BMCR_FULLDPLX;
			mii->full_duplex = 1;
		} else {
			mii->full_duplex = 0;
		}

		if (bmcr != tmp) {
			mii->mdio_write(dev, mii->phy_id, MII_BMCR, tmp);
		}

		mii->force_media = 1;
	}

err_invalid_input:

	return err;
}
#endif

/**
 * sel3390e4_mii_ethtool_gset() - get settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ecmd: requested ethtool_cmd
 *
 * Return: 0 always.
 */
int sel3390e4_mii_ethtool_gset(struct mii_if_info *mii, struct ethtool_cmd *ecmd)
{
	struct net_device *dev = mii->dev;
	struct sel3390e4_mac *mac = netdev_priv(dev);
	u16 bmcr;
	u16 bmsr;
	u16 ctrl1000 = 0;
	u16 stat1000 = 0;
	u16 lpa;
	u32 nego;
	unsigned long flags;

	ecmd->supported =
		(SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
		SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full |
		SUPPORTED_Autoneg | SUPPORTED_TP | SUPPORTED_MII);

	if (mii->supports_gmii) {
		/* 1Gbps Half Duplex is NOT supported */
		ecmd->supported |= SUPPORTED_1000baseT_Full;
	}

	/* only supports twisted-pair */
	ecmd->port = PORT_MII;

	/* only supports internal transceiver */
	ecmd->transceiver = XCVR_INTERNAL;

	/* set the phy address of this MAC */
	ecmd->phy_address = mii->phy_id;

	ecmd->advertising = (ADVERTISED_TP | ADVERTISED_MII);

	if (mac->fiber_mode) {
		/* This is a fiber port, thus settings are static */

		spin_lock_irqsave(&mac->board->sfp_lock, flags);

		if (mac->sfp_connected && sel3390e4_mii_link_ok(mii)) {
			ecmd->duplex = DUPLEX_FULL;

			switch (mac->sfp_part_number) {
			case PART_NUM_100_BASE_FX:
			case PART_NUM_100_BASE_LX10:

				ecmd->supported =
					(SUPPORTED_100baseT_Full |
					SUPPORTED_TP | SUPPORTED_MII);

				ecmd->speed = SPEED_100;
				ecmd->advertising |= ADVERTISED_100baseT_Full;
				break;

			case PART_NUM_1000_BASE_SX:
			case PART_NUM_1000_BASE_LX:

				ecmd->supported =
					(SUPPORTED_1000baseT_Full |
					SUPPORTED_TP | SUPPORTED_MII);

				ecmd->speed = SPEED_1000;
				ecmd->advertising |= ADVERTISED_1000baseT_Full;
				break;

			default:

				/* We shouldn't reach this point
				 * since all connected SFPs that are 'validated'
				 * should have part numbers we expect
				 */
				BUG();
				break;
			}
		} else {
			ecmd->duplex = DUPLEX_UNKNOWN;
			ecmd->speed = SPEED_UNKNOWN;
		}

		spin_unlock_irqrestore(&mac->board->sfp_lock, flags);

		ecmd->autoneg = AUTONEG_DISABLE;
		mii->full_duplex = ecmd->duplex;
		return 0;
	}

	/* This is a copper port */

	bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);
	bmsr = mii->mdio_read(dev, mii->phy_id, MII_BMSR);

	if (!sel3390e4_mii_link_ok(mii)) {
		ecmd->speed = SPEED_UNKNOWN;
		ecmd->duplex = DUPLEX_UNKNOWN;
	} else if (bmcr & BMCR_ANENABLE) {
		ecmd->advertising |= ADVERTISED_Autoneg;
		ecmd->autoneg = AUTONEG_ENABLE;

		ecmd->advertising |= mii_get_an(mii, MII_ADVERTISE);

		if (mii->supports_gmii) {
			ctrl1000 = mii->mdio_read(dev, mii->phy_id, MII_CTRL1000);
			stat1000 = mii->mdio_read(dev, mii->phy_id, MII_STAT1000);
		}

		if (ctrl1000 & ADVERTISE_1000HALF) {
			ecmd->advertising |= ADVERTISED_1000baseT_Half;
		}

		if (ctrl1000 & ADVERTISE_1000FULL) {
			ecmd->advertising |= ADVERTISED_1000baseT_Full;
		}

		if (bmsr & BMSR_ANEGCOMPLETE) {
			lpa = mii_get_an(mii, MII_LPA);

			if (stat1000 & LPA_1000HALF) {
				lpa |= ADVERTISED_1000baseT_Half;
			}

			if (stat1000 & LPA_1000FULL) {
				lpa |= ADVERTISED_1000baseT_Full;
			}
		} else {
			lpa = 0;
		}

		nego = ecmd->advertising & lpa;

		if (nego & (ADVERTISED_1000baseT_Full |
			ADVERTISED_1000baseT_Half)) {
			ecmd->speed = SPEED_1000;
			ecmd->duplex = !!(nego & ADVERTISED_1000baseT_Full);
		} else if (nego & (ADVERTISED_100baseT_Full |
			ADVERTISED_100baseT_Half)) {
			ecmd->speed = SPEED_100;
			ecmd->duplex = !!(nego & ADVERTISED_100baseT_Full);
		} else {
			ecmd->speed = SPEED_10;
			ecmd->duplex = !!(nego & ADVERTISED_10baseT_Full);
		}
	} else {
		ecmd->autoneg = AUTONEG_DISABLE;

		ecmd->speed =
			((bmcr & BMCR_SPEED1000) && (bmcr & BMCR_SPEED100) == 0) ?
			SPEED_1000 :
			((bmcr & BMCR_SPEED100) ? SPEED_100 : SPEED_10);
		ecmd->duplex = (bmcr & BMCR_FULLDPLX) ? DUPLEX_FULL : DUPLEX_HALF;
	}

	mii->full_duplex = ecmd->duplex;

	/* ignore maxtxpkt, maxrxpkt for now */

	return 0;
}

/**
 * sel3390e4_mii_ethtool_sset() - set settings that are specified in @ecmd
 *
 * @mii:  MII interface
 * @ecmd: requested ethtool_cmd
 *
 * Return: 0 for success, negative on error.
 */
int sel3390e4_mii_ethtool_sset(struct mii_if_info *mii, struct ethtool_cmd *ecmd)
{
	struct net_device *dev = mii->dev;
	struct sel3390e4_mac *mac = netdev_priv(dev);
	int err = 0;

	if (mac->fiber_mode) {
		/* Not allowed to set anything if this is a fiber port */
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ecmd->speed != SPEED_10) &&
		(ecmd->speed != SPEED_100) &&
		(ecmd->speed != SPEED_1000)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ecmd->duplex != DUPLEX_HALF) && (ecmd->duplex != DUPLEX_FULL)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ecmd->speed == SPEED_1000) && (ecmd->duplex == DUPLEX_HALF)) {
		/* 1Gbps Half Duplex is NOT supported */
		err = -EINVAL;
		goto err_invalid_input;
	}

	if (ecmd->port != PORT_MII) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if (ecmd->transceiver != XCVR_INTERNAL) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if (ecmd->phy_address != mii->phy_id) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ecmd->autoneg != AUTONEG_DISABLE) &&
		(ecmd->autoneg != AUTONEG_ENABLE)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	if ((ecmd->speed == SPEED_1000) && (!mii->supports_gmii)) {
		err = -EINVAL;
		goto err_invalid_input;
	}

	/* ignore supported, maxtxpkt, maxrxpkt */

	if (ecmd->autoneg == AUTONEG_ENABLE) {
		u32 bmcr;
		u32 advert;
		u32 advert_new;
		u32 advert2 = 0;
		u32 advert2_new = 0;

		if ((ecmd->advertising &
			(ADVERTISED_10baseT_Half  |
			ADVERTISED_10baseT_Full   |
			ADVERTISED_100baseT_Half  |
			ADVERTISED_100baseT_Full  |
			ADVERTISED_1000baseT_Full)) == 0) {
			/* we support advertisement of 10/100/1000 Full/Half Duplex.
			 * However, we don't support 1Gbps Half Duplex, so if that's
			 * the only one requested, we error out. Otherwise, it's masked
			 * away below.
			 */
			err = -EINVAL;
			goto err_invalid_input;
		}

		/* advertise only what has been requested */
		advert = mii->mdio_read(dev, mii->phy_id, MII_ADVERTISE);
		advert_new = (advert & ~(ADVERTISE_ALL | ADVERTISE_100BASE4));
		if (mii->supports_gmii) {
			advert2 =
				mii->mdio_read(dev, mii->phy_id, MII_CTRL1000);
			advert2_new =
				(advert2 & ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL));
		}

		if (ecmd->advertising & ADVERTISED_10baseT_Half) {
			advert_new |= ADVERTISE_10HALF;
		}

		if (ecmd->advertising & ADVERTISED_10baseT_Full) {
			advert_new |= ADVERTISE_10FULL;
		}

		if (ecmd->advertising & ADVERTISED_100baseT_Half) {
			advert_new |= ADVERTISE_100HALF;
		}

		if (ecmd->advertising & ADVERTISED_100baseT_Full) {
			advert_new |= ADVERTISE_100FULL;
		}

		if (mii->supports_gmii) {
			/* we only support 1Gbps FULL duplex */
			if (ecmd->advertising & ADVERTISED_1000baseT_Full) {
				advert2_new |= ADVERTISE_1000FULL;
			}
		}

		if (advert != advert_new) {
			mii->mdio_write(dev, mii->phy_id, MII_ADVERTISE, advert_new);
			mii->advertising = advert_new;
		}

		if ((mii->supports_gmii) && (advert2 != advert2_new)) {
			mii->mdio_write(dev, mii->phy_id, MII_CTRL1000, advert2_new);
		}

		/* turn on autonegotiation, and force a renegotiate */
		bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);
		bmcr |= (BMCR_ANENABLE | BMCR_ANRESTART);
		mii->mdio_write(dev, mii->phy_id, MII_BMCR, bmcr);

		mii->force_media = 0;
	} else {
		u32 bmcr;
		u32 advert_new;

		/* turn off auto negotiation, set speed and duplexity */
		bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);
		advert_new = (bmcr & ~(BMCR_ANENABLE | BMCR_SPEED100 |
			BMCR_SPEED1000 | BMCR_FULLDPLX));

		if (ecmd->speed == SPEED_1000) {
			advert_new |= BMCR_SPEED1000;
		} else if (ecmd->speed == SPEED_100) {
			advert_new |= BMCR_SPEED100;
		}

		if (ecmd->duplex == DUPLEX_FULL) {
			advert_new |= BMCR_FULLDPLX;
			mii->full_duplex = 1;
		} else {
			mii->full_duplex = 0;
		}

		if (bmcr != advert_new) {
			mii->mdio_write(dev, mii->phy_id, MII_BMCR, advert_new);
		}

		mii->force_media = 1;
	}

err_invalid_input:

	return err;
}

/**
 * mii_check_gmii_support() - check if the MII supports Gb interfaces
 *
 * @mii: the MII interface
 *
 * Return: 1 if gmii is supported, else 0.
 */
int sel3390e4_mii_check_gmii_support(struct mii_if_info *mii)
{
	int reg;

	reg = mii->mdio_read(mii->dev, mii->phy_id, MII_BMSR);

	if (reg & BMSR_ESTATEN) {
		/* The PHY supports extended status, so query for the 1Gbps
		 * status.
		 */
		reg = mii->mdio_read(mii->dev, mii->phy_id, MII_ESTATUS);

		if (reg & (ESTATUS_1000_TFULL | ESTATUS_1000_THALF)) {
			return 1;
		}
	}

	return 0;
}

/**
 * sel3390e4_mii_link_ok() - is link status up/ok
 *
 * @mii: the MII interface
 *
 * Return: 1 if the MII reports link status up/ok, 0 otherwise.
 */
int sel3390e4_mii_link_ok(struct mii_if_info *mii)
{
	/* first, a dummy read, needed to latch some MII phys */
	mii->mdio_read(mii->dev, mii->phy_id, MII_BMSR);

	if (mii->mdio_read(mii->dev, mii->phy_id, MII_BMSR) & BMSR_LSTATUS) {
		return 1;
	}

	return 0;
}

/**
 * mii_nway_restart() - restart NWay (autonegotiation) for this interface
 *
 * @mii: the MII interface
 *
 * Return: 0 on success, negative on error.
 */
int sel3390e4_mii_nway_restart(struct mii_if_info *mii)
{
	int bmcr;
	int err = -EINVAL;

	/* if autoneg is off, it's an error */
	bmcr = mii->mdio_read(mii->dev, mii->phy_id, MII_BMCR);

	if (bmcr & BMCR_ANENABLE) {
		bmcr |= BMCR_ANRESTART;
		mii->mdio_write(mii->dev, mii->phy_id, MII_BMCR, bmcr);
		err = 0;
	}

	return err;
}

/**
 * mii_check_link() - check MII link status
 *
 * @mii: MII interface
 *
 * If the link status changed (previous != current), calls
 * netif_carrier_on() if current link status is Up, or calls
 * netif_carrier_off() if current link status is Down.
 */
void sel3390e4_mii_check_link(struct mii_if_info *mii)
{
	int cur_link = sel3390e4_mii_link_ok(mii);
	int prev_link = netif_carrier_ok(mii->dev);
	struct ethtool_cmd cmd = { .cmd = ETHTOOL_GSET };
	u32 speed;

	if (cur_link && !prev_link) {
		sel3390e4_mii_ethtool_gset(mii, &cmd);
		speed = ethtool_cmd_speed(&cmd);

		netdev_info(
			mii->dev,
			"Link is Up: %u Mbps %s Duplex\n",
			(speed == SPEED_1000 ?
				1000 :
				(speed == SPEED_100 ?
				100 : 10)),
			(cmd.duplex == DUPLEX_FULL) ?
			"Full" : "Half");

		netif_carrier_on(mii->dev);
	} else if (prev_link && !cur_link) {
		netdev_info(mii->dev, "Link is Down\n");
		netif_carrier_off(mii->dev);
	}
}

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
	)
{
	int err = 0;
	unsigned int duplex_changed = 0;

	if (duplex_chg_out) {
		*duplex_chg_out = 0;
	}

	mii_data->phy_id &= mii_if->phy_id_mask;
	mii_data->reg_num &= mii_if->reg_num_mask;

	switch(cmd) {
	case SIOCGMIIPHY:
		mii_data->phy_id = mii_if->phy_id;
		/* fall through */

	case SIOCGMIIREG:
		mii_data->val_out =
			mii_if->mdio_read(
				mii_if->dev,
				mii_data->phy_id,
				mii_data->reg_num
				);
		break;

	case SIOCSMIIREG: {
		u16 val = mii_data->val_in;

		if (mii_data->phy_id == mii_if->phy_id) {
			switch(mii_data->reg_num) {

			case MII_BMCR: {
				unsigned int new_duplex = 0;
				if (val & (BMCR_RESET|BMCR_ANENABLE)) {
					mii_if->force_media = 0;
				} else {
					mii_if->force_media = 1;
				}

				if (mii_if->force_media && (val & BMCR_FULLDPLX)) {
					new_duplex = 1;
				}

				if (mii_if->full_duplex != new_duplex) {
					duplex_changed = 1;
					mii_if->full_duplex = new_duplex;
				}

				break;
			}

			case MII_ADVERTISE:
				mii_if->advertising = val;
				break;

			default:
				break;
			}
		}

		mii_if->mdio_write(
			mii_if->dev,
			mii_data->phy_id,
			mii_data->reg_num,
			val);

		break;
	}

	default:
		err = -EOPNOTSUPP;
		break;
	}

	if (!err && (duplex_chg_out != NULL) && duplex_changed) {
		*duplex_chg_out = 1;
	}

	return err;
}

