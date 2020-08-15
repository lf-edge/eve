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

#include <linux/kernel.h>      /* kern-specific macros */

#include <asm/delay.h>         /* delays */
#include <asm/io.h>            /* iowrites */
#include <linux/delay.h>       /* delays */
#include <linux/errno.h>       /* error codes */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */

#include "sel_hw.h"            /* hw interface */
#include "sel_phy.h"           /* phy interface */
#include "sel_sfp.h"           /* sfp interface */
#include "sel3390e4_hw_regs.h" /* hw register definitions */

/* SFP Validation Retries */
static u8 const SEL3390E4_SFP_VALIDATION_RETRIES = 8;

/* This is the override sfp part number. Configurable via
 * sysfs. This is a globally configurable value.
 */
u32 BYPASS_SFP_PART_NUM = 0;

/**
 * sel_sfp_read_data_update() - Update SFP Read Data
 *
 * @hw_mac: MAC base address
 */
static int sel_sfp_read_data_update(struct sel3390e4_hw_mac *hw_mac)
{
	u8 retries = 0;
	u32 sfp_data = 0;
	int err = 0;

	/* Update SFP read data */
	iowrite32(
		SFP_VALID_DATA,
		&hw_mac->sfp_mgmt.read_control);

	/* Wait for read to complete */
	do {
		if (retries >= SEL3390E4_SFP_VALIDATION_RETRIES) {
			err = -EIO;
			break;
		}

		/* It was tested to show that read updates take almost
		 * 200ms, thus we delay for half of that here and retry
		 * if it has not completed.
		 */
#ifdef __VMKLNX__
		udelay(100000);
#else
		mdelay(100);
#endif

		sfp_data = ioread32(&hw_mac->sfp_mgmt.read_control);
		retries++;
	} while (sfp_data == SFP_VALID_DATA);

	return err;
}

/**
 * sel_sfp_info() - Retrieve the address to a hardware SFP info block
 *
 * @hw_mac:   MAC base address
 * @port_num: port number
 *
 * Return: a ptr to hardware SFP information
 */
static struct sfp_info *sel_sfp_info(
	struct sel3390e4_hw_mac *hw_mac, 
	u8 port_num
	)
{
	struct sfp_info *retval = NULL;

	switch (port_num) {
	case 0:
		retval = &hw_mac->sfp_mgmt.sfp_0;
		break;

	case 1:
		retval = &hw_mac->sfp_mgmt.sfp_1;
		break;

	case 2:
		retval = &hw_mac->sfp_mgmt.sfp_2;
		break;

	case 3:
		retval = &hw_mac->sfp_mgmt.sfp_3;
		break;

	default:
		BUG();
	}

	return retval;
}

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
	spinlock_t *sfp_lock
	)
{
	u32 sfp_data = 0;
	u32 sfp_enable_bit = 0;
	u8 sfp_disabled = 0;
	unsigned long flags;

	/* Get port-specific registers */
	switch (port_num) {
	case 0:
		sfp_enable_bit = SFP_1_ENABLE;
		break;

	case 1:
		sfp_enable_bit = SFP_2_ENABLE;
		break;

	case 2:
		sfp_enable_bit = SFP_3_ENABLE;
		break;

	case 3:
		sfp_enable_bit = SFP_4_ENABLE;
		break;

	default:
		/* WE SHOULD NEVER REACH THIS POINT
		 * Unless we make a device with > 4 ports
		 */
		BUG();
	}

	spin_lock_irqsave(sfp_lock, flags);

	sfp_data = ioread32(&hw_mac->sfp_mgmt.status_control);
	
	if ((sfp_data & sfp_enable_bit) != 0) {
		/* Disable SFP */
		iowrite32(
			sfp_data & ~sfp_enable_bit,
			&hw_mac->sfp_mgmt.status_control);

		sfp_disabled = 1;
	}

	spin_unlock_irqrestore(sfp_lock, flags);

	return sfp_disabled;
}

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
	spinlock_t *mdio_lock
	)
{
	u8 validation_retries = 0;
	u32 sfp_data = 0;
	u8 sfp_connected = 0;
	u32 auth_done_bit = 0;
	u32 auth_result_bit = 0;
	u32 sfp_detect_bit = 0;
	u32 sfp_enable_bit = 0;
	u32 sfp_override_part_num = BYPASS_SFP_PART_NUM;
	unsigned long flags;

	spin_lock_irqsave(sfp_lock, flags);

	/* Get port-specific registers */
	switch (port_num) {
	case 0:
		auth_done_bit = SFP_1_AUTH_DONE;
		auth_result_bit = SFP_1_AUTH_RESULT;
		sfp_detect_bit = SFP_1_DETECT;
		sfp_enable_bit = SFP_1_ENABLE;
		break;

	case 1:
		auth_done_bit = SFP_2_AUTH_DONE;
		auth_result_bit = SFP_2_AUTH_RESULT;
		sfp_detect_bit = SFP_2_DETECT;
		sfp_enable_bit = SFP_2_ENABLE;
		break;

	case 2:
		auth_done_bit = SFP_3_AUTH_DONE;
		auth_result_bit = SFP_3_AUTH_RESULT;
		sfp_detect_bit = SFP_3_DETECT;
		sfp_enable_bit = SFP_3_ENABLE;
		break;

	case 3:
		auth_done_bit = SFP_4_AUTH_DONE;
		auth_result_bit = SFP_4_AUTH_RESULT;
		sfp_detect_bit = SFP_4_DETECT;
		sfp_enable_bit = SFP_4_ENABLE;
		break;

	default:
		/* WE SHOULD NEVER REACH THIS POINT
		 * Unless we make a device with > 4 ports
		 */
		BUG();
	}

	sfp_data = ioread32(&hw_mac->sfp_mgmt.status_control);

	if ((sfp_data & sfp_detect_bit) != sfp_detect_bit) {
		/* SFP not detected on this port */

		if ((sfp_data & sfp_enable_bit) != 0) {

			/* Disable SFP */
			iowrite32(
				sfp_data & ~sfp_enable_bit,
				&hw_mac->sfp_mgmt.status_control);

			sel_phy_clear_rgmii_100base_fx_mode(hw_mac, phy, mdio_lock);
		}

		*sfp_part_number = 0;
	} else { /* SFP Detected */

		/* Update SFP read data */
		if (sel_sfp_read_data_update(hw_mac)) {
			goto err_validation;
		}

		/* We report it as connected here since it may have already been
		 * connected and we won't have to do any validation.
		 */
		sfp_connected = 1;

		/* Store part number */

		if (sfp_override_part_num != 0) {
			*sfp_part_number = sfp_override_part_num;
		} else {
			*sfp_part_number =
				ioread32(&(sel_sfp_info(hw_mac, port_num)->sel_part_number));
		}

		if ((ioread32(&hw_mac->sfp_mgmt.status_control) & sfp_enable_bit) == 0) {
			/* An SFP wasn't already connected... */

			/* Until the SFP has passed validation, we'll report it
			 * as not connected.
			 */
			sfp_connected = 0;

			/* Ignore validation, and assume the sfp successfully
			 * authenticated if we are overriding SFP validation. */
			if (sfp_override_part_num != 0) {
				sfp_data |= auth_result_bit;
			} else {
				/* Wait for authentication to finish */
				while (((sfp_data & auth_done_bit) != auth_done_bit)
					&& (validation_retries < SEL3390E4_SFP_VALIDATION_RETRIES)) {

					/* Validation can take around 100+ ms, so we delay
					 * for 100ms and keep looping till it is complete or
					 * times out.
					 */
#ifdef __VMKLNX__
					udelay(100000);
#else
					mdelay(100);
#endif

					sfp_data = ioread32(&hw_mac->sfp_mgmt.status_control);
					validation_retries++;
				}
			}

			if (validation_retries
				>= SEL3390E4_SFP_VALIDATION_RETRIES) {
				/* Failed to finish SFP authentication */
				goto err_validation;
			}

			/* Check if SFP is valid. If we are overriding SFP validation,
			 * ignore the authentication result and use the override 
			 * part number.
			 */
			if ((sfp_data & auth_result_bit) == auth_result_bit) {
				/* Now that the SFP has been successfully validated,
				 * we can report it as connected.
				 */
				sfp_connected = 1;

				/* Set speed based on attached
				 * SFP's part number
				 */

				switch (*sfp_part_number) {
				case PART_NUM_100_BASE_FX:
				case PART_NUM_100_BASE_LX10:

					sel_phy_set_rgmii_100base_fx_mode(hw_mac, phy, mdio_lock);
					break;

				case PART_NUM_1000_BASE_SX:
				case PART_NUM_1000_BASE_LX:

					sel_phy_clear_rgmii_100base_fx_mode(hw_mac, phy, mdio_lock);
					break;

				default:

					/* We shouldn't reach this point
					 * since all connected SFPs that
					 * are 'validated' should have part
					 * numbers we expect
					 */

					sfp_connected = 0;
					*sfp_part_number = 0;
					break;
				}

				if (sfp_connected) {
					/* Enable SFP */
					iowrite32(
						sfp_data | sfp_enable_bit,
						&hw_mac->sfp_mgmt.status_control);

					/* flush */
					sel_write_flush(hw_mac);
				}
			}
		} else {
			/* There is a corner case where SFP override enables an SFP, but
			 * the network interface is restarted, and this state machine
			 * enters the state of "connected" (because the SFP was NOT disabled on
			 * reset), but the SFP connected is not an approved SFP and SFP override
			 * mode is NO longer enabled due to the reset. 
			 */
			switch (*sfp_part_number) {
			case PART_NUM_100_BASE_FX:
			case PART_NUM_100_BASE_LX10:
			case PART_NUM_1000_BASE_SX:
			case PART_NUM_1000_BASE_LX:
				break;

			default:
				/* Disable SFP */
				iowrite32(
					sfp_data & ~sfp_enable_bit,
					&hw_mac->sfp_mgmt.status_control);

				sfp_connected = 0;
				*sfp_part_number = 0;
				break;
			}
		}
	}

err_validation:

	spin_unlock_irqrestore(sfp_lock, flags);

	return sfp_connected;
}

