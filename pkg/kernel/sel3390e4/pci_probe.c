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
 * Driver interface to the PCI driver
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* printk */

#include <asm/atomic.h>        /* atomic operations */
#include <asm/io.h>            /* iowrites */
#include <linux/errno.h>       /* error codes */
#include <linux/firmware.h>    /* firmware */
#include <linux/if_ether.h>    /* ethernet definitions */
#include <linux/init.h>        /* driver init macros */
#include <linux/ioport.h>      /* iomap, request region */
#include <linux/module.h>      /* required module definitions */
#include <linux/moduleparam.h> /* module parameters */
#include <linux/pci.h>         /* pci interface */
#include <linux/pci_regs.h>    /* pci config registers */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/slab.h>        /* kmalloc, kzalloc */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

#ifdef __VMKLNX__
#include "core_firmware_image.h" /* firmware image */
#endif

#include "netdev.h"             /* netdevice interface */
#include "nor_hw_ctrl.h"        /* nor interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_hw.h"       /* mac interface */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */
#include "sel3390e4_mdio.h"     /* mdio interface */
#include "sel3390e4_sfp.h"      /* sfp interface */

/* Module parameter allowing the driver to auto-upgrade
 * out of date firmware
 */
static int AUTO_UPGRADE_FW = 1;
module_param(AUTO_UPGRADE_FW, int, 0);
MODULE_PARM_DESC(AUTO_UPGRADE_FW, "Automatically upgrade out-of-date firmware (0=off)");

/* Location of firmware data in /lib/firmware */
#define SEL3390E4_CORE_FIRMWARE_FILE "sel3390e4/sel3390e4_firmware.bin"

/* Firmware build ID. 
   This build ID is replaced during the build process in a staginf directory.
   As such, the syntax of everything leading up to the build id must not change.
 */
static u32 const FIRMWARE_BUILD_ID = 0x0101C01D;

/* Below are definitions related to device attributes. The APIs
 * compile cleanly under ESXi, but are NOT supported in ESXi. Thus,
 * you will only see these attributes displayed under Linux.
 */
#ifndef __VMKLNX__

/* SFP part number used when bypassing SFP validation */
extern u32 BYPASS_SFP_PART_NUM;

/**
 * enum sel3390e4_dev_attributes - device attributes
 *
 * These names match the exact names of the attributes supported
 * via sysfs. These attributes configure ALL ports with the same
 * values. (ex. bypass_sfp_speed_100 would cause all ports to
 * override SFP validation).
 */
enum sel3390e4_dev_attributes {
	BYPASS_SFP_SPEED_100  = 0,
	BYPASS_SFP_SPEED_1000 = 1,
	INTR_RX_ABS           = 2,
	INTR_RX_PACKET        = 3,
	INTR_TX_ABS           = 4,
	INTR_TX_PACKET        = 5,
	INTR_THROTTLE         = 6
};

/**
 * __show_attr() - Return data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer to store output
 * @attribute_type: the type of attribute to return information for
 *
 * Return: number of bytes stored in the buffer
 */
static ssize_t __show_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff,
	enum sel3390e4_dev_attributes attribute_type
	)
{
	struct pci_dev *pdev =
		container_of(dev, struct pci_dev, dev);
	struct sel3390e4_board *board = pci_get_drvdata(pdev);
	ssize_t bytes_written = 0;

	switch (attribute_type) {
	case BYPASS_SFP_SPEED_100:
		bytes_written =
			sprintf(buff, "%d\n", (u32)board->bypass_sfp_speed_100);
		break;

	case BYPASS_SFP_SPEED_1000:
		bytes_written =
			sprintf(buff, "%d\n", (u32)board->bypass_sfp_speed_1000);
		break;

	case INTR_RX_ABS:
		bytes_written =
			sprintf(buff, "%d\n", ioread32(&board->macs[0]->hw_mac->intr_moderation.rx_abs));
		break;

	case INTR_RX_PACKET:
		bytes_written =
			sprintf(buff, "%d\n", ioread32(&board->macs[0]->hw_mac->intr_moderation.rx_packet));
		break;

	case INTR_TX_ABS:
		bytes_written =
			sprintf(buff, "%d\n", ioread32(&board->macs[0]->hw_mac->intr_moderation.tx_abs));
		break;

	case INTR_TX_PACKET:
		bytes_written =
			sprintf(buff, "%d\n", ioread32(&board->macs[0]->hw_mac->intr_moderation.tx_packet));
		break;

	case INTR_THROTTLE:
		bytes_written =
			sprintf(buff, "%d\n", ioread32(&board->macs[0]->hw_mac->intr_moderation.intr_throttle));
		break;

	default:
		break;
	}

	return bytes_written;
}

/**
 * __store_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 * @attribute_type: the type of attribute to return information for
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t __store_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t size,
	enum sel3390e4_dev_attributes attribute_type
	)
{
	struct pci_dev *pdev =
		container_of(dev, struct pci_dev, dev);
	struct sel3390e4_board *board = pci_get_drvdata(pdev);
	unsigned long temp_data = 0;
	u8 sfp_settings_changed = 0;
	int i;
	ssize_t bytes_written = size;

	/* Convert the string to an integer */
	temp_data = simple_strtoul(buff, NULL, 10);

	switch (attribute_type) {
	case BYPASS_SFP_SPEED_100:
		board->bypass_sfp_speed_100 = temp_data;
		BYPASS_SFP_PART_NUM =
			(board->bypass_sfp_speed_100 != 0) ? PART_NUM_100_BASE_FX : 0;
		sfp_settings_changed = 1;
		break;

	case BYPASS_SFP_SPEED_1000:
		board->bypass_sfp_speed_1000 = temp_data;
		BYPASS_SFP_PART_NUM =
			(board->bypass_sfp_speed_1000 != 0) ? PART_NUM_1000_BASE_LX : 0;
		sfp_settings_changed = 1;
		break;

	case INTR_RX_ABS:
		iowrite32(temp_data, &board->macs[0]->hw_mac->intr_moderation.rx_abs);
		break;

	case INTR_RX_PACKET:
		iowrite32(temp_data, &board->macs[0]->hw_mac->intr_moderation.rx_packet);
		break;

	case INTR_TX_ABS:
		iowrite32(temp_data, &board->macs[0]->hw_mac->intr_moderation.tx_abs);
		break;

	case INTR_TX_PACKET:
		iowrite32(temp_data, &board->macs[0]->hw_mac->intr_moderation.tx_packet);
		break;

	case INTR_THROTTLE:
		iowrite32(temp_data, &board->macs[0]->hw_mac->intr_moderation.intr_throttle);
		break;

	default:
		bytes_written = 0;
		break;
	}

	if (sfp_settings_changed) {
		/* SFP override settings were changed, so we need
		 * to update SFP device state (enable/disable non-supported
		 * SFPs.
		 */
		for (i = 0; i < board->num_macs; ++i) {
			sel3390e4_sfp_detect(board->macs[i]);
		}
	}

	return bytes_written;
}

/**
 * show_sfp_100_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_sfp_100_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, BYPASS_SFP_SPEED_100);
}

/**
 * store_sfp_100_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_sfp_100_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, BYPASS_SFP_SPEED_100);
}

/* SFP override device attribute */
static DEVICE_ATTR(bypass_sfp_speed_100, (S_IWUSR | S_IRUGO), show_sfp_100_attr, store_sfp_100_attr);

/**
 * show_sfp_1000_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_sfp_1000_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, BYPASS_SFP_SPEED_1000);
}

/**
 * store_sfp_1000_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_sfp_1000_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, BYPASS_SFP_SPEED_1000);
}

/* SFP override device attribute */
static DEVICE_ATTR(bypass_sfp_speed_1000, (S_IWUSR | S_IRUGO), show_sfp_1000_attr, store_sfp_1000_attr);

/**
 * show_intr_rx_abs_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_intr_rx_abs_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, INTR_RX_ABS);
}

/**
 * store_intr_rx_abs_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_intr_rx_abs_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, INTR_RX_ABS);
}

/* Interrupt RX Packet Delay Device Attribute */
static DEVICE_ATTR(intr_rx_abs, (S_IWUSR | S_IRUGO), show_intr_rx_abs_attr, store_intr_rx_abs_attr);

/**
 * show_intr_rx_packet_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_intr_rx_packet_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, INTR_RX_PACKET);
}

/**
 * store_intr_rx_packet_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_intr_rx_packet_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, INTR_RX_PACKET);
}

/* Interrupt RX Packet Device Attribute */
static DEVICE_ATTR(intr_rx_packet, (S_IWUSR | S_IRUGO), show_intr_rx_packet_attr, store_intr_rx_packet_attr);

/**
 * show_intr_rx_packet_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_intr_tx_abs_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, INTR_TX_ABS);
}

/**
 * store_intr_tx_abs_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_intr_tx_abs_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, INTR_TX_ABS);
}

/* Interrupt TX Absolute Delay Device Attribute */
static DEVICE_ATTR(intr_tx_abs, (S_IWUSR | S_IRUGO), show_intr_tx_abs_attr, store_intr_tx_abs_attr);

/**
 * show_intr_tx_packet_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_intr_tx_packet_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, INTR_TX_PACKET);
}

/**
 * store_intr_tx_packet_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_intr_tx_packet_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, INTR_TX_PACKET);
}

/* Interrupt TX Packet Delay Device Attribute */
static DEVICE_ATTR(intr_tx_packet, (S_IWUSR | S_IRUGO), show_intr_tx_packet_attr, store_intr_tx_packet_attr);

/**
 * show_intr_throttle_attr() - Show data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 *
 * Return: number of bytes written to the buffer
 */
static ssize_t show_intr_throttle_attr(
	struct device *dev,
	struct device_attribute *attr,
	char *buff
	)
{
	return __show_attr(dev, attr, buff, INTR_THROTTLE);
}

/**
 * store_intr_throttle_attr() - Store data for a specific attribute
 *
 * @dev:            device object
 * @attr:           device attribute to show info for
 * @buff:           buffer containing the data to store
 * @size:           the size of the data to write from the buffer
 *
 * Return: number of bytes used from the buffer
 */
static ssize_t store_intr_throttle_attr(
	struct device *dev,
	struct device_attribute *attr,
	char const *buff,
	size_t count
	)
{
	return __store_attr(dev, attr, buff, count, INTR_THROTTLE);
}

/* Interrupt Throttle Device Attribute */
static DEVICE_ATTR(intr_throttle, (S_IWUSR | S_IRUGO), show_intr_throttle_attr, store_intr_throttle_attr);

/* Array of device attributes */
static struct attribute *sel3390e4_attributes[] = {
	&dev_attr_bypass_sfp_speed_100.attr,
	&dev_attr_bypass_sfp_speed_1000.attr,
	&dev_attr_intr_rx_abs.attr,
	&dev_attr_intr_rx_packet.attr,
	&dev_attr_intr_tx_abs.attr,
	&dev_attr_intr_tx_packet.attr,
	&dev_attr_intr_throttle.attr,
	NULL
};

/* Device attributes group */
static struct attribute_group const sel3390e4_attribute_group = {
	.attrs = sel3390e4_attributes
};

#endif /* __VMKLNX__ */

/**
 * __sel3390e4_shutdown() - Detach and bring down all netdevices
 *
 * @pdev:    pci device object
 * @pci_err: called because of an irrecoverable PCI error
 */
static void __sel3390e4_shutdown(struct pci_dev *pdev, int pci_err)
{
	int i;
	struct sel3390e4_mac *mac;
	struct sel3390e4_board *board = pci_get_drvdata(pdev);

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	for (i = 0; i < board->num_macs; i++) {
		mac = board->macs[i];

		/* netdev can never be NULL outside of
		 * the probe function, unless explictly changed.
		 */
		BUG_ON(mac->netdev == NULL);

		/* Mark this device as removed and no longer available */
		netif_device_detach(mac->netdev);

		/* Bring down the net device */

		if (!pci_err && netif_running(mac->netdev)) {
			sel3390e4_down(mac);
		}
	}

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);
}

/**
 * __sel3390e4_startup() - Attach and bring up all netdevices
 *
 * @pdev: pci device object
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int __sel3390e4_startup(struct pci_dev *pdev)
{
	int i;
	struct sel3390e4_mac *mac;
	struct sel3390e4_board *board = pci_get_drvdata(pdev);
	int err = 0;

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	for (i = 0; i < board->num_macs; i++) {
		mac = board->macs[i];

		/* netdev can never be NULL outside of
		 * the probe function, unless explictly changed.
		 */
		BUG_ON(mac->netdev == NULL);

		if (netif_running(mac->netdev) && sel3390e4_up(mac)) {
			err = -EIO;
			break;
		}

		netif_device_attach(mac->netdev);
	}

	if (err) {
		__sel3390e4_shutdown(pdev, 0);
	}

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);

	return err;
}

#ifdef CONFIG_PM
/**
 * sel3390e4_suspend() - Called when the system is entering sleep state
 *
 * @pdev:  pci device object
 * @state: state being entered
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int sel3390e4_suspend(struct pci_dev *pdev, pm_message_t state)
{
	int err = 0;

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	__sel3390e4_shutdown(pdev, 0);

	err = pci_save_state(pdev);
	if (err) {
		return err;
	}

	pci_disable_device(pdev);

	/* Disable wake capabilities and enter state
	 * Here we would normally enable wake capabilities,
	 * however, our device doesn't support wake-on-lan,
	 * so we disable the functionality for this device
	 */
	pci_enable_wake(pdev, pci_choose_state(pdev, state), 0);

	err = pci_set_power_state(pdev,  pci_choose_state(pdev, state));

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);

	return err;
}

/**
 * sel3390e4_resume() - Called when the system is leaving sleep state
 *
 * @pdev: pci device object
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int sel3390e4_resume(struct pci_dev *pdev)
{
	int err;

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);

	err = pci_enable_device(pdev);
	if (err) {
		return err;
	}

	/* Set as bus master */
	pci_set_master(pdev);

	/* ack any pending wake events, disable PME */
	pci_enable_wake(pdev, 0, 0);

        err = __sel3390e4_startup(pdev);

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);

	return err;
}
#endif /* CONFIG_PM */

/**
 * sel3390e4_io_error_detected() - Called when a PCI error is detected
 * on this device
 *
 * @pdev:  pci device object
 * @state: error type
 *
 * Return:
 *  PCI_ER_RESULT_NONE,
 *  PCI_ERS_RESULT_CAN_RECOVER,
 *  PCI_ERS_RESULT_NEED_RESET,
 *  PCI_ERRS_RESULT_DISCONNECT,
 *  PCI_ERS_RESULT_RECOVERED,
 *  PCI_ERS_RESULT_AER_DRIVER
 */
static pci_ers_result_t sel3390e4_io_error_detected(
	struct pci_dev *pdev,
	pci_channel_state_t state
	)
{
	int pci_err = (state == pci_channel_io_perm_failure);

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	__sel3390e4_shutdown(pdev, pci_err);

	if (pci_err) {
		/* The device has failed so completely disconnect
		 * as device registers would be unavailable as well
		 */
		return PCI_ERS_RESULT_DISCONNECT;
	}

	/* Disable this PCI device */
	pci_disable_device(pdev);

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * sel3390e4_io_slot_reset() - Restart the device from scratch
 *
 * @pdev: pci device object
 *
 * Called after the PCI bus has been reset
 *
 * Return:
 *  PCI_ERS_RESULT_DISCONNECT,
 *  PCI_ERS_RESULT_RECOVERED
 */
static pci_ers_result_t sel3390e4_io_slot_reset(struct pci_dev *pdev)
{
	struct sel3390e4_board *board = pci_get_drvdata(pdev);
	int err = 0;

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	if (pci_enable_device(pdev)) {
		return PCI_ERS_RESULT_DISCONNECT;
	}

	/* Set as PCI bus master */
	pci_set_master(pdev);

	/* Only one device per card can do a reset */
	if (0 != PCI_FUNC(pdev->devfn)) {
		return PCI_ERS_RESULT_RECOVERED;
	}

	/* Reset the MACs */
	sel3390e4_hw_reset_all_macs(board);
	err = PCI_ERS_RESULT_RECOVERED;

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);

	return err;
}

/**
 * sel3390e4_io_resume() - Resume normal operations after an error
 * recovery sequence has be completed
 *
 * @pdev: pci device object
 */
static void sel3390e4_io_resume(struct pci_dev *pdev)
{
	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	/* Acknowledge any pending wake events, disable PME */
	pci_enable_wake(pdev, 0, 0);

	/* Bring up each net device */
	(void)__sel3390e4_startup(pdev);

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);
}

/* PCI bus error handlers */
static struct pci_error_handlers sel3390e4_err_handler = {
	.error_detected = sel3390e4_io_error_detected,
	.slot_reset     = sel3390e4_io_slot_reset,
	.resume         = sel3390e4_io_resume
};

/**
 * sel3390e4_shutdown() - Hook into reboot_notifier_list
 *
 * @pdev: pci device object
 */
static void sel3390e4_shutdown(struct pci_dev *pdev)
{
	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	__sel3390e4_shutdown(pdev, 0);

	/* Disable this PCI device */
	pci_disable_device(pdev);

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);
}

/**
 * sel3390e4_probe() - PCI device initialization routine
 *
 * @pdev: PCI device information struct
 * @ent:  entry from the sel3390e4_pci_tbl
 *
 * Initializes an adapter identified by a pci_dev structure.
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int __init sel3390e4_probe(struct pci_dev *pdev, struct pci_device_id const *ent)
{
	struct sel3390e4_board *board;
	int err;

#ifndef __VMKLNX__
	struct firmware const *fw;
#endif

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

	/* Allocate the PCI device context */
	board = kzalloc(sizeof(struct sel3390e4_board), GFP_KERNEL);
	if (board == NULL) {
		err = -ENOMEM;
		goto all_done;
	}

	/* Store the PCI device in the pci device context */
	board->pdev = pdev;

	/* Store the PCI device context into the pci device object */
	pci_set_drvdata(pdev, board);

	/* Initialize the upgrade flag */
	atomic_set(&board->firmware_upgrade_in_progress, 1);

	/* Initialize board level spin locks */
	spin_lock_init(&board->nvm_lock);
	spin_lock_init(&board->sfp_lock);
	spin_lock_init(&board->mdio_lock);

	/* Enable the PCI device so that we can access
	 * I/O, IRQ, and config space
	 */
	err = pci_enable_device(pdev);
	if (err) {
		goto err_out_free_dev;
	}

	/* Reserve PCI regions for MAC, DIAG, and NVM BARs */

	err = pci_request_region(
		pdev, SEL3390E4_PCI_BAR_MACS, SEL3390E4_DRV_NAME);
	if (err) {
		goto err_out_disable_pdev;
	}

	err = pci_request_region(
		pdev, SEL3390E4_PCI_BAR_DIAG, SEL3390E4_DRV_NAME);
	if (err) {
		goto err_out_release_macs;
	}

	err = pci_request_region(
		pdev, SEL3390E4_PCI_BAR_NVM, SEL3390E4_DRV_NAME);
	if (err) {
		goto err_out_release_diag;
	}

	/* Set the DMA masks */

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))
		&& !pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64))) {
		/* The DMA mask is set to 64-bit */
		board->pci_using_dac = 1;
	} else if (pci_set_dma_mask(pdev, DMA_BIT_MASK(32))
		|| pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32))) {
		/* Failed to set the DMA mask to 64-bit or 32-bit */
		goto err_out_release_nvm;
	}

	/* Map the memory for the MACs */
	board->hw_macs =
		pci_iomap(pdev, SEL3390E4_PCI_BAR_MACS, 0);
	if (board->hw_macs == NULL) {
		err = -ENODEV;
		goto err_out_release_nvm;
	}

	/* Map the memory for the DIAG bar */
	board->hw_diag =
		pci_iomap(pdev, SEL3390E4_PCI_BAR_DIAG, 0);
	if (board->hw_diag == NULL) {
		err = -ENODEV;
		goto err_out_iounmap_mac;
	}

	/* Map the memory for the NOR flash */
	board->hw_nvm =
		pci_iomap(pdev, SEL3390E4_PCI_BAR_NVM, 0);
	if (board->hw_nvm == NULL) {
		err = -ENODEV;
		goto err_out_iounmap_diag;
	}

	/* Store the build ID */
	board->build_id = ioread32(&board->hw_diag->build_id);

	/* This driver only works for a matching build id version */
	if ((board->build_id != FIRMWARE_BUILD_ID) &&
       (AUTO_UPGRADE_FW != 0)) {
		dev_err(
			&pdev->dev,
			"[ERROR] Unsupported hardware build id %d.%d.%d.%d, expected %d.%d.%d.%d.\n",
			(board->build_id >> 24),
			((board->build_id >> 16) & 0xFFU),
			((board->build_id >> 8) & 0xFFU),
			(board->build_id & 0xFFU),
			(FIRMWARE_BUILD_ID >> 24),
			((FIRMWARE_BUILD_ID >> 16) & 0xFFU),
			((FIRMWARE_BUILD_ID >> 8) & 0xFFU),
			(FIRMWARE_BUILD_ID & 0xFFU));

#ifndef __VMKLNX__
      if (!request_firmware(&fw, SEL3390E4_CORE_FIRMWARE_FILE, &pdev->dev)) {
         err =
            sel3390e4_update_flash(
               board,
               FLASH_IMAGE_FUNCTIONAL,
               fw->data,
               fw->size,
               &board->nvm_lock);

         release_firmware(fw);
      }
#else
   err =
      sel3390e4_update_flash(
         board,
         FLASH_IMAGE_FUNCTIONAL,
         (u8*)CORE_FIRMWARE_IMAGE,
         CORE_FIRMWARE_IMAGE_SIZE,
         &board->nvm_lock);      
#endif

		err = -ENODEV;
		goto err_out_iounmap_nor;
	}

	/* Query the revision ID */
	err = pci_read_config_byte(pdev, PCI_REVISION_ID, &board->revision_id);
	if (err) {
		goto err_out_iounmap_nor;
	}

	/* Retrieve the subsystem ID so we know how many MACs we have */
	err = pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &board->num_macs);
	if (err) {
		goto err_out_iounmap_nor;
	}

	/* Enable the device as a master of the bus (for DMA) */
	pci_set_master(pdev);

	/* Allocate memory for the MAC array */
	board->macs =
		kzalloc(
			(sizeof(struct sel3390e4_mac *) * board->num_macs),
			GFP_KERNEL);
	if (board->macs == NULL) {
		err = -ENOMEM;
		goto err_out_iounmap_nor;
	}

	/* Allocate net devices */
	err = sel3390e4_allocate_net_devices(board);
	if (err) {
		goto err_out_free_macs;
	}

	/* Initialize all the attached PHYs
	 * This has to be done after the allocation of
	 * the net devices
	 */
	sel3390e4_mdio_probe(board);

   /* Set default interrupt moderation value */
   iowrite32(
         INTR_THROTTLE_DEFAULT, 
         &board->macs[0]->hw_mac->intr_moderation.intr_throttle);

	/* Register net devices */
	err = sel3390e4_register_net_devices(board);
	if (err) {
		goto err_free_net_devices;
	}

#ifndef __VMKLNX__

	/* Create device attributes */
	err = sysfs_create_group(&pdev->dev.kobj, &sel3390e4_attribute_group);
	if (err) {
		goto err_unregister_netdevices;
	}

#endif /* __VMKLNX__ */

	goto all_done;

#ifndef __VMKLNX__

err_unregister_netdevices:

	sel3390e4_unregister_net_devices(board);

#endif /* __VMKLNX__ */

err_free_net_devices:

	sel3390e4_free_net_devices(board);

err_out_free_macs:

	kfree(board->macs);

err_out_iounmap_nor:

	pci_iounmap(pdev, board->hw_nvm);

err_out_iounmap_diag:

	pci_iounmap(pdev, board->hw_diag);

err_out_iounmap_mac:

	pci_iounmap(pdev, board->hw_macs);

err_out_release_nvm:

	pci_release_region(pdev, SEL3390E4_PCI_BAR_NVM);

err_out_release_diag:

	pci_release_region(pdev, SEL3390E4_PCI_BAR_DIAG);

err_out_release_macs:

	pci_release_region(pdev, SEL3390E4_PCI_BAR_MACS);

err_out_disable_pdev:

	pci_disable_device(pdev);

err_out_free_dev:

	pci_set_drvdata(pdev, NULL);
	kfree(board);

all_done:

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);

	return err;
}

/**
 * sel3390e4_remove() - PCI device removal routine
 *
 * @pdev: PCI device information struct
 *
 * Called by the PCI subsystem when the device needs
 * to be removed. Could be because the driver is getting
 * unloaded or because of a hot-plug event.
 */
static void __exit sel3390e4_remove(struct pci_dev *pdev)
{
	struct sel3390e4_board *board = pci_get_drvdata(pdev);

	dev_vdbg(&pdev->dev, "--> %s\n", __func__);

#ifndef __VMKLNX__

	/* Remove device attributes */
	sysfs_remove_group(&pdev->dev.kobj, &sel3390e4_attribute_group);

#endif /* __VMKLNX__ */

	/* De-register the net devices */
	sel3390e4_unregister_net_devices(board);

	/* Free the net device memory */
	sel3390e4_free_net_devices(board);

	/* Free the net device context memory */
	kfree(board->macs);

	/* Unmap all the BARs */
	pci_iounmap(pdev, board->hw_nvm);
	pci_iounmap(pdev, board->hw_diag);
	pci_iounmap(pdev, board->hw_macs);

	/* Release all the BARs */
	pci_release_region(pdev, SEL3390E4_PCI_BAR_NVM);
	pci_release_region(pdev, SEL3390E4_PCI_BAR_DIAG);
	pci_release_region(pdev, SEL3390E4_PCI_BAR_MACS);

	/* Disable the device */
	pci_disable_device(pdev);

	/* Free the PCI device context memory */
	pci_set_drvdata(pdev, NULL);
	kfree(board);

	dev_vdbg(&pdev->dev, "<-- %s\n", __func__);
}

/* PCI device description table */
static struct pci_device_id sel3390e4_pci_tbl[] __initdata = {
	/* 1-port 3390 Ethernet Device */
	{
		.vendor = PCI_VENDOR_ID_SCHWEITZER,
		.device = PCI_DEVICE_ID_SCHWEITZER_3390E4,
		.subdevice = 1,
		.subvendor = PCI_ANY_ID
	},

	/* 2-port 3390 Ethernet Device */
	{
		.vendor = PCI_VENDOR_ID_SCHWEITZER,
		.device = PCI_DEVICE_ID_SCHWEITZER_3390E4,
		.subdevice = 2,
		.subvendor = PCI_ANY_ID
	},

	/* 4-port 3390 Ethernet Device */
	{
		.vendor = PCI_VENDOR_ID_SCHWEITZER,
		.device = PCI_DEVICE_ID_SCHWEITZER_3390E4,
		.subdevice = 4,
		.subvendor = PCI_ANY_ID
	},

	{} /* No more */
};
MODULE_DEVICE_TABLE(pci, sel3390e4_pci_tbl);

/* PCI Device Driver Structure */
static struct pci_driver sel3390e4_driver = {
	.name           = SEL3390E4_DRV_NAME,
	.id_table       = sel3390e4_pci_tbl,
	.probe          = sel3390e4_probe,
	.remove         = sel3390e4_remove,

#ifdef CONFIG_PM
	.suspend        = sel3390e4_suspend,
	.resume         = sel3390e4_resume,
#endif

	.shutdown       = &sel3390e4_shutdown,
	.err_handler    = &sel3390e4_err_handler,
};

/**
 * sel3390e4_init_module() - Driver Initialization Routine
 *
 * Return: 0 if successful, otherwise negative error code
 */
static int __init sel3390e4_init_module(void)
{
	pr_debug("--> %s", __func__);

	pr_info(
		"%s v%s\n",
		SEL3390E4_DRV_DESCRIPTION,
		SEL3390E4_DRV_VERSION);

	pr_info("%s\n", SEL3390E4_DRV_COPYRIGHT);

	pr_debug("<-- %s", __func__);

	return pci_register_driver(&sel3390e4_driver);
}
module_init(sel3390e4_init_module)

/**
 * sel3390e4_exit_module() - Driver Exit Routine
 */
static void __exit sel3390e4_exit_module(void)
{
	pr_debug("--> %s", __func__);

	pci_unregister_driver(&sel3390e4_driver);

	pr_debug("<-- %s", __func__);
}
module_exit(sel3390e4_exit_module);

MODULE_AUTHOR(SEL3390E4_DRV_COPYRIGHT);
MODULE_DESCRIPTION(SEL3390E4_DRV_DESCRIPTION);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(SEL3390E4_DRV_VERSION);
MODULE_FIRMWARE(SEL3390E4_CORE_FIRMWARE_FILE);
