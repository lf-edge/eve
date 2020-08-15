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
 * Schweitzer Engineering Laboratories, Inc
 * 2350 NE Hopkins Court, Pullman, WA 99163
 ******************************************************************************
 ** @brief
 ** b2071 upgrade driver
 **
 ** @remarks
 ** Driver used to upgrade the b2071 mainboard. This driver is usually packaged
 ** with the b2071_upgrade utility.
 *****************************************************************************/

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/module.h>        /* required */
#include <linux/device.h>        /* dev_err */

#include <asm/atomic.h>          /* atomic operations */
#include <asm/io.h>              /* outb, inb, etc. */
#include <asm/uaccess.h>         /* user access functions (copy_*_user) */
#include <linux/uaccess.h>
#include <linux/fs.h>            /* character driver registration and file operations */
#include <linux/cdev.h>          /* character device */
#include <linux/errno.h>         /* error codes */
#include <linux/init.h>          /* init/exit macros */
#include <linux/slab.h>          /* kzalloc, kmalloc */
#include <linux/types.h>         /* std types */
#include <linux/version.h>       /* linux version */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))

#ifndef pr_err
#define pr_err(fmt, arg...) printk(KERN_ERR fmt, ##arg)
#endif

#endif /* KERNEL_VERSION(2,6,24) */

#ifdef __VMKLNX__

#include <linux/miscdevice.h>   /* miscdevice registration */

#else /* !defined(__VMKLNX__) */

#include <linux/acpi.h>         /* acpi related items */
#include <acpi/acpi_bus.h>      /* acpi registration */

#endif /* __VMKLNX__ */

/* Driver Version Number */
#define DRV_VERSION "1.0.49152.76"

#define DRIVER_NAME ("selb2071upg")
#define CLASS_NAME ("selb2071upg")
#define B2071UPG_DEVICE_ID ("SEL0001")

/* INTERFACE CONSTANTS AND MACROS */

uint16_t const STATUS_REGISTER = 0x190;
uint16_t const FIFO_REGISTER   = 0x191;

/**
 * enum ec_errors - EC Errors
 */
enum ec_errors {
	STATUS_REGISTER_FIFO_EMPTY   = (1<<0),
	STATUS_REGISTER_FIFO_FULL    = (1<<1),
	STATUS_REGISTER_START        = (1<<2),
	STATUS_REGISTER_COMPLETE     = (1<<3),
	STATUS_REGISTER_FAILURE      = (1<<4),
	STATUS_REGISTER_SUCCESS      = (1<<5),
	STATUS_REGISTER_UPGRADE_BUSY = (1<<6)
};

/* Maximum size of the EC fifo */
static uint16_t const EC_FIFO_SIZE = 512;

/* The DAT file used for the upgrade has a defined header. The length of
 * the DAT file is a 4-byte unsigned integer in little-endian format starting
 * at byte 26 of the header.  (-1 for zero index) */
static uint8_t const DAT_FILE_LENGTH_START = 25;

/* Maximum DAT file size supported by the EC. */
static uint32_t const DAT_FILE_MAXIMUM_SIZE = (1024 * 1024);

/**
 * struct b2071upg_device_context - Device Private Context Area
 */
struct b2071upg_device_context {

#ifdef __VMKLNX__
	/* misc device object */
	struct miscdevice misc_device;
#else
	/* acpi device object */
	struct acpi_device* pdev;

	/* character device object */
	struct cdev cdev;

	/* major/minor device number */
	dev_t dev_no;

	/* device class */
	struct class *device_class;

	/* device node */
	struct device *device_node;
#endif

	/* atomic used to serialize write operations */
	atomic_t write_available;

	/* atomic variable used for preventing multiple open file handles */
	atomic_t open_available;
};

/**
 * struct b2071upg_file_context - File Private Context Area
 */
struct b2071upg_file_context {
	/* Pointer to the main driver context */
	struct b2071upg_device_context* ctx;

	/* Total size of the file to load in bytes */
	uint32_t size;

	/* Number of bytes sent to the EC */
	uint32_t sent;

	/* Flag indicating if we have signaled complete */
	uint8_t done;
};

#ifdef __VMKLNX__

/* Global device context */
static struct b2071upg_device_context *g_b2071upg_device_context;

#endif

/**
 * b2071upg_read() - User space request to read driver data
 *
 * @filp:  open kernel file descriptor
 * @buff:  user output buffer
 * @count: number of bytes to read
 * @offp:  file position to access
 *
 * This function returns the state of the EC, whether it is
 * busy, or available.
 *
 * Return: >= 0 if successful, otherwise appropriate negative error value
 */
static ssize_t b2071upg_read(
	struct file *filp,
	char __user *buff,
	size_t count,
	loff_t *offp
	)
{
	ssize_t err = -EBUSY;
	struct b2071upg_file_context *fctx = filp->private_data;
	uint8_t data;

	pr_debug("--> %s\n", __func__);

	if (fctx->done == 1) {
		data = inb(STATUS_REGISTER);

		if ((data & STATUS_REGISTER_SUCCESS) != 0) {
			err = 0;
		} else if ((data & STATUS_REGISTER_FAILURE) != 0) {
			pr_err("[ERROR] B2071UPG: File transfer error.\n");
			err = -EIO;
		}
	}

	pr_debug("<-- %s\n", __func__);

	return err;
}

/**
 * b2071upg_write() - User space request to write driver data
 *
 * @filp:  open kernel file descriptor
 * @buff:  user input buffer
 * @count: number of bytes to write
 * @offp:  file position to access
 *
 * Return: >= 0 if successful, otherwise appropriate negative error value
 */
static ssize_t b2071upg_write(
	struct file *filp,
	const char __user *buff,
	size_t count,
	loff_t *offp
	)
{
	ssize_t err = 0;
	uint8_t *buffer = NULL;
	uint8_t *original_buffer = NULL;
	struct b2071upg_file_context *fctx = filp->private_data;
	u32 old_size = fctx->sent;

	pr_debug("--> %s\n", __func__);

	if (!atomic_dec_and_test(&fctx->ctx->write_available)) {
		/* already open */
		atomic_inc(&fctx->ctx->write_available);
		return -EBUSY;
	}

	buffer = kzalloc(count, GFP_KERNEL);
	if (buffer == NULL) {
		atomic_inc(&fctx->ctx->write_available);
		return -ENOMEM;
	}

	original_buffer = buffer;

	if (copy_from_user(buffer, buff, count) != 0) {
		atomic_inc(&fctx->ctx->write_available);
		kfree(original_buffer);
		return -EIO;
	}

	/* If this is the first write, then get the real file size */
	if (fctx->size == 0) {
		/* make sure there is enough bytes for a 4 byte integer. */
		if (count < (DAT_FILE_LENGTH_START + sizeof(uint32_t) + 1)) {
			pr_err("[ERROR] First write of DAT file too small.\n");
			err = -EIO;
		} else {
			/* Unaligned 32-bit access (little endian) */
			fctx->size += buffer[DAT_FILE_LENGTH_START];
			fctx->size += (buffer[DAT_FILE_LENGTH_START + 1] << 8);
			fctx->size += (buffer[DAT_FILE_LENGTH_START + 2] << 16);
			fctx->size += (buffer[DAT_FILE_LENGTH_START + 3] << 24);
			if (fctx->size > DAT_FILE_MAXIMUM_SIZE) {
				pr_err("[ERROR] DAT file too large.\n");
				fctx->size = 0;
				err = -EIO;
			} else {
				pr_info("Data file size = %d\n", fctx->size);
			}
		}
	}

	/* Loop through write request until we are done or run out of bytes. */
	while ((fctx->sent < fctx->size) && (count > 0)) {
		uint8_t data = 0;
		uint32_t byte_count;

		/* Wait for FIFO empty */

		pr_debug("Waiting for FIFO to become empty.\n");

		while (((data & STATUS_REGISTER_FIFO_EMPTY) == 0) ||
			((data & STATUS_REGISTER_UPGRADE_BUSY) == STATUS_REGISTER_UPGRADE_BUSY)) {
			data = inb(STATUS_REGISTER);

			if ((data & STATUS_REGISTER_FAILURE) == STATUS_REGISTER_FAILURE) {
				pr_debug("[ERROR] Failed to empty FIFO.\n");
				err = -EIO;
				break;
			}
		}

		/* Bail if an EC error occurs. This handles the case where a
		 * previous operation caused the EC to enter a failure state.
		 * Unfortunately, this means the EC may need a full power cycle 
		 * to enter a well know good state (and successfully perform upgrades).
		 */
		if (err != 0) {
			break;
		}

		/* Figure out how much to send while checking for overflow */
		byte_count = (count < EC_FIFO_SIZE) ? count : EC_FIFO_SIZE;
		if (byte_count > (fctx->size - fctx->sent)) {
			pr_debug("B2071UPG: Incorrect dat file size.\n");
			err = -EIO;
			break;
		}

		/* Write the data out to the FIFO */

		outsb(FIFO_REGISTER, buffer, byte_count);
		fctx->sent += byte_count;
		count -= byte_count;
		buffer += byte_count;

		pr_info("Sent %d/%d bytes.\n", fctx->sent, fctx->size);
	}

	/* if we sent it all, and don't have extra, then write the done bit. */
	if ((fctx->size != 0) && (fctx->size == fctx->sent)) {
		pr_info("File transfer complete.\n");
		outb((uint8_t)STATUS_REGISTER_COMPLETE, STATUS_REGISTER);
		fctx->done = 1;
	}

	/* Complete the request */
	if (err == 0) {
		err = (fctx->sent - old_size);
	}

	kfree(original_buffer);

	atomic_inc(&fctx->ctx->write_available);

	pr_debug("<-- b2071upg_write\n");

	return err;
}

/**
 * b2071upg_close() - Closes a handle to the driver
 *
 * @inode: kernel internal file descriptor
 * @filp:  open kernel file descriptor
 *
 * Return: 0 always
 */
static int b2071upg_close(struct inode *inode, struct file *filp)
{
	struct b2071upg_file_context* fctx = filp->private_data;

	pr_debug("--> %s\n", __func__);

	/* if we haven't already indicated completion, and we've sent
	 * all the data, indicate complete. */

	if ((fctx->done == 0) && (fctx->size != 0) && (fctx->size == fctx->sent)) {
		pr_info("File transfer complete.\n");
		outb((uint8_t)STATUS_REGISTER_COMPLETE, STATUS_REGISTER);
	}

	atomic_inc(&fctx->ctx->open_available);

	/* Free the file context */
	kfree(filp->private_data);
	filp->private_data = NULL;

	pr_debug("<-- %s\n", __func__);

	return 0;
}

/**
 * b2071upg_open() - Opens a handle to the driver
 *
 * @inode: kernel internal file descriptor
 * @filp:  open kernel file descriptor
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
static int b2071upg_open(struct inode *inode, struct file *filp)
{
	struct b2071upg_file_context *fctx;

#ifdef __VMKLNX__
	struct b2071upg_device_context *device_context = g_b2071upg_device_context;
#else
	struct b2071upg_device_context *device_context =
		container_of(inode->i_cdev, struct b2071upg_device_context, cdev);
#endif

	pr_debug("--> %s\n", __func__);

	if (!atomic_dec_and_test(&device_context->open_available)) {
		/* already open */
		atomic_inc(&device_context->open_available);
		return -EBUSY;
	}

	/* Allocate file context area */

	fctx = kzalloc(sizeof(struct b2071upg_file_context), GFP_KERNEL);

	if (fctx == NULL) {
		atomic_inc(&device_context->open_available);
		pr_err("[ERROR] Unable to allocate file context.");
		return -ENOMEM;
	}

	fctx->ctx = device_context;
	filp->private_data = fctx;

	/* Signal to the EC that we are starting an upgrade */
	outb((uint8_t)STATUS_REGISTER_START, STATUS_REGISTER);

	pr_debug("<-- %s\n", __func__);

	return 0;
}

/* File operations structure */
static struct file_operations b2071upg_file_ops = {
	.owner   = THIS_MODULE,
	.read    = b2071upg_read,
	.write   = b2071upg_write,
	.open    = b2071upg_open,
	.release = b2071upg_close
};

#ifdef __VMKLNX__

/**
 * acpi_misc_device_add() - ACPI device registration function
 *
 * @dev: ptr to the acpi device object
 *
 * This function is called during execution of acpi_bus_register_driver.
 *
 * Return: 0 if successful, otherwise an appropriate error code (negative)
 */
static int __init acpi_misc_device_add(void)
{
	int err = 0;
	struct b2071upg_device_context *device_context = NULL;

	pr_debug("--> %s\n", __func__);

	/* Try to allocate private data struct */
	device_context =
		kzalloc(sizeof(struct b2071upg_device_context), GFP_KERNEL);

	if (device_context == NULL) {
		pr_err("[ERROR] Unable to allocate device context.");
		return -ENOMEM;
	}

	/* initialize count of available open handles */
	atomic_set(&device_context->open_available, 1);

	/* initialize count of available writes */
	atomic_set(&device_context->write_available, 1);

	/* Set up the misc device. Under VMware, the character device
	 * source files don't seem to be available, so the linking fails.
	 * Thus, we use a misc device which esentially does the same thing
	 * as a character device. */

	device_context->misc_device.minor = MISC_DYNAMIC_MINOR;
	device_context->misc_device.name = DRIVER_NAME;
	device_context->misc_device.fops = &b2071upg_file_ops;

	if (misc_register(&device_context->misc_device)) {
		pr_err("[ERROR] Unable to register misc device.\n");
		err = -ENOMEM;
	} else {
		pr_info("Misc Device registered with minor # %d\n",
			device_context->misc_device.minor);

		/* Store the context */
		g_b2071upg_device_context = device_context;
		goto all_done;
	}

	kfree(device_context);
	device_context = NULL;

all_done:

	pr_debug("<-- %s\n", __func__);

	return err;
}

/**
 * acpi_misc_device_remove() - ACPI device de-registration function
 *
 * @dev:  ptr to the acpi device object
 * @type: the type of ACPI bus (only in kernel versions < 3.9)
 *
 * This function is called during execution of acpi_bus_unregister_driver.
 *
 * Return: 0 if successful, otherwise an appropriate error code (negative)
 */
static int __exit acpi_misc_device_remove(void)
{
	struct b2071upg_device_context *device_context = g_b2071upg_device_context;

	pr_debug("--> %s\n", __func__);

	/* unregister misc device */
	misc_deregister(&device_context->misc_device);

	/* Free the device context */
	kfree(device_context);
	device_context = NULL;

	pr_debug("<-- %s\n", __func__);

	return 0;
}

#else /* !defined(__VMKLNX__) */

/**
 * b2071upg_acpi_resource() - ACPI Resource Enumeration function
 *
 * @resource: acpi resource item
 * @context:  device context used to store resource info
 *
 * This method is called by ACPI for each resource that is found. When no more
 * resources are available, the ACPI_RESOURCE_TYPE_END_TAG resource type is passed.
 * This function merely performs address validation.
 *
 * Return: 0 if successful, otherwise an appropriate error code (negative)
 */
static acpi_status __init b2071upg_acpi_resource(
	struct acpi_resource *resource,
	void *context
	)
{
	static int status_reg_found = 0;
	acpi_status retval = AE_OK;

	pr_debug("--> %s\n", __func__);

	if (resource == NULL) {
		return AE_ERROR;
	}

	switch (resource->type) {
	case ACPI_RESOURCE_TYPE_IO:
		/* The first address region returned is the status port, and
		 * the second address returned is the fifo port */

		retval = (resource->data.io.minimum == STATUS_REGISTER)
			? AE_OK : AE_ERROR;

		status_reg_found = (retval == AE_OK);

		break;

	case ACPI_RESOURCE_TYPE_END_TAG:
		if (status_reg_found) {
			retval = AE_OK;
		} else {
			retval = AE_NOT_FOUND;
		}

		break;

	case ACPI_RESOURCE_TYPE_IRQ:
		retval = AE_OK;
		break;

	default:
		retval = AE_ERROR;
		break;
	}

	pr_debug("<-- %s\n", __func__);

	return retval;
}

/**
 * acpi_device_add() - ACPI device registration function
 *
 * @dev: ptr to the acpi device object
 *
 * This function is called during execution of acpi_bus_register_driver.
 *
 * Return: 0 if successful, otherwise an appropriate error code (negative)
 */
static int __init acpi_device_add(struct acpi_device *dev)
{
	int err = 0;
	struct b2071upg_device_context *device_context = NULL;

	pr_debug("--> %s\n", __func__);

	/* Try to allocate private data struct */
	device_context =
		kzalloc(sizeof(struct b2071upg_device_context), GFP_KERNEL);

	if (device_context == NULL) {
		pr_err("[ERROR] Unable to allocate device context.");
		return -ENOMEM;
	}

	/* Dynamically allocate a major number for this device */
	if (alloc_chrdev_region(&device_context->dev_no, 0, 1, DRIVER_NAME) != 0) {
		pr_err("[ERROR] Unable to allocate character device.\n");
		err = -ENODEV;
		goto err_free_context;
	}

	/* Store the acpi_device object */
	device_context->pdev = dev;

	/* initialize count of available open handles */
	atomic_set(&device_context->open_available, 1);

	/* initialize count of available writes */
	atomic_set(&device_context->write_available, 1);

	/* Create the class */
	device_context->device_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(device_context->device_class)) {
		pr_err("[ERROR] Unable to create device class.\n");
		err = PTR_ERR(device_context->device_class);
		goto err_free_chrdev_region;
	}

	/* Create the device node */
	device_context->device_node =
		device_create(
			device_context->device_class,
			NULL,
			device_context->dev_no,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
			NULL,
#endif
			DRIVER_NAME);
	if (IS_ERR(device_context->device_node)) {
		pr_err("[ERROR] Unable to create device node.\n");
		err = PTR_ERR(device_context->device_node);
		goto err_class_destroy;
	}

	/* Enumerate the device resources */
	if (ACPI_FAILURE(
		acpi_walk_resources(
			dev->handle,
			METHOD_NAME__CRS,
			b2071upg_acpi_resource,
			NULL)
		)) {
		pr_err("[ERROR] Unable to retrieve ACPI device resources.\n");
		err = -ENODEV;
		goto err_device_destroy;
	}

	/* Add the character device to the list of available interfaces */

	cdev_init(&device_context->cdev, &b2071upg_file_ops);
	device_context->cdev.owner = THIS_MODULE;
	device_context->cdev.ops = &b2071upg_file_ops;

	if (cdev_add(&device_context->cdev, device_context->dev_no, 1) != 0) {
		pr_err("[ERROR] Could not add cdev object.\n");
		err = -ENODEV;
	} else {
		/* Store the context in the device object */
		dev->driver_data = device_context;

		goto all_done;
	}

err_device_destroy:

	device_destroy(
		device_context->device_class,
		device_context->dev_no);

err_class_destroy:

	class_destroy(device_context->device_class);

err_free_chrdev_region:

	/* Free the major number we allocated during init */
	unregister_chrdev_region(device_context->dev_no, 1);

err_free_context:

	kfree(device_context);
	device_context = NULL;

all_done:

	pr_debug("<-- %s\n", __func__);

	return err;
}

/**
 * acpi_device_remove() - ACPI device de-registration function
 *
 * @dev:  ptr to the acpi device object
 * @type: the type of ACPI bus (only in kernel versions < 3.9)
 *
 * This function is called during execution of acpi_bus_unregister_driver.
 *
 * Return: 0 always
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
static int __exit acpi_device_remove(struct acpi_device *dev, int type)
#else
static int __exit acpi_device_remove(struct acpi_device *dev)
#endif
{
	struct b2071upg_device_context *device_context = acpi_driver_data(dev);

	pr_debug("--> %s\n", __func__);

	/* Delete the character device */
	cdev_del(&device_context->cdev);

	device_destroy(
		device_context->device_class,
		device_context->dev_no);

	class_destroy(device_context->device_class);

	/* Free the major number we allocated during init */
	unregister_chrdev_region(device_context->dev_no, 1);

	/* Free the device context */
	kfree(device_context);
	device_context = NULL;

	pr_debug("<-- %s\n", __func__);

	return 0;
}

/* Table of pnp device ids for this acpi device */
static struct acpi_device_id b2071upg_device_ids[] __initdata = {
	{B2071UPG_DEVICE_ID},
	{""}
};
MODULE_DEVICE_TABLE(acpi, b2071upg_device_ids);

/* ACPI Driver Description */
static struct acpi_driver acpi_driver =
{
	.name    = DRIVER_NAME,
	.class   = CLASS_NAME,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23))
	.ids     = b2071upg_device_ids,
#else
	.ids     = B2071UPG_DEVICE_ID,
#endif
	.ops     = {
		.add     = acpi_device_add,
		.remove  = acpi_device_remove,
	}
};

#endif /* VMKLNX */

/**
 * device_init() - Driver initialization function
 *
 * Return: 0 if successful, otherwise appropriate error value
 */
static int __init device_init(void)
{
	int err;

	pr_debug("--> %s\n", __func__);

	pr_info(
		"SEL(R) B2071 UPG Driver v%s\n",
		DRV_VERSION);

	pr_info("Copyright(c) 2014 Schweitzer Engineering Laboratories.\n");

#ifdef __VMKLNX__

	err = acpi_misc_device_add();

#else /* !defined(__VMKLNX__) */

	err = acpi_bus_register_driver(&acpi_driver);

#endif /* __VMKLNX__ */

	pr_debug("<-- %s\n", __func__);

	return err;
}
module_init(device_init);

/**
 * device_cleanup() - Driver cleanup function
 */
static void __exit device_cleanup(void)
{
	pr_debug("--> %s\n", __func__);

#ifdef __VMKLNX__

	acpi_misc_device_remove();

#else /* !defined(__VMKLNX__) */

	acpi_bus_unregister_driver(&acpi_driver);

#endif

	pr_debug("<-- %s\n", __func__);
}
module_exit(device_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Schweitzer Engineering Laboratories, Inc.");
MODULE_DESCRIPTION("SEL(R) B2071 Upgrade Driver");
MODULE_VERSION(DRV_VERSION);
