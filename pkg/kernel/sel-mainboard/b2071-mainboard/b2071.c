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
 ** b2071 mainboard driver
 *****************************************************************************/

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>  /* printk, pr...etc */
#include <linux/module.h>  /* required */

#include <asm/uaccess.h>   /* user access functions (copy_*_user) */
#include <linux/device.h>  /* dev_err */
#include <linux/fs.h>      /* character driver registration and file operations */
#include <linux/cdev.h>    /* character device */
#include <linux/init.h>    /* init/exit macros */
#include <linux/types.h>   /* std types */
#include <linux/slab.h>    /* kzalloc, kmalloc */
#include <linux/version.h> /* linux version */
#include <linux/errno.h>   /* error codes */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))

#ifndef pr_err
	#define pr_err(fmt, arg...) printk(KERN_ERR fmt, ##arg)
#endif

#endif /* KERNEL_VERSION(2,6,24) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26))
	#include <linux/semaphore.h>
#else
	#include <asm/semaphore.h>
#endif

#ifdef __VMKLNX__
	#include <linux/miscdevice.h>  /* miscdevice registration */

	/* Global device context */
	struct b2071_device_context *g_b2071_device_context;
#else /* !defined(__VMKLNX__) */
	#include <linux/acpi.h>        /* acpi related items */
	#include <acpi/acpi_bus.h>     /* acpi registration */
#endif /* __VMKLNX__ */

#include "b2071.h"             /* device context */
#include "b2071_api.h"         /* user api */
#include "b2071_ec.h"          /* ec operations */

/* Driver Version Number */
#define DRV_VERSION "1.0.49152.76"

#define DRIVER_NAME "selb2071"
#define CLASS_NAME "selb2071"
#define B2071_DEVICE_ID "SEL0002"

/**
 * b2071_read() - User space request to read driver data
 *
 * @filp:  open kernel file descriptor
 * @buff:  user output buffer
 * @count: number of bytes to read
 * @offp:  file position to access
 *
 * Return: the number of bytes read, or an appropriate negative error value
 */
static ssize_t b2071_read(
	struct file *filp,
	char __user *buff,
	size_t count,
	loff_t *offp
	)
{
	ssize_t err = count;
	void* output_buffer = NULL;
	struct b2071_read8_response output_buffer_8;
	struct b2071_read32_response output_buffer_32;
	struct b2071_response_header output_buffer_response;
	struct b2071_file_context *file_context = filp->private_data;
	uint8_t error_code = file_context->error_code;

	pr_debug("--> %s\n", __func__);

	if (count == 0)
	{
		return count;
	}

	/* As explained in the struct definition, we use a semaphore here as 
	 * semaphores allow processes to sleep if they cannot obtain the lock. This
	 * is appropriate here as the function is called from user context. We'd like
	 * to relinquish the processor to other useful jobs if the semaphore cannot
	 * be obtained. */

	if (down_interruptible(&file_context->device_context->read_write_semaphore)) {
		return -ERESTARTSYS;
	}

	switch (file_context->function_code) {
	case FC_READ8: /* read8 */

		/* Verify the count */
		if (count != sizeof(struct b2071_read8_response)) {
			err = -ENOBUFS;
			break;
		}

		output_buffer_8.header.function_code = file_context->function_code;
		output_buffer_8.header.error_code = error_code;
		output_buffer_8.header.size = sizeof(uint8_t);
		output_buffer_8.data = (uint8_t)file_context->data;
		output_buffer = &output_buffer_8;
		break;

	case FC_READ32: /* read32 */

		/* Verify the count */
		if (count != sizeof(struct b2071_read32_response)) {
			err = -ENOBUFS;
			break;
		}

		output_buffer_32.header.function_code = file_context->function_code;
		output_buffer_32.header.error_code = error_code;
		output_buffer_32.header.size = sizeof(uint32_t);
		output_buffer_32.data = file_context->data;
		output_buffer = &output_buffer_32;

		break;

	case FC_WRITE8: /* write8 */

		/* Verify the count */
		if (count != sizeof(struct b2071_response_header)) {
			err = -ENOBUFS;
			break;
		}

		output_buffer_response.function_code = file_context->function_code;
		output_buffer_response.error_code = error_code;
		output_buffer_response.size = 0;
		output_buffer = &output_buffer_response;

		break;

	default:
		err = -EINVAL;
		break;
	}

	up(&file_context->device_context->read_write_semaphore);

	if (err == count) {
		if (copy_to_user(buff, output_buffer, count) != 0) {
			err = -ENOBUFS;
		}
	}

	pr_debug("<-- %s\n", __func__);

	return err;
}

/**
 * b2071_write() - User space request to write driver data
 *
 * @filp:  open kernel file descriptor
 * @buff:  user input buffer
 * @count: number of bytes to write
 * @offp:  file position to access
 *
 * Return: the number of bytes written, or an appropriate negative error value
 */
static ssize_t b2071_write(
	struct file *filp,
	const char __user *buff,
	size_t count,
	loff_t *offp
	)
{
	ssize_t err = count;

	union {
		struct b2071_request_header header;
		struct b2071_write8_request application_write8_request;
		struct b2071_request application_read_request;
	} request;

	uint32_t read_data_size;
	uint8_t temp_data;
	struct b2071_file_context* file_context = filp->private_data;

	pr_debug("--> %s\n", __func__);

	if (count == 0) {
		return 0;
	}

	if ((count > sizeof(request)) || (copy_from_user(&request, buff, count) != 0)) {
		return -ENOMEM;
	}

	/* As explained in the struct definition, we use a semaphore here as 
	 * semaphores allow processes to sleep if they cannot obtain the lock. This
	 * is appropriate here as the function is called from user context. We'd like
	 * to relinquish the processor to other useful jobs if the semaphore cannot
	 * be obtained. */

	if (down_interruptible(&file_context->device_context->read_write_semaphore)) {
		return -ERESTARTSYS;
	}

	switch(request.header.function_code) {
	case FC_READ8:    /* Read_8 Request */
	case FC_READ32:   /* Read_32 Request */

		if ((count != sizeof(struct b2071_request))) {
			err = -ENOBUFS;
			break;
		} 
		
		file_context->function_code = request.header.function_code;

		if (request.application_read_request.register_address >= MAX_ADDR) {
			pr_err("[ERROR] Invalid register_address in read request.\n");
			file_context->data = 0x0;
			file_context->error_code = DRIVER_EC_INVALID_ADDR;
			err = -EINVAL;
		} else {
			/* Clear data and read new data */

			read_data_size = (request.header.function_code == FC_READ8)
				? sizeof(uint8_t) : sizeof(uint32_t);

			file_context->data = 0x0;
			file_context->error_code =
				(uint8_t)ec_io_protocol_read(
					request.application_read_request.register_address,
					&file_context->data,
					sizeof(file_context->data),
					read_data_size);
		}

		break;

	case FC_WRITE8: /* Write_8 Request */

		if ((count != sizeof(struct b2071_write8_request))) {
			err = -ENOBUFS;
			break;
		}

		file_context->function_code = request.header.function_code;

		if (request.application_write8_request.register_address >= MAX_ADDR) {
			pr_err("[ERROR] Invalid register_address in write request.\n");
			file_context->data = 0x0;
			file_context->error_code = DRIVER_EC_INVALID_ADDR;
			err = -EINVAL;
		} else {
			/* Only change bits requested, represented by supplied mask */

			file_context->error_code =
				(uint8_t)ec_io_protocol_read(
					request.application_write8_request.register_address,
					&temp_data,
					sizeof(temp_data),
					sizeof(temp_data));

			if (file_context->error_code == DRIVER_EC_SUCCESS) {
				temp_data =
					(temp_data & ~request.application_write8_request.mask) |
					(request.application_write8_request.value &
					request.application_write8_request.mask);

				file_context->error_code =
					(uint8_t)ec_io_protocol_write(
						request.application_write8_request.register_address,
						temp_data);
			}
		}

		break;

	default:
		err = -EINVAL;
		break;

	}

	up(&file_context->device_context->read_write_semaphore);

	pr_debug("<-- %s\n", __func__);

	return err;
}

/**
 * b2071_close() - Closes a handle to the driver
 *
 * @inode: kernel internal file descriptor
 * @filp:  open kernel file descriptor
 *
 * Return: 0 always
 */
static int b2071_close(struct inode *inode, struct file *filp)
{
	pr_debug("--> %s\n", __func__);

	/* Free the file context */
	kfree(filp->private_data);
	filp->private_data = NULL;

	pr_debug("<-- %s\n", __func__);

	return 0;
}

/**
 * b2071_open() - Opens a handle to the driver
 *
 * @inode: kernel internal file descriptor
 * @filp:  open kernel file descriptor
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
static int b2071_open(struct inode *inode, struct file *filp)
{
	struct b2071_file_context *file_context;

#ifdef __VMKLNX__
	struct b2071_device_context *device_context = g_b2071_device_context;
#else
	struct b2071_device_context *device_context =
		container_of(inode->i_cdev, struct b2071_device_context, cdev);
#endif

	pr_debug("--> %s\n", __func__);

	/* Allocate file context area */

	file_context =
		kzalloc(sizeof(struct b2071_file_context), GFP_KERNEL);

	if (file_context == NULL) {
		pr_err("[ERROR] Unable to allocate file context.");
		return -ENOMEM;
	}

	file_context->device_context = device_context;
	filp->private_data = file_context;

	pr_debug("<-- %s\n", __func__);

	return 0;
}

/* struct b2071_file_ops - File operations structure */
static struct file_operations b2071_file_ops = {
	.owner   = THIS_MODULE,
	.read    = b2071_read,
	.write   = b2071_write,
	.open    = b2071_open,
	.release = b2071_close
};

#ifdef __VMKLNX__

/**
 * acpi_misc_device_add() - ACPI device registration function
 *
 * This function is called during execution of acpi_bus_register_driver.
 *
 * Return: 0 if successful, otherwise an appropriate error code (negative)
 */
static int __init acpi_misc_device_add(void)
{
	int err = 0;
	struct b2071_device_context *device_context = NULL;

	pr_debug("--> %s\n", __func__);

	/* Try to allocate private data struct */
	device_context =
		kzalloc(sizeof(struct b2071_device_context), GFP_KERNEL);

	if (device_context == NULL) {
		pr_err("[ERROR] Unable to allocate device context.");
		return -ENOMEM;
	}

	/* Initialize the semapahore */
#ifndef init_MUTEX
	sema_init(&device_context->read_write_semaphore, 1);
#else
	init_MUTEX(&device_context->read_write_semaphore);
#endif /* init_MUTEX */

	/* Set up the misc device. Under VMware, the character device
	 * source files don't seem to be available, so the linking fails.
	 * Thus, we use a misc device which esentially does the same thing
	 * as a character device. */

	device_context->misc_device.minor = MISC_DYNAMIC_MINOR;
	device_context->misc_device.name = DRIVER_NAME;
	device_context->misc_device.fops = &b2071_file_ops;

	if (misc_register(&device_context->misc_device)) {
		pr_err("[ERROR] Unable to register misc device.\n");
		kfree(device_context);
		device_context = NULL;
		err = -ENOMEM;
	} else {
		pr_info("Misc Device registered with minor # %d\n",
			device_context->misc_device.minor);

		/* Store the context */
		g_b2071_device_context = device_context;
	}

	pr_debug("<-- %s\n", __func__);

	return err;
}

/**
 * acpi_misc_device_remove() - ACPI device de-registration function
 *
 * @dev: ptr to the device object
 *
 * This function is called during execution of acpi_bus_unregister_driver.
 *
 * Return: always 0
 */
static void __exit acpi_misc_device_remove(void)
{
	struct b2071_device_context *device_context = g_b2071_device_context;

	pr_debug("--> %s\n", __func__);

	/* unregister misc device */
	misc_deregister(&device_context->misc_device);

	/* Free the device context */
	kfree(device_context);
	device_context = NULL;

	pr_debug("<-- %s\n", __func__);
}

#else // !defined(__VMKLNX__)

/**
 * b2071_acpi_resource() - ACPI Resource Enumeration function
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
static acpi_status __init b2071_acpi_resource(
	struct acpi_resource* resource,
	void* context
	)
{
	static int data_reg_found = 0;
	acpi_status retval = AE_OK;

	pr_debug("--> %s\n", __func__);

	if (resource == NULL) {
		return AE_ERROR;
	}

	switch (resource->type) {
	case ACPI_RESOURCE_TYPE_IO:
		/* The first address region returned is the data port, and
		 * the second address returned is the status port */

		retval = (resource->data.io.minimum == DATA_REGISTER_ADDRESS)
			? AE_OK : AE_ERROR;

		data_reg_found = (retval == AE_OK);

		break;

	case ACPI_RESOURCE_TYPE_END_TAG:
		if (data_reg_found) {
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
 * @dev: ptr to the device object
 *
 * This function is called during execution of acpi_bus_register_driver.
 *
 * Return: 0 if successful, otherwise an appropriate error code (negative)
 */
static int __init acpi_device_add(struct acpi_device* dev)
{
	int err = 0;
	struct b2071_device_context *device_context = NULL;

	pr_debug("--> %s\n", __func__);

	/* Try to allocate private data struct */
	device_context =
		kzalloc(sizeof(struct b2071_device_context), GFP_KERNEL);

	if (device_context == NULL) {
		pr_err("[ERROR] Unable to allocate device context.");
		return -ENOMEM;
	}

	/* Initialize the semapahore */
#ifndef init_MUTEX
	sema_init(&device_context->read_write_semaphore, 1);
#else
	init_MUTEX(&device_context->read_write_semaphore);
#endif /* init_MUTEX */

	/* Dynamically allocate a major number for this device */
	if (alloc_chrdev_region(&device_context->dev_no, 0, 1, DRIVER_NAME) != 0) {
		pr_err("[ERROR] Unable to allocate character device.\n");
		err = -ENODEV;
		goto err_free_context;
	}

	/* Store the acpi_device object */
	device_context->pdev = dev;

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
		pr_err("[ERROR] Unable to create device node\n");
		err = PTR_ERR(device_context->device_node);
		goto err_class_destroy;
	}

	/* Enumerate the device resources */
	if (ACPI_FAILURE(
		acpi_walk_resources(
			dev->handle,
			METHOD_NAME__CRS,
			b2071_acpi_resource,
			NULL)
		)) {
		pr_err("[ERROR] Unable to retrieve ACPI device resources.\n");
		err = -ENODEV;
		goto err_device_destroy;
	}

	/* Add the character device to the list of available interfaces */

	cdev_init(&device_context->cdev, &b2071_file_ops);
	device_context->cdev.owner = THIS_MODULE;
	device_context->cdev.ops = &b2071_file_ops;

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
 * ACPI device de-registration function
 *
 * @dev:  ptr to the device object
 * @type: acpi device type (only in kernel versions < 3.9)
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
	struct b2071_device_context *device_context = acpi_driver_data(dev);

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

/* struct b2071_device_ids - Table of pnp device ids for this acpi device */
static struct acpi_device_id b2071_device_ids[] __initdata = {
	{B2071_DEVICE_ID},
	{""}
};
MODULE_DEVICE_TABLE(acpi, b2071_device_ids);

/* struct acpi_driver - ACPI Driver Description */
static struct acpi_driver acpi_driver = {
	.name    = DRIVER_NAME,
	.class   = CLASS_NAME,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23))
	.ids     = b2071_device_ids,
#else
	.ids     = B2071_DEVICE_ID,
#endif
	.ops     = {
		.add     = acpi_device_add,
		.remove  = acpi_device_remove,
	}
};

#endif // defined(__VMKLNX__)

/**
 * b2071_module_init() - Driver initialization function
 *
 * Return: 0 if successful, otherwise appropriate error value
 */
static int __init b2071_module_init(void)
{
	int err;

	pr_debug("--> %s\n", __func__);

	pr_info(
		"SEL(R) B2071 Driver v%s\n",
		DRV_VERSION);

	pr_info("Copyright(c) 2014 Schweitzer Engineering Laboratories, Inc.\n");

#ifdef __VMKLNX__

	err = acpi_misc_device_add();

#else /* !defined(__VMKLNX__) */

	err = acpi_bus_register_driver(&acpi_driver);

#endif /* __VMKLNX__ */

	pr_debug("<-- %s\n", __func__);

	return err;
}
module_init(b2071_module_init);

/**
 * b2071_module_cleanup() - Driver cleanup function
 */
static void __exit b2071_module_cleanup(void)
{
	pr_debug("--> %s\n", __func__);

#ifdef __VMKLNX__

	acpi_misc_device_remove();

#else /* !defined(__VMKLNX__) */

	acpi_bus_unregister_driver(&acpi_driver);

#endif

	pr_debug("<-- %s\n", __func__);
}
module_exit(b2071_module_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Schweitzer Engineering Laboratories, Inc.");
MODULE_DESCRIPTION("SEL(R) B2071 mainboard driver");
MODULE_VERSION(DRV_VERSION);
