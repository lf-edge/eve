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
 ** This is the general include file for the b2071 driver
 *****************************************************************************/

#ifndef B2071_H_INCLUDED
#define B2071_H_INCLUDED

#include <linux/types.h>

#ifdef __VMKLNX__
	#include <linux/miscdevice.h>
#else
	#include <linux/device.h>
	#include <linux/acpi.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26))
	#include <linux/semaphore.h>
#else
	#include <asm/semaphore.h>
#endif

/**
 * struct b2071_device_context - Device Private Context Area
 */
struct b2071_device_context {

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

	/* semaphore used to serialize read/write file and EC operations. 
	 * This lock MUST be acquired prior to any EC read or write operations. */
	struct semaphore read_write_semaphore; 
};

/**
 * struct b2071_file_context - File Private Context Area
 */
struct b2071_file_context {

	/* desired device access */
	uint8_t function_code;

	/* data to pass to device */
	uint32_t data;

	/* error code from last read/write operation */
	uint8_t error_code;

	/* ptr to device context */
	struct b2071_device_context* device_context;
};

#endif /* B2071_H_INCLUDED */
