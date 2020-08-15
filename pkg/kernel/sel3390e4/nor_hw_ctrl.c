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
 * ****************************************************************************
 *  Provides the ability to write the statically stored firmware image
 *  to flash at a user defined address, or default address ,and also the
 *  ability to read from r/w user storage
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h> /* kern-specific macros */
#include <linux/slab.h>   /* kmalloc, kzalloc */
#include <linux/types.h>  /* types */
#include <linux/spinlock.h> /* locks */

#include "flash.h"
#include "nor_hw_ctrl.h"
#include "sel_driver_status.h"

/**
 * dump_flash_rw_storage() - Reads data from flash r/w user storage
 *
 * @pci_bar_virtual: flash base address register
 * @given_offset:    The offset provided by the user to read from
 * @data:            the data read from the flash
 * @number_bytes:    the number of bytes to read, and the bytes actually read
 * @nvm_lock:        nvm_lock nor flash lock
 *
 * Return: 0 if successful, otherwise negative error code
 */
int dump_flash_rw_storage(
	u32 __iomem *pci_bar_virtual,
	u32 given_offset,
	u8 *data,
	u32 *number_bytes,
	spinlock_t *nvm_lock
	)
{
	SEL_STATUS status = SEL_STATUS_SUCCESS;
	u32 bytes_read = 0;
	FLASH_DESCRIPTION const *flash_device = NULL;
	unsigned long flags;

	pr_debug("--> %s\n", __func__);

	spin_lock_irqsave(nvm_lock, flags);

	/* Bail out if input parameter is incorrect */
	if ((data == NULL) || (number_bytes == NULL)) {
		status = SEL_STATUS_INVALID_PARAMETER;
		goto error_flash;
	}

	/* Initialize device timing, and find the flash part */
	status = flash_initialize_chip_timing(pci_bar_virtual, &flash_device);

	if (SEL_SUCCESS(status)) {
		/* Verify input address and bytes to read */
		u32 region_address =
			flash_device->flash_regions[
				flash_device->rw_settings].address;

		u32 region_length =
			flash_device->flash_regions[
				flash_device->rw_settings].length;

		if ((given_offset + *number_bytes) > region_length) {
			status = SEL_STATUS_INVALID_PARAMETER;
			goto error_flash;
		}

		/* Extract the data from flash */
		status =
			flash_read_data(
				pci_bar_virtual,
				data,
				(region_address + given_offset),
				*number_bytes,
				&bytes_read);

		if (SEL_SUCCESS(status)) {
			if (bytes_read != *number_bytes) {
				pr_debug("ERROR: Unable to read the proper amount from flash\n");
				status = SEL_STATUS_ERROR_HARDWARE_ERROR;
			}

			*number_bytes = bytes_read;
		}
	}

error_flash:

	spin_unlock_irqrestore(nvm_lock, flags);

	pr_debug("<-- %s\n", __func__);

	return SEL_SUCCESS(status) ? 0 : 1;
}

/**
 * dump_file_to_flash() - Writes a binary image to flash memory
 *
 * @pci_bar_virtual:  flash base address register
 * @image_to_write:   ptr to the data to write to flash
 * @image_size:       size of the image_to_write, in bytes
 * @number_bytes:     The number of bytes written to the flash
 * @nvm_lock:         nvm_lock nor flash lock
 *
 * Return: 0 if successful, otherwise negative error code
 */
int dump_file_to_flash(
	u32 *pci_bar_virtual,
	enum flash_image_section section_to_write,
	u8 const *image_to_write,
	u32 image_size,
	u32 *number_bytes,
	spinlock_t *nvm_lock
	)
{
	SEL_STATUS  status = SEL_STATUS_SUCCESS;
	u8 *image_read_from_flash = NULL;
	u32 bytes_read = 0;
	u32 bytes_written = 0;
	u32 start_address = 0;
	FLASH_DESCRIPTION const *flash_device = NULL;
	u32 i;
	u8 valid_region = 0;
	unsigned long flags;

	pr_debug("--> %s\n", __func__);

	spin_lock_irqsave(nvm_lock, flags);

	/* Bail out if invalid parameter given. */
	if (number_bytes == NULL) {
		status = SEL_STATUS_INVALID_PARAMETER;
		goto error_exit;
	}

	*number_bytes = 0;

	/* Find the flash part */
	status = flash_initialize_chip_timing(pci_bar_virtual, &flash_device);

	if (!SEL_SUCCESS(status)) {
		goto error_exit;
	} else {
		/* Validate the input flash region */

		switch(section_to_write)
		{
		case FLASH_IMAGE_FUNCTIONAL:
			if (flash_device->functional_image != MAX_NUM_FLASH_REGIONS) {
				start_address = 
					flash_device->flash_regions[
						flash_device->functional_image].address;

				valid_region = 1;
			}

			break;

		case FLASH_RW:
			if (flash_device->rw_settings != MAX_NUM_FLASH_REGIONS) {
				start_address = 
					flash_device->flash_regions[
						flash_device->rw_settings].address;

				valid_region = 1;
			}

			break;

		default:
			break;
		}

		if (!valid_region) {
			/* An invalid flash region was selected, so fail the request */
			status = SEL_STATUS_INVALID_PARAMETER;
			goto error_exit;
		}
	}

	/* Erase the section we plan to write to
	 * Note: This will erase full erase blocks/sectors
	 * which will likely erase
	 * MORE data than the image_size.  It's YOUR responsibility to make
	 * sure you aren't erasing data in an area in use.
	 */

	status = flash_erase_data(pci_bar_virtual, start_address, image_size);

	if (!SEL_SUCCESS(status)) {
		goto error_exit;
	}

	pr_debug("Preparing to write %d byte image\n", image_size);

	/* Write the image to flash */
	status = flash_write_data(
		pci_bar_virtual,
		(u8 *)image_to_write,
		start_address,
		image_size,
		&bytes_written
		);

	pr_debug(
		"Done writing %d byte image."
		"%d bytes actually written\n",
		image_size, bytes_written);

	if (!SEL_SUCCESS(status)) {
		goto error_exit;
	}

	/* Verify the correct amount of bytes were actually written */
	if (bytes_written != image_size) {
		status = SEL_STATUS_INTERNAL_ERROR;

		pr_debug("ERROR: Unable to write the proper amount to flash\n");

		goto error_exit;
	}

	/* Allocate a buffer to read data into */
	image_read_from_flash = kzalloc(image_size, GFP_KERNEL);

	if (image_read_from_flash == NULL) {
		status = SEL_STATUS_OUT_OF_RESOURCES;
		goto error_exit;
	}

	/* Pull the image back out of flash for verification */
	status = flash_read_data(
		pci_bar_virtual,
		image_read_from_flash,
		start_address,
		image_size,
		&bytes_read
		);

	if (!SEL_SUCCESS(status)) {
		goto error_exit;
	}

	/* Verify we read the amount of data we wrote */
	if (bytes_read != image_size) {
		status = SEL_STATUS_INTERNAL_ERROR;

		pr_debug("ERROR: Unable to read the proper amount from flash\n");

		goto error_exit;
	}

	/* Read back and verify the binary file we just wrote; that every byte matches */

	BUG_ON(image_read_from_flash == NULL);

	for (i = 0; i < image_size; ++i) {
		if (*(image_to_write+i) != *(image_read_from_flash+i)) {
			pr_debug(
				"ERROR: Validation failed.  The data at position %d "
				"in NOR flash doesn't match the input file!\n",
				i);

			pr_debug(
				"FlashByte: 0x%x FileByte: 0x%x\n",
				*(image_read_from_flash+i),
				*(image_to_write+i));

			status = SEL_STATUS_INTERNAL_ERROR;
			break;
		}
	}

	if (SEL_SUCCESS(status)) {
		/* Return the number of bytes written to the flash */
		*number_bytes = bytes_written;
	}

error_exit:

	/* Free the memory allocated when the image was read from flash */
	if (NULL != image_read_from_flash) {
		kfree(image_read_from_flash);
		image_read_from_flash = NULL;
	}

	spin_unlock_irqrestore(nvm_lock, flags);

	pr_debug("<-- %s\n", __func__);

	return SEL_SUCCESS(status) ? 0 : -1;
}

