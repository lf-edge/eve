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
 * Provides the ability to write the statically stored firmware image
 * to flash at a user defined address, or default address ,and also the
 * ability to read from r/w user storage
 ******************************************************************************
 */
#ifndef SEL_NOR_HW_CTRL_H_INCLUDED
#define SEL_NOR_HW_CTRL_H_INCLUDED

#include <linux/spinlock.h> /* locks */
#include <linux/types.h>    /* types */

/**
 * enum flash_image_section - flash image sections
 */
enum flash_image_section {
	FLASH_IMAGE_FUNCTIONAL,
	FLASH_RW
};

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
	);

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
	);

#endif /* SEL_NOR_HW_CTRL_H_INCLUDED */

