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
 **
 ** @brief 
 ** This file contains defines and structures for driver and application
 *****************************************************************************/

#ifndef B2071_API_H_INCLUDED
#define B2071_API_H_INCLUDED

#include <linux/types.h>

#pragma pack(1) /* Need API structures ordered the same in kernel/user-space */

/**
 * struct b2071_request_header - Global request header
 */
struct b2071_request_header {
	uint8_t function_code;
	uint16_t size;
};

/**
 * struct b2071_request - Read8 and Read32 Request API
 */
struct b2071_request {
	struct b2071_request_header header;
	uint16_t register_address;
};

/**
 * struct b2071_write8_request - Write8 Request API
 */
struct b2071_write8_request {
	struct b2071_request_header header;
	uint16_t register_address;
	uint8_t value;
	uint8_t mask;
};

/**
 * struct b2071_response_header - Global response header
 */
struct b2071_response_header  {
	uint8_t function_code;
	uint8_t error_code;
	uint16_t size;
};

/**
 * struct b2071_read8_response - Read8 Response API
 */
struct b2071_read8_response {
	struct b2071_response_header header;
	uint8_t data;
};

/**
 * struct b2071_read32_response - Read32 Response API
 */
struct b2071_read32_response {
	struct b2071_response_header header;
	uint32_t data;
};

#pragma pack()

/**
 * enum ec_function_codes - Function Codes
 */
enum ec_function_codes {
	FC_READ8       = 0x1,
	FC_READ32      = 0x2,
	FC_READ_DIAG   = 0x3,
	FC_WRITE8      = 0x4
};

/**
 * enum ec_register_offsets - Register Offsets
 */
enum ec_register_offsets {
	CONFIG_OFFSET  = 0x100,
	DIAG_OFFSET    = 0x200,
	IRIG_OFFSET    = 0x300,
	PS_DIAG_OFFSET = 0x400,
	MAX_ADDR       = 0x500
};

/**
 * enum sel_driver_error_code - driver error codes
 */
enum sel_driver_error_code {
	DRIVER_EC_SUCCESS          = 0,
	DRIVER_EC_INVALID_ADDR     = 1,
	DRIVER_EC_LPC_COMM_ERROR   = 2,
	DRIVER_EC_BAD_BUFFER_SIZE  = 3
};

/* Driver Error Macro */
#define DRIVER_ERROR(error_code) (error_code != DRIVER_EC_SUCCESS) 

#endif /* B2071_API_H_INCLUDED */

