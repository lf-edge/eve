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
 ** This file provides access to the b2071 embedded controller
 *****************************************************************************/

#ifndef B2071_EC_H_INCLUDED
#define B2071_EC_H_INCLUDED

#include <linux/types.h>

static uint16_t const DATA_REGISTER_ADDRESS  = 0x192;
static uint16_t const COMMAND_STATUS_ADDRESS = 0x193;

/**
 * enum interface_states - LPC Interface States (S0 & S1 bits)
 */
enum interface_states {
	LPC_IDLE  = 0,
	LPC_WRITE = 1,
	LPC_READ  = 2,
	LPC_ERROR = 3
};

#define EC_STATUS_IBF(status)   (((status) >> 0x1) & 0x1)
#define EC_STATUS_OBF(status)   (((status) & 0x1))
#define EC_STATUS_BUSY(status)  (((status) >> 0x4) & 0x1)
#define EC_STATUS_STATE(status) ((enum interface_states)(((status) >> 0x6) & 0x3))

/**
 * enum lpc_commands - LPC Commands
 */
enum lpc_commands {
	WRITE_CONFIG      = 0x10,
	WRITE_DIAG        = 0x11,
	WRITE_IRIG        = 0x12,
	WRITE_PS_DIAG     = 0x13,
	ABORT             = 0x0,
	READ_CONFIG       = 0x20,
	READ_DIAG         = 0x21,
	READ_IRIG         = 0x22,
	READ_PS_DIAG      = 0x23,
	READ_CONT_OFFSET  = 0x20,
	READCONTEND       = 0x60
};

/**
 * ec_io_protocol_write() - Write 1 byte of data to the EC
 *
 * @address: Address to write the data to
 * @buffer:  Buffer holding the data to be sent
 *
 * This method must be protected with a lock, as concurrent ec reads/writes
 * cause unexpected behavior. 
 *
 * Return: 
 *  DRIVER_EC_SUCCESS,
 *  DRIVER_EC_LPC_COMM_ERROR,
 *  DRIVER_EC_INVALID_ADDR
 */
enum sel_driver_error_code ec_io_protocol_write(
	uint32_t address,
	uint8_t  buffer
	);

/**
 * ec_io_protocol_read() - Read 1 or more bytes of data from the EC
 *
 * @address:     Address to read the data from
 * @buffer:      Buffer holding the data to be rececived
 * @buffer_size: size of the input buffer in bytes
 * @bytes:       number of bytes to read from the EC
 *
 * This method must be protected with a lock, as concurrent ec reads/writes
 * cause unexpected behavior.
 *
 * Return:
 *  DRIVER_EC_SUCCESS,
 *  DRIVER_EC_LPC_COMM_ERROR,
 *  DRIVER_EC_INVALID_ADDR
 */
enum sel_driver_error_code ec_io_protocol_read(
	uint32_t address,
	void *buffer,
	uint8_t buffer_size,
	uint8_t bytes
	);

#endif /* B2071_EC_H_INCLUDED */

