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

#if (!defined(pr_fmt) && defined(__KERNEL__))
	#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>  /* printk, pr...etc */
#include <linux/module.h>  /* required */

#include <asm/io.h>        /* outb, inb, etc. */
#include <linux/types.h>   /* std types */
#include <linux/delay.h>   /* delays */

#include "b2071_api.h"     /* user api */
#include "b2071_ec.h"      /* ec operations */

/* # of retries before error is returned */
uint8_t const SEL_EC_RETRIES = 50U;

/* # of microseconds to sleep during a wait */
uint8_t const SEL_EC_WAIT_US = 10U;

/**
 * ec_wait() - Wait on input buffer flag to clear
 *
 * Return value only needs to be checked after writing a command
 * other than ABORT. When the IBF and BUS bits in the command/status
 * register become zero, the WAIT state can be exited.
 *
 * Return:
 *  DRIVER_EC_SUCCESS,
 *  DRIVER_EC_LPC_COMM_ERROR
 */
static enum sel_driver_error_code ec_wait(void)
{
	/* Define the registers that need to be checked
	 * while in the wait state */

	uint8_t status = 0x0;
	uint32_t timeout = 0;
	enum sel_driver_error_code error_code = DRIVER_EC_LPC_COMM_ERROR;

	pr_debug("--> %s\n", __func__);

	while (timeout < SEL_EC_RETRIES) {
		status = inb(COMMAND_STATUS_ADDRESS);

		if ((EC_STATUS_IBF(status) == 0x0) &&
			(EC_STATUS_BUSY(status) == 0x0) &&
			(EC_STATUS_STATE(status) != LPC_ERROR)) {
			error_code = DRIVER_EC_SUCCESS;
			break;
		}

		pr_debug("STATUS: 0x%x\n", status);

		/* Sleep to allow hardware to process information
		 * before reading again */
		udelay(SEL_EC_WAIT_US);
		++timeout;
	}

	/* If an error occurred, store the error code */
	if ((error_code != DRIVER_EC_SUCCESS) ||
		(EC_STATUS_STATE(status) == LPC_ERROR)) {
		pr_debug("Error waiting. Error Code: %d State: %d\n",
			error_code, EC_STATUS_STATE(status));
		error_code = DRIVER_EC_LPC_COMM_ERROR;
	}

	pr_debug("<-- %s\n", __func__);

	return error_code;
}

/**
 * ec_receive_data() - Receive data from the EC
 *
 * @return_value: returned data
 *
 * Return:
 *  DRIVER_EC_SUCCESS,
 *  DRIVER_EC_LPC_COMM_ERROR
 */
static enum sel_driver_error_code ec_receive_data(uint8_t* return_value)
{
	uint8_t status = 0;
	enum sel_driver_error_code error_code = DRIVER_EC_LPC_COMM_ERROR;
	uint32_t timeout = 0;

	pr_debug("--> %s\n", __func__);

	/* Wait for Output Buffer Flag to be set, representing new data available
	 * or fail if timeout */
	while (timeout < SEL_EC_RETRIES) {
		status = inb(COMMAND_STATUS_ADDRESS);

		/* Stop waiting if OBF is set (new data available) */
		if (EC_STATUS_OBF(status) == 1) {
			error_code = DRIVER_EC_SUCCESS;
			break;
		}

		/* Sleep before trying to read OBF again */
		udelay(SEL_EC_WAIT_US);
		++timeout;
	}

	/* Read 1 byte of data */
	if (!DRIVER_ERROR(error_code)) {
		*return_value = inb(DATA_REGISTER_ADDRESS);
		pr_debug("Data read: 0x%x\n", *return_value);
	} else {
		pr_debug("OBF Flag Check Fail - OBF: 0x%x\n",
			EC_STATUS_OBF(status));
	}

	pr_debug("<-- %s\n", __func__);

	return error_code;
}

/**
 * ec_abort() - Abort any pending LPC command
 *
 * Return:
 *  DRIVER_EC_SUCCESS,
 *  DRIVER_EC_LPC_COMM_ERROR
 */
static enum sel_driver_error_code ec_abort(void)
{
	enum sel_driver_error_code retval = DRIVER_EC_SUCCESS;
	uint8_t status;

	pr_debug("--> %s\n", __func__);

	status = inb(COMMAND_STATUS_ADDRESS);

	if (EC_STATUS_STATE(status) != LPC_IDLE) {
		pr_debug("Writing command 0x%x to port 0x%x\n",
			ABORT, COMMAND_STATUS_ADDRESS);

		outb((uint8_t)ABORT, COMMAND_STATUS_ADDRESS);

		retval = ec_wait();
	}

	pr_debug("<-- %s\n", __func__);

	return retval;
}

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
	)
{
	uint8_t register_address = 0;
	enum sel_driver_error_code status = DRIVER_EC_SUCCESS;

	pr_debug("--> %s\n", __func__);

	/* Abort pending ops and wait for interface to become idle */
	if (DRIVER_ERROR(ec_abort())) {
		return DRIVER_EC_LPC_COMM_ERROR;
	}

	if (address < DIAG_OFFSET) { /* Config Register */
		pr_debug("Writing command 0x%x to port 0x%x\n",
			WRITE_CONFIG, COMMAND_STATUS_ADDRESS);

		outb((uint8_t)WRITE_CONFIG, COMMAND_STATUS_ADDRESS);

		register_address = (uint8_t)(address - CONFIG_OFFSET);
	} else if (address < IRIG_OFFSET) { /* Diag Register */
		pr_debug("Writing command 0x%x to port 0x%x\n",
			WRITE_DIAG, COMMAND_STATUS_ADDRESS);

		outb((uint8_t)WRITE_DIAG, COMMAND_STATUS_ADDRESS);

		register_address = (uint8_t)(address - DIAG_OFFSET);
	} else if (address < PS_DIAG_OFFSET) { /* Irig Register */
		pr_debug("Writing command 0x%x to port 0x%x\n",
			WRITE_IRIG, COMMAND_STATUS_ADDRESS);

		outb((uint8_t)WRITE_IRIG, COMMAND_STATUS_ADDRESS);

		register_address = (uint8_t)(address - IRIG_OFFSET);
	} else if (address < MAX_ADDR) { /* Power Supply Register */
		pr_debug("Writing command 0x%x to port 0x%x\n",
			WRITE_PS_DIAG, COMMAND_STATUS_ADDRESS);

		outb((uint8_t)WRITE_PS_DIAG, COMMAND_STATUS_ADDRESS);

		register_address = (uint8_t)(address - PS_DIAG_OFFSET);
	} else { /* Invalid address */
		pr_debug("Attempting to write to invalid address: 0x%x\n", address);
		status = DRIVER_EC_INVALID_ADDR;
	}

	/* Now that CMD has been written, we need to specify the address and data */
	if (!DRIVER_ERROR(status)) {

		/* Wait for interface to become idle */
		status = ec_wait();
		
		if (!DRIVER_ERROR(status)) {

			// Write the address

			pr_debug("Writing data 0x%x to port 0x%x\n",
				register_address, DATA_REGISTER_ADDRESS);

			outb(register_address, DATA_REGISTER_ADDRESS);

			/* Wait for interface to become idle */
			status = ec_wait();

			if (!DRIVER_ERROR(status)) {
				/* Write the data */

				pr_debug("Writing data 0x%x to port 0x%x\n",
				buffer, DATA_REGISTER_ADDRESS);

				outb(buffer, DATA_REGISTER_ADDRESS);

				/* Wait for interface to become idle */
				status = ec_wait();
			}
		}
	}

	pr_debug("<-- %s\n", __func__);

	return status;
}

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
	)
{
	enum sel_driver_error_code status = DRIVER_EC_LPC_COMM_ERROR;
	uint8_t command = 0;
	uint8_t reg_address = 0;
	uint8_t bytes_read = 0;
	uint8_t continuous_read = 0;

	pr_debug("--> %s\n", __func__);

	/* Abort pending ops and wait for interface to become idle */
	if (DRIVER_ERROR(ec_abort())) {
		return status;
	}

	/* Make sure the buffer is big enough */
	if (buffer_size >= bytes) {
		if (address < DIAG_OFFSET) { /* Config Register */
			command = READ_CONFIG;
			reg_address = (uint8_t)(address - CONFIG_OFFSET);
			status = DRIVER_EC_SUCCESS;
		} else if (address < IRIG_OFFSET){ /* Diag Register */
			command = READ_DIAG;
			reg_address = (uint8_t)(address - DIAG_OFFSET);
			status = DRIVER_EC_SUCCESS;
		} else if (address < PS_DIAG_OFFSET) { /* Irig Register */
			command = READ_IRIG;
			reg_address = (uint8_t)(address - IRIG_OFFSET);
			status = DRIVER_EC_SUCCESS;
		} else if (address < MAX_ADDR) { /* Power Supply Register */
			command = READ_PS_DIAG;
			reg_address = (uint8_t)(address - PS_DIAG_OFFSET);
			status = DRIVER_EC_SUCCESS;
		} else { /* Invalid address */
			pr_debug("Attempting to read invalid address: 0x%x\n", address);
			status = DRIVER_EC_INVALID_ADDR;
		}

		/* Make sure address + bytes doesn't exceed length of register */
		if (((uint32_t)reg_address + bytes - 1) > 0xFF) {
			status = DRIVER_EC_INVALID_ADDR;
		}

		if (!DRIVER_ERROR (status)) {
			/* A request for more than 1 byte will start a continuous read */
			if (bytes > 1) {
				continuous_read = 1;
				command += READ_CONT_OFFSET;
			}

			/* Send the command */

			pr_debug("Writing command 0x%x to port 0x%x\n",
				command, COMMAND_STATUS_ADDRESS);

			outb((uint8_t)command, COMMAND_STATUS_ADDRESS);

			status = ec_wait();

			/* Write the address  */

			if (!DRIVER_ERROR(status)) {
				pr_debug("Writing data 0x%x to port 0x%x\n",
					reg_address, DATA_REGISTER_ADDRESS);

				outb(reg_address, DATA_REGISTER_ADDRESS);

				status = ec_wait();
			}

			/* Fill up the read buffer */
			while (!DRIVER_ERROR(status) && (bytes_read < bytes)) {
				/* Read the data */
				status = ec_receive_data((uint8_t*)buffer + bytes_read);

				if (!DRIVER_ERROR(status)) {
					++bytes_read;

					/* Get more data if this is a continuous read */

					if (continuous_read && (bytes_read < bytes)) {
						pr_debug("Writing command 0x%x to port 0x%x\n",
							command, COMMAND_STATUS_ADDRESS);

						outb((uint8_t)command, COMMAND_STATUS_ADDRESS);

						status = ec_wait();
					}
				}
			}

			if (!DRIVER_ERROR(status) &&
				continuous_read &&  (bytes_read == bytes)) {
				/* Send the command to end a continuous read */

				command = READCONTEND;

				pr_debug("Writing command 0x%x to port 0x%x\n",
					command, COMMAND_STATUS_ADDRESS);

				outb((uint8_t)command, COMMAND_STATUS_ADDRESS);

				status = ec_wait();
			}
		}
	} else {
		status = DRIVER_EC_BAD_BUFFER_SIZE;
	}

	pr_debug("<-- %s\n", __func__);

	return status;
}

