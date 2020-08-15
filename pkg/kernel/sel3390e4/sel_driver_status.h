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
 * SEL Driver Status Codes
 *****************************************************************************/
#ifndef SEL_DRIVER_STATUS_H_INCLUDED
#define SEL_DRIVER_STATUS_H_INCLUDED

typedef enum {
	SEL_STATUS_SUCCESS                 = 0,
	SEL_STATUS_ERROR_HARDWARE_ERROR    = -1,
	SEL_STATUS_INVALID_PARAMETER       = -2,
	SEL_STATUS_INTERNAL_ERROR          = -3,
	SEL_STATUS_INVALID_BUFFER_SIZE     = -4,
	SEL_STATUS_NOT_FOUND               = -5,
	SEL_STATUS_ACCESS_DENIED           = -6,
	SEL_STATUS_UNSUPPORTED             = -7,
	SEL_STATUS_OUT_OF_RESOURCES        = -8
} SEL_STATUS;

#define SEL_SUCCESS(status) (status >= SEL_STATUS_SUCCESS)

#endif /* SEL_DRIVER_STATUS_H_INCLUDED */
