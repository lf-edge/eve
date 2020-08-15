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
 * Net Device Receive Operations
 ******************************************************************************
 */

#ifndef NETDEV_RX_H_INCLUDED
#define NETDEV_RX_H_INCLUDED

#include <linux/types.h> /* types */

#include "sel3390e4.h"   /* 3390 definitions */

/**
 * sel3390e4_rx_alloc_skb() - Allocate an SKB and DMA data buffer for an RXBD
 *
 * @mac: net device context
 * @idx: the index of the RXBD to manipulate
 *
 * This function assumes the rx_lock has been acquired.
 *
 * Return: 0 if successful, otherwise an appropriate negative error value
 */
int sel3390e4_rx_alloc_skb(struct sel3390e4_mac *mac, u16 idx);

/**
 * sel3390e4_free_receive_memory() - Free memory associated with the receive path
 *
 * @mac net device context
 *
 * This function should not be called from an atomic context.
 */
void sel3390e4_free_receive_memory(struct sel3390e4_mac *mac);

/**
 * sel3390e4_alloc_receive_memory() - Allocate memory associated with the receive path
 *
 * @mac net device context
 *
 * Callers of this function must eventually call sel3390e4_free_receive_memory in
 * order to free allocated memory.
 *
 * Return: 0 if successful, otherwise an appropriate negative error value
 */
int sel3390e4_alloc_receive_memory(struct sel3390e4_mac *mac);

/**
 * sel3390e4_rx_clean() - Loop through the rx ring and indicate received packets
 *
 * @mac:        net device context
 * @work_done:  the amount of packets indicated to the kernel
 * @work_to_do: the amount of packets to process
 *
 * In this function we indicate receive packets to the kernel, unmapping
 * memory created for data buffer memory, and re-creating that DMA memory
 * and skb memory for future receive packets. This functiono bails whenever
 * work_done >= work_to_do, or if there is no receive data to process.
 * This function can only be called from soft irq context.
 */
void sel3390e4_rx_clean(
	struct sel3390e4_mac *mac,
	int *work_done,
	int work_to_do);

#endif /* NETDEV_RX_H_INCLUDED */

