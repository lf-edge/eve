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
 * Net Device Transmit Operations
 ******************************************************************************
 */

#ifndef NETDEV_TX_H_INCLUDED
#define NETDEV_TX_H_INCLUDED

#include <linux/netdevice.h>   /* net device interface */
#include <linux/skbuff.h>      /* skb allocations */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */
#include <linux/workqueue.h>   /* workqueues */

#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */

/**
 * sel3390e4_tx_clean() - Process all packets that have been sent by the hardware
 *
 * @mac: net device context
 *
 * This function frees any data buffers allocated for a completed TXBD,
 * and frees the associated skb. This function can only run in 
 * soft irq context.
 *
 * Return: number of TX packets processed
 */
int sel3390e4_tx_clean(struct sel3390e4_mac *mac);

/**
 * Free the memory associated with the transmit path.
 *
 * @mac: net device context
 *
 * This function must not be called from an atomic context.
 */
void sel3390e4_free_transmit_memory(struct sel3390e4_mac *mac);

/**
 * sel3390e4_alloc_transmit_memory() - Allocate the memory associated with the transmit path
 *
 * @mac: the net device context
 *
 * The caller needs to eventually call sel3390e4_free_transmit_memory in order to
 * free memory allocated in this function.
 *
 * Return: 0 if successful, otherwise an appropriate negative error code
 */
int sel3390e4_alloc_transmit_memory(struct sel3390e4_mac *mac);

/**
 * sel3390e4_xmit_frame() - Transmit a packet
 *
 * @skb:    the packet to be transmitted
 * @netdev: the net device object
 *
 * If scatter/gather is supported, the first frag is stored in skb->data,
 * with length skb_headlen(skb). The remaining frags have a total size of
 * skb->len - skb_headlen(skb), and are retrieved using
 * skb_shinfo(skb)->frags[n] and skb_shinfo(skb)->nr_frags. This function
 * can not be called higher than soft irq context. The kernel calls this function
 * from process level context.
 *
 * Return:
 *  NETDEV_TX_OK,
 *  NETDEV_TX_BUSY
 */
netdev_tx_t sel3390e4_xmit_frame(
	struct sk_buff *skb,
	struct net_device *netdev
	);

/**
 * sel3390e4_tx_timeout() - Called when the net device interface senses a
 * timeout in packet transmission
 *
 * @netdev: net device object
 *
 * This function runs in the interrupt context
 */
void sel3390e4_tx_timeout(struct net_device *netdev);

/**
 * sel3390e4_tx_timeout_task() - reset the device because of a transmission timeout
 *
 * @work: work item object
 * @data: work item object
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)) || defined(__VMKLNX__))
void sel3390e4_tx_timeout_task(struct work_struct *work);
#else
void sel3390e4_tx_timeout_task(void *data);
#endif

#endif /* NETDEV_TX_H_INCLUDED */
