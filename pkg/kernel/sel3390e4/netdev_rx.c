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

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* kern-specific macros */

#include <asm/byteorder.h>     /* byte ordering (le32_to_cpu) */
#include <linux/errno.h>       /* error codes */
#include <linux/if_ether.h>    /* ethernet definitions */
#include <linux/if_vlan.h>     /* VLAN */
#include <linux/pci.h>         /* pci interface */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/skbuff.h>      /* skb allocations */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

#include "sel3390e4.h"          /* 3390 definitions */
#include "sel_hw.h"             /* mac interface */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */

/**
 * sel3390e4_rx_clean_array() - Free the data buffer and skb associated with all RXBDs
 *
 * @mac: net device context
 *
 * This function should not be called from an atomic context.
 */
static void sel3390e4_rx_clean_array(struct sel3390e4_mac *mac)
{
	u32 i;

	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	for (i = 0; i < mac->num_rx_bds; ++i) {
		if (mac->rx_skb[i] != NULL) {
			/* There is a one-to-one mapping of skbs
			 * and dma data buffers. Thus, we should have
			 * a dma data buffer to be unmapped if we reach
			 * this point.
			 */
			BUG_ON(mac->rx_bd_data_dma_addr[i] == 0);

			pci_unmap_single(
				mac->board->pdev,
				mac->rx_bd_data_dma_addr[i],
				SEL3390E4_RX_BUFF_LEN,
				PCI_DMA_FROMDEVICE);

			mac->rx_bd_data_dma_addr[i] = 0;

			dev_kfree_skb(mac->rx_skb[i]);
			mac->rx_skb[i] = NULL;
		}
	}

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);
}

/**
 * sel3390e4_rx_indicate() - Indicate/Pass received packets to the kernel
 *
 * @mac:        net device context
 * @rx_idx:     index of the RXBD/SKB to indicate
 * @work_done:  the amount of receive packets indicated
 * @work_to_do: the amount of receive packets to be processed
 *
 * The receive SKB is no longer available after this function call. Also,
 * the RXBD DMA data buffer memory is deallocated here as well. This function
 * no longer processes packets after work_done >= work_to_do.
 * This function assumes the rx_lock has been acquired, and software interrupts
 * are enabled.
 *
 * Return:
 *  0 if succesful,
 * -EAGAIN if work_done >= work_to_do,
 * -ENODATA if RXBD is empty
 */
static int sel3390e4_rx_indicate(
	struct sel3390e4_mac *mac,
	u32 rx_idx,
	int *work_done,
	int work_to_do)
{
	u16 actual_size;
	u32 packet_status;
	struct sk_buff *skb = mac->rx_skb[rx_idx];

	if (unlikely((work_done != NULL) && (*work_done >= work_to_do))) {
		return -EAGAIN;
	}

	packet_status = le32_to_cpu(mac->base_rx_bd[rx_idx].stat);

	if ((packet_status & RX_BD_EMT) != 0) {
		return -ENODATA;
	}

	netif_info(mac, rx_status, mac->netdev,
		"RBD EMT[%d] WRP[%d] LST[%d] PAR_ERR[%d] BABR_ERR[%d] LEN[%d] BUF[0x%016llX]\n",
		((packet_status & RX_BD_EMT) != 0),
		((packet_status & RX_BD_WRP) != 0),
		((packet_status & RX_BD_LST) != 0),
		((packet_status & RX_BD_PAR_ERR) != 0),
		((packet_status & RX_BD_BABR_ERR) != 0),
		(packet_status & RX_BD_DATA_LEN_MASK),
		le64_to_cpu(mac->base_rx_bd[rx_idx].rx_data_buff_ptr));

	actual_size = (packet_status & RX_BD_DATA_LEN_MASK);

	/* Unmap the data buffer memory now that we are going to hand
	 * possession of the memory to the kernel
	 */

	BUG_ON(mac->rx_bd_data_dma_addr[rx_idx] == 0);

	pci_unmap_single(
		mac->board->pdev,
		mac->rx_bd_data_dma_addr[rx_idx],
		SEL3390E4_RX_BUFF_LEN,
		PCI_DMA_FROMDEVICE);

	mac->rx_bd_data_dma_addr[rx_idx] = 0;

	if ((packet_status & (RX_BD_PAR_ERR | RX_BD_BABR_ERR)) != 0) {
		dev_kfree_skb_any(skb);
	} else {
		/* Update the SKB and relinquish its ownership to the kernel */
		skb_put(skb, actual_size);
		skb->protocol = eth_type_trans(skb, mac->netdev);

		/* This function must be called with interrupts enabled */
		netif_receive_skb(skb);

		if (work_done != NULL) {
			(*work_done)++;
		}

		/* Update statistics */

		mac->stats.rx_packets++;
		mac->stats.rx_bytes += actual_size;
	}

	/* We handed the skb to the kernel (or freed it). */
	mac->rx_skb[rx_idx] = NULL;

	return 0;
}

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
int sel3390e4_rx_alloc_skb(struct sel3390e4_mac *mac, u16 idx)
{
	u32 new_stat;
	dma_addr_t dma_addr;
	struct sk_buff *skb;

	/* Allocate a single SKB (enough for a receive buffer and alignment)
	 * We don't align the buffer here since not all platforms the driver is
	 * built on utilizes IP alignment.
	 */
	skb = netdev_alloc_skb(mac->netdev, SEL3390E4_RX_BUFF_LEN + NET_IP_ALIGN);
	if (skb == NULL) {
		return -ENOMEM;
	}

	/* Align IP header */
#ifndef __VMKLNX__
	/* This is commented out, rather than removed, intentionally.
	 * We want this code to exist at some point, but there is a defect in
	 * the card firmware that causes unaligned DMA transfers to transmit
	 * bad data.  When that is fixed, this should work again and the
	 * VMWare flags should be able to be removed.
	 */
	/*skb_reserve(skb, NET_IP_ALIGN);*/
#endif

	/* Map the SKB's data buffer */
	dma_addr =
		pci_map_single(
			mac->board->pdev,
			skb->data,
			SEL3390E4_RX_BUFF_LEN,
			PCI_DMA_FROMDEVICE);

	if (unlikely(pci_dma_mapping_error(mac->board->pdev, dma_addr))) {
		dev_kfree_skb_any(skb);
		return -ENOMEM;
	}

	/* Store the data buffer ptr into the RXBD */
	mac->rx_bd_data_dma_addr[idx] = dma_addr;
	mac->base_rx_bd[idx].rx_data_buff_ptr = cpu_to_le64(dma_addr);
	mac->rx_skb[idx] = skb;

	/* Initialize the status as empty */
	new_stat = RX_BD_EMT;
	if (idx == (mac->num_rx_bds - 1)) {
		new_stat |= RX_BD_WRP;
	}

	mac->base_rx_bd[idx].stat = cpu_to_le32(new_stat);

	return 0;
}

/**
 * sel3390e4_free_receive_memory() - Free memory associated with the receive path
 *
 * @mac: net device context
 *
 * This function should not be called from an atomic context.
 */
void sel3390e4_free_receive_memory(struct sel3390e4_mac *mac)
{
	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	sel3390e4_rx_clean_array(mac);

	if (mac->base_rx_bd_dma_addr != 0) {
		pci_pool_free(
			mac->rx_bd_pool,
			mac->base_rx_bd,
			mac->base_rx_bd_dma_addr);

		mac->base_rx_bd_dma_addr = 0;
		mac->base_rx_bd = NULL;
	}

	if (mac->rx_bd_pool != NULL) {
		pci_pool_destroy(mac->rx_bd_pool);
		mac->rx_bd_pool = NULL;
	}

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);
}

/**
 * sel3390e4_alloc_receive_memory() - Allocate memory associated with the receive path
 *
 * @mac: net device context
 *
 * Callers of this function must eventually call sel3390e4_free_receive_memory in
 * order to free allocated memory.
 *
 * Return: 0 if successful, otherwise an appropriate negative error value
 */
int sel3390e4_alloc_receive_memory(struct sel3390e4_mac *mac)
{
	int err = 0;
	u32 idx;
	mac->rx_to_alloc = 0;
	mac->rx_to_clean = 0;

	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	mac->rx_bd_buffer_size =
		(sizeof(struct sel3390e4_rx_bd) * mac->num_rx_bds);

	/* Create the pool for RXBDs
	 * An allocation from this pool will be one complete set of RXBDs
	 */
	mac->rx_bd_pool =
		pci_pool_create(
			mac->netdev->name,
			mac->board->pdev,
			mac->rx_bd_buffer_size,
			SEL3390E4_DATA_ALIGN, /* 16-byte aligned */
			0);

	if (mac->rx_bd_pool == NULL) {
		return -ENOMEM;
	}

	/* Allocate all the RXBDs from the DMA pool
	 * We created the DMA pool earlier, and allocations from this pool
	 * are mac->num_rx_bds * sizeof(struct sel3390e4_rx_bd)
	 */
	mac->base_rx_bd =
		pci_pool_alloc(
			mac->rx_bd_pool,
			GFP_KERNEL,
			&mac->base_rx_bd_dma_addr);

	if (mac->base_rx_bd == NULL) {
		sel3390e4_free_receive_memory(mac);
		return -ENOMEM;
	}

	/* Clean the buffer ring */
	memset(mac->base_rx_bd, 0, mac->rx_bd_buffer_size);

	for (idx = 0; idx < mac->num_rx_bds; ++idx) {
		err = sel3390e4_rx_alloc_skb(mac, idx);
		if (err) {
			sel3390e4_free_receive_memory(mac);
			break;
		}
	}

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);

	return err;
}

/**
 * sel3390e4_rx_clean() - Loop through the rx ring and indicate received packets
 *
 * @mac:        net device context
 * @work_done:  the amount of packets indicated to the kernel
 * @work_to_do: the amount of packets to process
 *
 * In this function we indicate receive packets to the kernel, unmapping
 * memory created for data buffer memory, and re-creating that DMA memory
 * and skb memory for future receive packets. This function bails whenever
 * work_done >= work_to_do, or if there is no receive data to process.
 * This function can only be called from soft irq context.
 */
void sel3390e4_rx_clean(
	struct sel3390e4_mac *mac,
	int *work_done,
	int work_to_do)
{
	int restart_required = 0;
	int err = 0;
	u32 current_bd;

	spin_lock(&mac->rx_lock);

	/* Below we make two loops on receive buffers. The first scans
	 * the RBD list for RBDs with receive data, and passes the buffers
	 * along to the kernel. The second scans the RBD list for RBDs that
	 * need new SKB data, and allocates new SKBs.
	 */

	for (current_bd = mac->rx_to_clean;
		mac->rx_skb[current_bd] != NULL;
		current_bd = ((current_bd + 1) % mac->num_rx_bds),
		mac->rx_to_clean = current_bd) {
		err =
			sel3390e4_rx_indicate(
				mac,
				current_bd,
				work_done,
				work_to_do);
		if (err) {
			break;
		}
	}

	if (-ENODATA == err) {
		/* We reached a buffer with no data, so the receiver
		 * may or may not have been stopped, so just in case, restart
		 * the receiver once we are finished with receive processing
		 */
		restart_required = 1;
	}

	for (current_bd = mac->rx_to_alloc;
		mac->rx_skb[current_bd] == NULL;
		current_bd = ((current_bd + 1) % mac->num_rx_bds),
		mac->rx_to_alloc = current_bd) {
		/* We need to allocate a new data buffer and skb
		 * for all the RXBDs we indicated and passed to
		 * the kernel. We also mark the RXBD as
		 * ready again here as well.
		 */
		err = sel3390e4_rx_alloc_skb(mac, current_bd);
		if (unlikely(err)) {
			/* Start the watchdog timer */
			mod_timer(&mac->watchdog_timer, jiffies);
			break;
		}
	}

	if (restart_required) {
		/* Clear QHLT which will start the receiver if it was stopped
		 * due to running out of RX buffers.
		 */

		sel_read_mod_write(
			&mac->hw_mac->mac.rx_stat,
			RSTAT_QHLT,
			0);

		sel_write_flush(mac->hw_mac);
	}

	spin_unlock(&mac->rx_lock);
}
