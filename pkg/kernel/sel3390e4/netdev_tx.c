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
#include <linux/rtnetlink.h>   /* rtnl_lock functions */
#include <linux/skbuff.h>      /* skb allocations */
#include <linux/slab.h>        /* kmalloc, kzalloc */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */
#include <linux/workqueue.h>   /* workqueues */

#include "netdev.h"             /* net device interface */
#include "netdev_tx.h"          /* transmit interface */
#include "sel_hw.h"             /* mac interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
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
int sel3390e4_tx_clean(struct sel3390e4_mac *mac)
{
	struct sel3390e4_tx_bd_wrapper *dty_tx;
	u32 tx_cleaned = 0;
	u32 packet_status;
	dma_addr_t dma_addr;

	spin_lock(&mac->tx_lock);

	/* Clean all the buffer descriptors and mark them as complete. */

	dty_tx = mac->dty_tx;

	while (mac->tx_bd_avail != mac->num_tx_bds) {
		packet_status = le32_to_cpu(dty_tx->bd->stat);
		dma_addr = le64_to_cpu(dty_tx->bd->tx_data_buff_ptr);

		if ((packet_status & TX_BD_RDY) != 0) {
			break;
		}

		netif_info(mac, tx_done, mac->netdev,
			"TBD RDY[%d] WRP[%d] LST[%d] BABT_ERR[%d] LEN[%d] BUF[0x%016llX]\n",
			((packet_status & TX_BD_RDY) != 0),
			((packet_status & TX_BD_WRP) != 0),
			((packet_status & TX_BD_LST) != 0),
			((packet_status & TX_BD_BABT_ERR) != 0),
			(packet_status & TX_BD_DATA_LEN_MASK),
			(long long)dma_addr);

		/* if we reached this point, the txbd should have mapped data */
		BUG_ON(dma_addr == 0);

		/* We unmap the size of the buffer since that was the original size
		 * that was mapped.
		 */
		pci_unmap_single(
			mac->board->pdev,
			dma_addr,
			(packet_status & TX_BD_DATA_LEN_MASK),
			PCI_DMA_TODEVICE);

		dty_tx->bd->tx_data_buff_ptr = 0;

		/* The last buffer in a frame contains the skb to be freed */
		if (dty_tx->skbuf != NULL) {
			mac->stats.tx_packets++;
			mac->stats.tx_bytes += dty_tx->skbuf->len;

			dev_kfree_skb_any(dty_tx->skbuf);
			dty_tx->skbuf = NULL;
		}

		tx_cleaned++;
		dty_tx = dty_tx->next;
		mac->dty_tx = dty_tx;
		mac->tx_bd_avail++;
	}

	/* Recover from running out of Tx resources in xmit_frame
	 * by starting the queue of transmit packets if it was stopped
	 * and we have TXBDs available
	 */
	if (unlikely((tx_cleaned > 0) && netif_queue_stopped(mac->netdev))) {
		netif_wake_queue(mac->netdev);
	}

	spin_unlock(&mac->tx_lock);

	return tx_cleaned;
}

/**
 * Free the memory associated with the transmit path.
 *
 * @mac: net device context
 *
 * This function must not be called from an atomic context.
 */
void sel3390e4_free_transmit_memory(struct sel3390e4_mac *mac)
{
	struct sel3390e4_tx_bd_wrapper *tx;

	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	/* Packets may have already been sent to hardware.
	 * Unmap those packets and free the respective
	 * skb memory
	 */
	while (mac->tx_bd_avail != mac->num_tx_bds) {
		tx = mac->dty_tx;

		if (le64_to_cpu(tx->bd->tx_data_buff_ptr) != 0) {

			pci_unmap_single(
				mac->board->pdev,
				le64_to_cpu(tx->bd->tx_data_buff_ptr),
				(le32_to_cpu(tx->bd->stat)
					& TX_BD_DATA_LEN_MASK),
				PCI_DMA_TODEVICE);

			tx->bd->tx_data_buff_ptr = 0;
		}

		/* The tx_wrapper containing the last buffer in a
		 * frame contains the skb ptr to be freed
		 */
		if (tx->skbuf != NULL) {
			dev_kfree_skb_any(tx->skbuf);
			tx->skbuf = NULL;
		}

		mac->dty_tx = tx->next;
		mac->tx_bd_avail++;
	}

	if (mac->base_tx_bd_dma_addr != 0) {
		pci_pool_free(
			mac->tx_bd_pool,
			mac->base_tx_bd,
			mac->base_tx_bd_dma_addr);

		mac->base_tx_bd_dma_addr = 0;
		mac->base_tx_bd = 0;
	}

	if (mac->tx_bd_pool != NULL) {
		pci_pool_destroy(mac->tx_bd_pool);
		mac->tx_bd_pool = NULL;
	}

	if (mac->base_tx != NULL) {
		kfree(mac->base_tx);
		mac->base_tx = NULL;
	}

	mac->cur_tx = NULL;
	mac->dty_tx = NULL;
	mac->tx_bd_avail = 0;

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);
}

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
int sel3390e4_alloc_transmit_memory(struct sel3390e4_mac *mac)
{
	u16 i;
	struct sel3390e4_tx_bd *tx_bd;
	struct sel3390e4_tx_bd_wrapper *tx;

	netdev_vdbg(mac->netdev, "--> %s\n", __func__);

	/* Initialize the total number of TXBDs available for this net device */
	mac->tx_bd_avail = 0;

	mac->tx_bd_buffer_size =
		(sizeof(struct sel3390e4_tx_bd) * mac->num_tx_bds);

	/* Create the pool for TXBDs
	 * An allocation from this pool will be one complete set of TXBDs
	 */
	mac->tx_bd_pool =
		pci_pool_create(
			mac->netdev->name,
			mac->board->pdev,
			mac->tx_bd_buffer_size,
			SEL3390E4_DATA_ALIGN, /* 16-byte aligned */
			0);

	if (mac->tx_bd_pool == NULL) {
		return -ENOMEM;
	}

	/* Allocate all the TXBDs from the DMA pool.
	 * We created the DMA pool earlier, and allocations from this pool
	 * are mac->num_tx_bds * sizeof(struct sel3390e4_tx_bd)
	 */
	mac->base_tx_bd =
		pci_pool_alloc(
			mac->tx_bd_pool,
			GFP_KERNEL,
			&mac->base_tx_bd_dma_addr);

	if (mac->base_tx_bd == NULL) {
		goto err_free_pci;
	}

	/* Clear the TXBD memory */
	memset(
		mac->base_tx_bd,
		0,
		mac->tx_bd_buffer_size);

	/* Allocate memory for the TXBD wrapper */
	mac->base_tx =
		kzalloc(
			(mac->num_tx_bds *
				sizeof(struct sel3390e4_tx_bd_wrapper)),
			GFP_KERNEL);
	if (mac->base_tx == NULL) {
		goto err_free_pci;
	}

	/* Setup each TXBD and TXBD wrapper */

	for (tx = mac->base_tx, tx_bd = mac->base_tx_bd, i = 0;
		i < mac->num_tx_bds;
		tx++, tx_bd++, i++) {

		/* Link this txbd wrapper to this txbd */
		tx->bd = tx_bd;

		/* Setup linked list for txbd wrappers */

		if ((i + 1) < mac->num_tx_bds) {
			tx->next = tx + 1;
		} else {
			tx->next = mac->base_tx;

			/* Set the wrap bit in the buffer
			 * descriptor so RTL knows this is the last one
			 */
			tx_bd->stat |= cpu_to_le32(TX_BD_WRP);
		}

		tx->prev = (i == 0) ?
			(mac->base_tx + (mac->num_tx_bds - 1)) : (tx - 1);
	}

	/* Initialize the txbd wrapper ptrs
	 * cur_tx is the currently available txbd wrapper
	 * dty_tx is the txbd wrapper containing the oldest pack sent and
	 * not marked as sent yet.
	 */
	mac->cur_tx = mac->base_tx;
	mac->dty_tx = mac->base_tx;

	mac->tx_bd_avail = mac->num_tx_bds;

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);

	return 0;

err_free_pci:

	sel3390e4_free_transmit_memory(mac);

	netdev_vdbg(mac->netdev, "<-- %s\n", __func__);

	return -ENOMEM;
}

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
	)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	struct sel3390e4_tx_bd_wrapper *tx = NULL;
	int err = 0;
	netdev_tx_t retval = NETDEV_TX_OK;
	u32 tx_bd_stat;
	int len;
	int offset = 0;
	int size = 0;
	dma_addr_t dma_head;
	u32 tbds_needed = 0;

	/* Protect against funky skbs */
	if (unlikely(skb->len <= 0)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* This driver assumes all SKBs are linear (i.e. not fragmented).
	 * Thus we need to linearize SKBs that are not linear.
	 */
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb)) {
			return NETDEV_TX_BUSY;
		}
	}

	spin_lock_bh(&mac->tx_lock);

	/* Calculate the total number of TBDs needed */
	
	tbds_needed = 
		DIV_ROUND_UP(
			skb_headlen(skb), 
			SEL3390E4_MAX_BYTES_PER_TXBD);
	
	if (unlikely(mac->tx_bd_avail < tbds_needed)) {
		netif_stop_queue(netdev);
		err = -ENOMEM;
		goto err_unlock;
	}
	
	/* Set up each TBD */
	
	tx = mac->cur_tx;
	len = skb_headlen(skb);
	offset = 0;

	dma_head =
		pci_map_single(
			mac->board->pdev,
			skb->data,
			len,
			PCI_DMA_TODEVICE);

	if (unlikely(pci_dma_mapping_error(mac->board->pdev, dma_head))) {
		err = -ENOMEM;
		goto err_unlock;
	}

	while (len > 0) {
		/* Store only as much data in each TXBD as you can */
		size = min((u32)len, SEL3390E4_MAX_BYTES_PER_TXBD);

		dma_head += offset;
			
		/* copy DMA addr of sk_buff to Tx Data
		 * Buffer Pointer field tx_bd
		 */
		BUG_ON(tx->bd->tx_data_buff_ptr != 0);
		BUG_ON((size | TX_BD_DATA_LEN_MASK) != TX_BD_DATA_LEN_MASK);
		
		tx->bd->tx_data_buff_ptr = cpu_to_le64(dma_head);
		tx_bd_stat = le32_to_cpu(tx->bd->stat) & TX_BD_WRP;
		tx_bd_stat |= size;

		if (len <= SEL3390E4_MAX_BYTES_PER_TXBD) {
			/* Set the last bit since this
			 * is the last buffer in this frame
			 */
			tx_bd_stat |= TX_BD_LST;

			/* Store the skb in the last fragment */
			tx->skbuf = skb;

			/* SKBs must be timestamped before being sent */
			skb_tx_timestamp(skb);
		}

		tx->bd->stat = cpu_to_le32(tx_bd_stat);

		netif_info(mac, tx_queued, mac->netdev,
			"Sending skb: 0x%016llX cur_tx: %p tx_bd: %p stat: 0x%08x bd_avail: %d",
			le64_to_cpu(tx->bd->tx_data_buff_ptr),
			tx,
			tx->bd,
			le32_to_cpu(tx->bd->stat),
			mac->tx_bd_avail);
			
		/* Ready bit cleared by HW when frame transmission complete. */
		tx->bd->stat |= cpu_to_le32(TX_BD_RDY);

		/* Move to the next TXBD and reduce
		 * the number of available TXBDs
		 */
		tx = tx->next;
		mac->cur_tx = tx;
		mac->tx_bd_avail--;

		len -= size;
		offset += size;
	}
	
	/* Clear the THLT bit to start a transmission by writing a 1. */
	sel_read_mod_write(
		&mac->hw_mac->mac.tx_stat,
		TSTAT_THLT,
		0);

	sel_write_flush(mac->hw_mac);

	/* If we are running out of space, stop the TX queue */
	if (unlikely(mac->tx_bd_avail == 0)) {
		netif_stop_queue(netdev);
		err = -ENOSPC;
	}

err_unlock:

	switch (err) {
	case -ENOMEM:
		/* Memory error occured, tell the kernel to try again */
		retval = NETDEV_TX_BUSY;
		break;

	default:
		/* The skb was successfully passed to hardware */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34))
		/* This timestamp needs to be set on every new transmit.
		 * The kernel uses this timestamp to determine when a timeout
		 * occurs in the TX path AFTER the TX queue is STOPPED.
		 * For example, if this is set to  4 (and the timeout
		 * is 3 seconds), if the timestamp is still set to 4
		 * after 3 seconds, the kernel reports a timeout (and
		 * our tx timeout function is called.
		 */
		netdev->trans_start = jiffies;
#endif
		retval = NETDEV_TX_OK;
		break;
	}

	spin_unlock_bh(&mac->tx_lock);

	return retval;
}

/**
 * sel3390e4_tx_timeout() - Called when the net device interface senses a
 * timeout in packet transmission
 *
 * @netdev: net device object
 *
 * This function runs in the interrupt context
 */
void sel3390e4_tx_timeout(struct net_device *netdev)
{
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	netdev_vdbg(netdev, "--> %s\n", __func__);

	/* Reset the device outside of interrupt context
	 * since up'ing and down'ing the device involves allocated memory
	 */
	schedule_work(&mac->tx_timeout_task);

	netdev_vdbg(netdev, "<-- %s\n", __func__);
}

/**
 * sel3390e4_tx_timeout_task() - reset the device because of a transmission timeout
 *
 * @work: work item object
 * @data: work item object
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)) || defined(__VMKLNX__))
void sel3390e4_tx_timeout_task(struct work_struct *work)
#else
void sel3390e4_tx_timeout_task(void *data)
#endif
{
	/* This net device is unresponsive, so restart it */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)) || defined(__VMKLNX__))
	struct sel3390e4_mac *mac =
		container_of(work, struct sel3390e4_mac, tx_timeout_task);
#else
	struct sel3390e4_mac *mac = (struct sel3390e4_mac *)data;
#endif

	struct net_device *netdev = mac->netdev;

	netdev_vdbg(netdev, "--> %s\n", __func__);

	/* We grab the semaphore used by the kernel during netdev
	 * open() and close() before we reset
	 * to protect against any other reset operations.
	 */

	rtnl_lock();
	if (netif_running(netdev)) {
		sel3390e4_down(mac);
		(void)sel3390e4_up(mac);
	}
	rtnl_unlock();

	netdev_vdbg(netdev, "<-- %s\n", __func__);
}
