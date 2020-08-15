/******************************************************************************
 * COPYRIGHT (c) 2019 Schweitzer Engineering Laboratories, Inc.
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
 * Net Device Interrupt Interface (Watchdog, PCI Interrupt, NAPI Polling)
 ******************************************************************************
 */

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/kernel.h>      /* printk */

#include <asm/io.h>            /* iowrites */
#include <linux/errno.h>       /* error codes */
#include <linux/interrupt.h>   /* IRQ interface */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

#include "netdev_rx.h"          /* netdevice rx interface */
#include "netdev_tx.h"          /* netdevice tx interface */
#include "sel_hw.h"             /* mac interface */
#include "sel3390e4.h"          /* 3390 definitions */
#include "sel3390e4_hw.h"       /* mac interface */
#include "sel3390e4_hw_regs.h"  /* hw register definitions */
#include "sel3390e4_kcomp.h"    /* kernel compatability header */
#include "sel3390e4_mii.h"      /* mii interface */
#include "sel3390e4_sfp.h"      /* sfp interface */

/**
 * sel3390e4_rx_watchdog() - Monitor RX buffers
 *
 * @data: net device context
 *
 * During a RX interrupt, we pass received SKBs to the kernel. After this, 
 * we attempt to reallocate a new SKB to store in the RBD. If the allocation
 * fails, we won't attempt to reallocate the buffer again until anoter RX
 * interrupt occurs. In order to supplement this retry, we use this watchdog
 * timer to allocate buffers when needed.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
void sel3390e4_rx_watchdog(unsigned long data)
{
	struct sel3390e4_mac *mac = (struct sel3390e4_mac *)data;
#else
void sel3390e4_rx_watchdog(struct timer_list *c)
{
	struct sel3390e4_mac *mac = from_timer(mac, c, watchdog_timer);
#endif
	u32 current_bd;

	/* When processing rx buffers, we may have been unable to allocate
	 * skbs, so lets try to here...
	 */

	spin_lock(&mac->rx_lock);

	for (current_bd = mac->rx_to_alloc;
		mac->rx_skb[current_bd] == NULL;
		current_bd = ((current_bd + 1) % mac->num_rx_bds),
		mac->rx_to_alloc = current_bd) {
		/* We need to allocate a new data buffer and skb
		 * for all the RXBDs we indicated and passed to
		 * the kernel. We also mark the RXBD as
		 * ready again here as well.
		 */
		if (unlikely(sel3390e4_rx_alloc_skb(mac, current_bd))) {
			mod_timer(
				&mac->watchdog_timer,
				round_jiffies(jiffies + SEL3390E4_WATCHDOG_SEC));
			break;
		}
	}

	spin_unlock(&mac->rx_lock);
}

/**
 * sel3390e4_intr() - Device interrupt handler
 *
 * @irq:    interrupt number
 * @dev_id: context passed to interrupt handler
 * @regs:   unused parameter
 *
 * Return: 
 *  IRQ_NONE if there is no interrupt for this driver to process.
 *  IRQ_HANDLED if this driver processed the interrupt.
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)) || defined(__VMKLNX__))
irqreturn_t sel3390e4_intr(int irq, void *dev_id)
#else
irqreturn_t sel3390e4_intr(int irq, void *dev_id, struct pt_regs *regs)
#endif
{
	struct net_device *netdev = dev_id;
	struct sel3390e4_mac *mac = netdev_priv(netdev);

	u32 ievent = ioread32(&mac->hw_mac->mac.ievent);
	u32 imask = ioread32(&mac->hw_mac->mac.imask);
	
	ievent &= imask;

	if (0 == ievent) {
		return IRQ_NONE;
	}

	/* Disable interrupts */
	sel_disable_irq(
		mac->hw_mac,
		ievent,
		&mac->imask_lock);

	/* Ack the event(s) */
	iowrite32(
		ievent,
		&mac->hw_mac->mac.ievent);

	sel_write_flush(mac->hw_mac);

	if ((ievent & (IEVENT_RXF | IEVENT_TXF)) != 0) {
		/* Handle receive and transmit interrupts through NAPI polling.
		 * Check if napi is already running. If not, schedule it and
		 * mark it as running. Also, disable interrupts as
		 * well since we'll now be in polling mode.
		 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)) || defined(__VMKLNX__))
		napi_schedule(&mac->napi);
#else
		netif_rx_schedule(mac->netdev);
#endif
	}

	if ((ievent & IEVENT_SFP) != 0) {
		/* SFPs may be attached, so query for them */
		sel3390e4_sfp_detect(mac);
	}

	if ((ievent & IEVENT_LINK) != 0) {
		/* Check Link State */
		sel3390e4_mii_check_link(&mac->mii_if);
	}

	if ((ievent & IEVENT_STAT) != 0) {
		/* Retrieve updated device statistics */
		sel3390e4_update_device_stats(mac);
	}

	/* We don't re-enable RX/TX interrupts here, as NAPI polling will
	 * re-enable them when it is complete in the NAPI polling handler
	 */
	sel_enable_irq(
		mac->hw_mac, 
		ievent & ~(IEVENT_RXF | IEVENT_TXF),
		&mac->imask_lock);

	sel_write_flush(mac->hw_mac);

	return IRQ_HANDLED;
}

/**
 * sel3390e4_poll() - Called periodically by the kernel when napi is enabled
 *
 * @napi:        the napi handle
 * @budget:      the max number of packets that can be indicated
 * @netdev:      net device object
 * @napi_budget: the max number of packets that can be indicated
 *
 * In our interrupt handler, we disabled interrupts and call __napi_schedule,
 * which then calls our polling function. In this function, if we don't
 * complete enough work (indicate a certain amount of received packets,
 * i.e. the budget param), we re-enable interrupts and
 * disable napi polling mode. NAPI polling helps to decrease the number
 * of interrupts. The function runs in an interrupt context (softirq), however,
 * hardware interrupts are still enabled (technically). We explicitly disabled
 * Rx and Tx hardware interrupts before scheduling NAPI, so no need 
 * to worry about them ocurring.
 *
 * Return: the number of packets processed
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)) || defined(__VMKLNX__))
int sel3390e4_poll(struct napi_struct *napi, int budget)
#else
int sel3390e4_poll(struct net_device *netdev, int *napi_budget)
#endif
{
	int work_done = 0;
	u32 tx_cleaned = 0;

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)) && !defined(__VMKLNX__))
	struct sel3390e4_mac *mac = netdev_priv(netdev);
	int budget = min(*napi_budget, netdev->quota);
#else
	struct sel3390e4_mac *mac = container_of(napi, struct sel3390e4_mac, napi);
#endif

	sel3390e4_rx_clean(mac, &work_done, budget);

	tx_cleaned = sel3390e4_tx_clean(mac);

	if (tx_cleaned == mac->num_tx_bds) {
		/* we may be under heavy transmit load, 
		 * so force polling to continue by saying we've
		 * completed the budget amount.
		 */
		work_done = budget;
	}

	/* When we have processed less than the budget, this means
	 * we haven't done the minimum required amount of work to
	 * stay in polling mode (meaning we really haven't received many
	 * interrupts. Thus we can safely return to interrupt mode.)
	 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)) || defined(__VMKLNX__))
	if (work_done < budget) {
		napi_complete(napi);
		sel_enable_irq(mac->hw_mac, (IEVENT_RXF | IEVENT_TXF), &mac->imask_lock);
	}
#else
	*napi_budget -= work_done;
	mac->netdev->quota -= work_done;

	if (work_done < budget) {
		netif_rx_complete(mac->netdev);
		sel_enable_irq(mac->hw_mac, (IEVENT_RXF | IEVENT_TXF), &mac->imask_lock);
	}
#endif

	return work_done;
}
