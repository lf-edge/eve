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

#ifndef NETDEV_ISR_H_INCLUDED
#define NETDEV_ISR_H_INCLUDED

#include <linux/interrupt.h>   /* IRQ interface */
#include <linux/netdevice.h>   /* net device interface */
#include <linux/types.h>       /* types */
#include <linux/version.h>     /* linux version */

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
void sel3390e4_rx_watchdog(unsigned long data);
#else
void sel3390e4_rx_watchdog(struct timer_list *c);
#endif

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
irqreturn_t sel3390e4_intr(int irq, void *dev_id);
#else
irqreturn_t sel3390e4_intr(int irq, void *dev_id, struct pt_regs *regs);
#endif

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
int sel3390e4_poll(struct napi_struct *napi, int budget);
#else
int sel3390e4_poll(struct net_device *netdev, int *napi_budget);
#endif

#endif /* NETDEV_ISR_H_INCLUDED */

