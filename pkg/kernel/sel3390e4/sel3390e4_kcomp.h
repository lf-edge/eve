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
 * SEL-3390E4 kernel compatability header
 ******************************************************************************
 */

#ifndef SEL_3390E4_COMPATABILITY_H_INCLUDED
#define SEL_3390E4_COMPATABILITY_H_INCLUDED

#include <linux/module.h>       /* required */
#include <linux/device.h>       /* dev_dbg */
#include <linux/dma-mapping.h>  /* dma mask */
#include <linux/ethtool.h>      /* ethtool interface */
#include <linux/firmware.h>     /* firmware data */
#include <linux/if_ether.h>     /* ethernet definitions */
#include <linux/kernel.h>       /* printk */
#include <linux/netdevice.h>    /* net device interface */
#include <linux/pci.h>          /* pci interface */
#include <linux/skbuff.h>       /* skb allocations */
#include <linux/types.h>        /* types */
#include <linux/version.h>      /* linux version */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37))
#include <linux/printk.h>       /* printk */
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))

#ifndef MODULE_FIRMWARE
#define MODULE_FIRMWARE(str)
#endif

#endif /* KERNEL_VERSION(2,6,19) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN 4
#endif

#ifndef upper_32_bits
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#endif

#endif /* KERNEL_VERSION(2,6,22) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))

#ifndef pr_err
#define pr_err(fmt, arg...) printk(KERN_ERR fmt, ##arg)
#endif

#endif /* KERNEL_VERSION(2,6,24) */

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)) && !defined(__VMKLNX__))

#ifndef dev_vdbg

#ifdef VERBOSE_DEBUG
	  #define dev_vdbg dev_dbg
#else
	  #define dev_vdbg(dev, format, arg...)
#endif /* VERBOSE_DEBUG */

#endif /* dev_vdbg */

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) \
	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#ifndef round_jiffies
#define round_jiffies(n) ((unsigned long)(n))
#endif

#endif /* < KERNEL_VERSION(2,6,25) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27))

#ifndef ethtool_cmd_speed
#define ethtool_cmd_speed(ethtool_cmd) ((ethtool_cmd)->speed)
#endif

#ifndef pci_dma_mapping_error
#define pci_dma_mapping_error(pdev, dma_addr) \
	dma_mapping_error(dma_addr)
#endif

#ifndef lower_32_bits
#define lower_32_bits(n) ((u32)(n))
#endif

#endif /* < KERNEL_VERSION(2,6,27) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32))
typedef int netdev_tx_t;
#endif /* < KERNEL_VERSION(2,6,32) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34))

#ifndef netdev_name
#define netdev_name(netdev) (netdev->name)
#endif

/* net_device tracing functions */

#ifndef netdev_printk
#define netdev_printk(level, netdev, format, args...) \
	printk(level \
		KBUILD_MODNAME " %s: " format, \
		netdev_name(netdev), ##args)
#endif

#ifndef netdev_vdbg

#ifdef VERBOSE_DEBUG

#define netdev_vdbg(dev, format, args...) \
	netdev_printk(KERN_DEBUG, (dev), format, ##args)

#else /* !defined(VERBOSE_DEBUG) */

#define netdev_vdbg(dev, format, args...)
#endif /* VERBOSE_DEBUG */

#endif /* netdev_vdbg */

#ifndef netdev_info
#define netdev_info(dev, format, args...) \
	netdev_printk(KERN_INFO, (dev), format, ##args)
#endif

#ifndef netdev_err
#define netdev_err(dev, format, args...) \
	netdev_printk(KERN_ERR, (dev), format, ##args)
#endif

#ifndef netif_printk
#define netif_printk(priv, type, level, dev, fmt, args...) \
do { \
	if (netif_msg_##type(priv)) \
		netdev_printk(level, (dev), fmt, ##args); \
} while (0)
#endif

#ifndef netif_info
#define netif_info(priv, type, dev, fmt, args...) \
	netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)
#endif

#ifndef netif_err
#define netif_err(priv, type, dev, fmt, args...) \
	netif_printk(priv, type, KERN_ERR, (dev), fmt, ##args)
#endif

#endif /* < KERNEL_VERSION(2,6,34) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = (dev)->mc_list; mclist; mclist = mclist->next)
#endif

#ifndef netdev_mc_count
#define netdev_mc_count(dev) ((dev)->mc_count)
#endif

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))

#ifndef skb_tx_timestamp
#define skb_tx_timestamp(skb)
#endif

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0))

#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN -1
#endif

#ifndef DUPLEX_UNKNOWN
#define DUPLEX_UNKNOWN 0xFF
#endif

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)) */

#ifdef __VMKLNX__

/* VMware ESXi 5.X compatibility Definitions */

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend, dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev, ops) (ethtool_ops = (ops))
#endif

#endif /* VMKLNX */

#endif /* SEL_3390E4_COMPATABILITY_H_INCLUDED */


