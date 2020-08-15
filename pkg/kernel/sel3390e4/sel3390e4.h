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
 * SEL-3390E4 Linux Driver Defitions
 ******************************************************************************
 */

#ifndef _SEL3390E4_H_
#define _SEL3390E4_H_

#include <linux/if_ether.h>    /* ethernet definitions */
#include <linux/if_vlan.h>     /* VLAN */
#include <linux/jiffies.h>     /* jiffies, HZ */
#include <linux/mii.h>         /* mii registers */
#include <linux/netdevice.h>   /* net device types */
#include <linux/pci.h>         /* PCI device type */
#include <linux/skbuff.h>      /* skb types */
#include <linux/spinlock.h>    /* spin locks */
#include <linux/timer.h>       /* timers */
#include <linux/types.h>       /* std types */
#include <linux/workqueue.h>   /* workqueue */
#include <linux/version.h>     /* Linux version macros */

#include "sel3390e4_hw_regs.h"  /* hw register definitions */

/* Generic Defines */

/* Driver Version Number */
#define SEL3390E4_DRV_VERSION "1.4.49152.1"

/* Driver Copyright */
#define SEL3390E4_DRV_COPYRIGHT \
	"Copyright(c) 2014 Schweitzer Engineering Laboratories, Inc."

/* Driver Description */
#define SEL3390E4_DRV_DESCRIPTION "SEL(R) 3390E4 Network Driver"

/* Driver Name */
#define SEL3390E4_DRV_NAME "sel3390e4"

/* Required alignment for rx base and tx base */
#define SEL3390E4_DATA_ALIGN 16U

/* number of packets required to be processed
 * in order stay in polling mode
 */
#define SEL3390E4_NAPI_WEIGHT 64U

/* default number of rx and tx bds */
#define SEL3390E4_NUM_RX_BDS 2048U
#define SEL3390E4_NUM_TX_BDS 2048U

/* minimum number of rx and tx bds */
#define SEL3390E4_MIN_NUM_RX_BDS 1024U
#define SEL3390E4_MIN_NUM_TX_BDS 1024U

/* max number of rx and tx bds */
#define SEL3390E4_MAX_NUM_RX_BDS 4096U
#define SEL3390E4_MAX_NUM_TX_BDS 4096U

/* time window, in seconds, in which transmit
 * packets must be sent by hardware before a
 * reset is triggered
 */
#define SEL3390E4_TX_TIMEOUT     (3 * HZ)
#define SEL3390E4_WATCHDOG_SEC   (2 * HZ)

/* max size of the data buffer in each txbd */
#define SEL3390E4_MAX_BYTES_PER_TXBD  2048U

/* Size of Receive Buffer */
#define SEL3390E4_RX_BUFF_LEN (VLAN_ETH_FRAME_LEN + ETH_FCS_LEN)

/**
 * struct sel3390e4_device_stats - Device Statistics
 */
struct sel3390e4_device_stats {
	/* Number of packets sent that pass CRC check */
	u64 out_packets;

	/* Number of bad packets sent, including those due to
	 * collisions, retransmissions, buffer underflow, and
	 * discard frames.
	 */
	u64 out_frag_packets;

	/* Number of half-duplex collisions */
	u64 restart_frames;

	/* Number of frames aborted due to excessive collisions */
	u64 excessive_collisions;

	/* Number of packets received that pass CRC check */
	u64 in_packets;

	/* Number of frames received with CRC errors */
	u64 in_crc_err;

	/* Number of events where data was lost due to buffer overflow */
	u64 in_buff_ovf;

	/* Number of packets received with size less than 64 bytes */
	u64 in_runt_packets;

	/* Number of packets received with exactly 64 bytes */
	u64 in_64_packets;

	/* Number of packets received with size between 65 and 127 bytes */
	u64 in_65_127_packets;

	/* Number of packets received with size between 128 and 255 bytes */
	u64 in_128_255_packets;

	/* Number of packets received with size between 256 and 511 bytes */
	u64 in_256_511_packets;

	/* Number of packets received with size between 512 and 1023 bytes */
	u64 in_512_1023_packets;

	/* Number of packets received with size 1024 and 1518 bytes */
	u64 in_1024_1518_packets;

	/* Number of packets received with size greater than 1518 bytes */
	u64 jumbo_packets;

	/* Number of broadcast packets received */
	u64 in_broadcast_packets;

	/* Number of multicast packets received */
	u64 in_multicast_packets;

	/* Number of unicast packets received */
	u64 in_unicast_packets;

	/* Number of packets received that were neither broadcast, nor
	 * multicast, nor unicast, and were rejected because promiscuous
	 * mode is disabled.
	 */
	u64 in_misses;

	/* Number of packets received that were only accepted because
	 * promiscuous mode was enabled.
	 */
	u64 in_promiscuous_only_packets;

	/* Number of packets discarded due to uncorrectable parity errors
	 * in the transmit FIFO.
	 */
	u64 out_discards;

	/* Number of packets discarded due to uncorrectable parity errors
	 * in the received FIFO.
	 */
	u64 in_discards;

	/* Number of output octets (good or bad) */
	u64 out_octets;

	/* Number of bytes received, included CRC bytes */
	u64 in_octets;
};

/**
 * struct sel3390e4_tx_bd_wrapper - Wrapper for transmit buffer descriptors
 *
 * This is used to link TXBDs together, and associate an sk_buff with each bd
 */
struct sel3390e4_tx_bd_wrapper {
	/* The buffer descriptor we are wrapping */
	struct sel3390e4_tx_bd *bd;

	/* Next bd in list */
	struct sel3390e4_tx_bd_wrapper *next;

	/* Previous bd in list */
	struct sel3390e4_tx_bd_wrapper *prev;

	/* skb buffer for this descriptor */
	struct sk_buff *skbuf;
};

/**
 * struct sel3390e4_mac - Net Device Context Area
 */
struct sel3390e4_mac {
	/* ptr to this MAC's mapped memory */
	struct sel3390e4_hw_mac __iomem *hw_mac;

	/* pointer to PCI device object context */
	struct sel3390e4_board *board;

	/* net device stats */
	struct net_device_stats stats;

	/* device stats */
	struct sel3390e4_device_stats device_stats;

	/* net device object for this MAC */
	struct net_device *netdev;

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)) || defined(__VMKLNX__))
	/* NAPI interface object */
	struct napi_struct napi;
#endif

	/* lock used to serialize imask/ievent accesses */
	spinlock_t imask_lock;

	/* lock to protect transmit memory */
	spinlock_t tx_lock;

	/* lock to protect receive memory */
	spinlock_t rx_lock;

	/* total number of TXBDs */
	u32 num_tx_bds;

	/* total number of RXBDs */
	u32 num_rx_bds;

	/* work item for unresponsive transmits */
	struct work_struct tx_timeout_task;

	/* watchdog for the hw. monitors link, speed, etc */
	struct timer_list watchdog_timer;

	/* number of TXBDs available */
	u32 tx_bd_avail;

	/* pool of TXBDs */
	struct pci_pool *tx_bd_pool;

	/* size of TXBD ring */
	u32 tx_bd_buffer_size;

	/* base DMA address for TXBDs */
	dma_addr_t base_tx_bd_dma_addr;

	/* base kernel mem address for TXBDs */
	struct sel3390e4_tx_bd *base_tx_bd;

	/* base address of TXBD wrappers */
	struct sel3390e4_tx_bd_wrapper *base_tx;

	/* Wrapper for current bd to use */
	struct sel3390e4_tx_bd_wrapper *cur_tx;

	/* Wrapper for dirty bd (oldest unprocessed TXBD that was sent) */
	struct sel3390e4_tx_bd_wrapper *dty_tx;

	/* pool of RXBDs */
	struct pci_pool *rx_bd_pool;

	/* base rxbd bus address */
	dma_addr_t base_rx_bd_dma_addr;

	/* base rxbd virtual address */
	struct sel3390e4_rx_bd *base_rx_bd;

	/* base rxbd data buffer bus address */
	dma_addr_t rx_bd_data_dma_addr[SEL3390E4_MAX_NUM_RX_BDS];

	/* RX SKBs */
	struct sk_buff *rx_skb[SEL3390E4_MAX_NUM_RX_BDS];

	/* size of RXBD ring */
	u32 rx_bd_buffer_size;

	/* index of next RXBD to be re-allocated */
	u16 rx_to_alloc;

	/* index of RXBD to be processed for receive data */
	u16 rx_to_clean;

	/* related to netif messaging for this net device */
	u32 msg_enable;

	/* the MII interface associated with this net device */
	struct mii_if_info mii_if;

	/* part number of the attached SFP */
	u32 sfp_part_number;

	/* whether an SFP connection exists for this net device */
	u8 sfp_connected;

	/* whether this device is in fiber mode (hardware strapping) */
	u8 fiber_mode;
};

/**
 * struct sel3390e4_board - PCI Device Context Area
 */
struct sel3390e4_board {
	/* the number of macs on this device (subdevice id) */
	u16 num_macs;

	/* ptr to an array of net device contexts */
	struct sel3390e4_mac **macs;

	/* NOR device base address */
	u32 __iomem *hw_nvm;

	/* MACs device base address
	 * basically a ptr to the first MAC
	 */
	struct sel3390e4_hw_mac __iomem *hw_macs;

	/* ptr to DIAG mapped BAR */
	struct sel3390e4_hw_diag __iomem *hw_diag;

	/* pci device object */
	struct pci_dev *pdev;

	/* lock used to serialize NOR access */
	spinlock_t nvm_lock;

	/* lock used to serialize MII bus access. This lock should be acquired
	 * before any other mdio locks are acquired.
	 */
	spinlock_t mdio_lock;

	/* lock used to serialize SFP management registers */
	spinlock_t sfp_lock;

	/* used to verify if an upgrade is progress */
	atomic_t firmware_upgrade_in_progress;

	/* PCI Revision ID
	 * Peripheral Version Number
	 */
	u8 revision_id;

	/* Firmware Build ID */
	u32 build_id;

	/* Bypass SFP validation and enable all attached
	 * SFPs, and assume they are 100Mbps
	 */
	u32 bypass_sfp_speed_100;

	/* Bypass SFP validation and enable all attached
	 * SFPs, and assume they are 1Gbps
	 */
	u32 bypass_sfp_speed_1000;

	/* Whether we are using a 64-bit DMA mask */
	u8 pci_using_dac;
};

#endif /* _SEL3390E4_H_ */

