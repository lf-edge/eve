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
 * SEL-3390E4 HW Definitions
 ******************************************************************************
 */

#ifndef SEL3390E4_HW_REGS_H_INCLUDED
#define SEL3390E4_HW_REGS_H_INCLUDED

#include <linux/types.h>

/* PCI Vendor ID */
#define PCI_VENDOR_ID_SCHWEITZER        0x1AA9U

/* PCI Device ID */
#define PCI_DEVICE_ID_SCHWEITZER_3390E4 0x000EU

/* PCI Bars */

#define SEL3390E4_PCI_BAR_MACS 0U
#define SEL3390E4_PCI_BAR_TIME 1U
#define SEL3390E4_PCI_BAR_DIAG 2U
#define SEL3390E4_PCI_BAR_NVM  3U

#define SEL3390E4_PCI_BAR_MAC_LEN  0x4000U
#define SEL3390E4_PCI_BAR_TIME_LEN 0x1000U
#define SEL3390E4_PCI_BAR_DIAG_LEN 0x1000U
#define SEL3390E4_PCI_BAR_NVM_LEN  0x4000U

/* Generic Defines */

/* Every MAC has a register set this size */
#define SEL3390E4_MAC_REG_SIZE 0x1000U

/* Number of MAC registers */
#define SEL3390E4_NUM_MAC_REGISTERS (SEL3390E4_MAC_REG_SIZE/sizeof(u32))

/* PHY Addresses */
static u8 const SEL3390E4_PHY_ADDRS[] = {2, 3, 4, 5};

/**
 * enum ievent_flags - IEVENT/IMASK bits
 */
enum ievent_flags {
	IEVENT_RXC  = (1UL<<30),
	IEVENT_BSY  = (1UL<<29),
	IEVENT_GTSC = (1UL<<25),
	IEVENT_BABT = (1UL<<24),
	IEVENT_TXC  = (1UL<<23),
	IEVENT_TXE  = (1UL<<22),
	IEVENT_TXF  = (1UL<<20),
	IEVENT_MMRD = (1UL<<10),
	IEVENT_MMWR = (1UL<<9),
	IEVENT_RXF  = (1UL<<7),
	IEVENT_LINK = (1UL<<6),
	IEVENT_SFP  = (1UL<<5),
	IEVENT_STAT = (1UL<<4),
	IEVENT_TXR  = (1UL<<1),
	IEVENT_RXR  = (1UL<<0),
};

/**
 * enum tstat_flags - TSTAT bits/flags
 */
enum tstat_flags {
	TSTAT_THLT   = (1UL<<31),
	TSTAT_DMA_IP = (1UL<<30)
};

/**
 * enum rx_ctrl_flags - RX_CTRL bits/flags
 */
enum rx_ctrl_flags {
	RX_CTRL_BC_REJ = (1UL<<4),
	RX_CTRL_PROM   = (1UL<<3),
};

/**
 * enum rstat_flags - RSTAT bits/flags
 */
enum rstat_flags {
	RSTAT_DMA_IP   = (1UL<<30),
	RSTAT_QHLT     = (1UL<<23),
	RSTAT_RX_FRAME_CNT_MASK = 0x7FFUL
};

/**
 * enum maccfg_flags - MACCFG bits/flags
 */
enum maccfg_flags {
	MCCFG_SOFT_RESET = (1UL<<31),
	MCCFG_LOOP       = (1UL<<8),
	MCCFG_GTS        = (1UL<<4),
	MCCFG_RX_EN      = (1UL<<2),
	MCCFG_TX_EN      = (1UL<<0),
};

/**
 * enum mac_maxfrm_masks - MAC maxfrm register flags
 */
enum maxfrm_flags {
	MAXFRM_MAXFRM_MASK = 0xFFFFUL,
};

/**
 * enum mac_maxfrm_masks - MAC mac_stn_addr register flags
 */
enum mac_stn_addr_flags {
	MAC_STN_ADDR_MAC_VALID = (1UL<<0)
};

/**
 * enum rxlen_flags - RXLEN bits/flags
 *
 * Not used in case of an internal DMA controller
 */
enum rxlen_flags {
	RXLEN_RX_ERR           = (1UL<<31),
	RXLEN_LAST             = (1UL<<30),
	RXLEN_RX_BAB_ERR       = (1UL<<29),
	RXLEN_RX_DATA_LEN_MASK = 0x7FFUL
};

/**
 * enum txlen_flags - TXLEN bits/flags
 *
 * Not used in case of an internal DMA controller
 */
enum txlen_flags {
	TXLEN_INT_DIS          = (1UL<<31),
	TXLEN_LAST             = (1UL<<30),
	TXLEN_TX_DATA_LEN_MASK = 0x7FFUL
};

/**
 * enum mac_status_flags - MAC Status Flags
 */
enum mac_status_flags {
	MAC_STATUS_TX_FIFO_COUNT      = (1UL<<0),
	MAC_STATUS_TX_FIFO_COUNT_MASK = 0x1FFFFUL
};

/**
 * enum sel3390e4_nvm_rw_storage_offsets - NOR R/W Storage Offsets (Mac Addresses)
 */
enum sel3390e4_nvm_rw_storage_offsets {
	NVM_RW_ADDR_MAC_1 = 0x00UL,
	NVM_RW_ADDR_MAC_2 = 0x08UL,
	NVM_RW_ADDR_MAC_3 = 0x10UL,
	NVM_RW_ADDR_MAC_4 = 0x18UL,
};

/**
 * enum mii_cfg - MII Interface configuration
 */
enum mii_cfg {
	MII_RST = (1UL<<31)
};

/**
 * enum mii_com - MII Interface Command Masks
 */
enum mii_com {
	MII_READ_CYCLE = (1UL<<0),
	MII_SCAN_CYCLE = (1UL<<1)
};

/**
 * enum mii_add - MII Interface Address Masks
 */
enum mii_add {
	MII_REG_ADDR_MASK    = 0x001FUL,
	MII_PHY_ADDR_MASK    = 0x1F00UL,
	MII_PHY_ADDR_OFFSET  = 8UL
};

/**
 * enum mii_con - MII Interface Control Masks
 */
enum mii_con {
	MII_PHY_CONTROL_MASK = 0xFFFFUL
};

/**
 * enum mii_stat - MII Interface Status Masks
 */
enum mii_stat {
	MII_PHY_STATUS_MASK = 0xFFFFUL
};

/**
 * enum mii_ind - MII Interface Statuses
 */
enum mii_ind {
	MII_BUSY       = (1UL<<0),
	MII_SCAN       = (1UL<<1),
	MII_NOT_VALID  = (1UL<<2)
};

/**
 * enum tx_bd_flags - TXBD bits
 */
enum tx_bd_flags {
	TX_BD_RDY           = (1UL<<31),
	TX_BD_WRP           = (1UL<<29),
	TX_BD_LST           = (1UL<<27),
	TX_BD_BABT_ERR      = (1UL<<24),
	TX_BD_DATA_LEN_MASK = 0x7FFUL,
};

#pragma pack(1)
/**
 * struct sel3390e4_tx_bd - Transmit Buffer Descriptor (TXBD)
 */
struct sel3390e4_tx_bd {
	/* wrap, data, last, error, length bits */
	__le32 volatile stat;

	__le32 volatile reserved;

	/* DMA address of Ethernet frame to send */
	__le64 volatile tx_data_buff_ptr;
};
#pragma pack()

/**
 * enum rx_bd_flags - RXBD bits
 */
enum rx_bd_flags {
	RX_BD_EMT           = (1UL<<31),
	RX_BD_WRP           = (1UL<<29),
	RX_BD_LST           = (1UL<<27),
	RX_BD_PAR_ERR       = (1UL<<24),
	RX_BD_BABR_ERR      = (1UL<<22),
	RX_BD_DATA_LEN_MASK = 0x7FFUL,
};

#pragma pack(1)
/**
 * struct sel3390e4_rx_bd - Receive Buffer Descriptor (RXBD)
 */
struct sel3390e4_rx_bd {
	/* wrap, data, last, error, length bits */
	__le32 volatile stat;

	__le32 volatile reserved;

	/* DMA address of Ethernet frame to receive */
	__le64 volatile rx_data_buff_ptr;
};
#pragma pack()

/* PHY Registers */

static const u8 PHY_CONTROL_REGISTER = 0x00;

	static u16 const CONTROL_REGISTER_SWRESET_MASK     = (1U<<15);
	static u16 const CONTROL_REGISTER_LOOPBACK_MASK    = (1U<<14);
	static u16 const CONTROL_REGISTER_SPEEDLSB_MASK    = (1U<<13);
	static u16 const CONTROL_REGISTER_ANEGEN_MASK      = (1U<<12);
	static u16 const CONTROL_REGISTER_PWRDWN_MASK      = (1U<<11);
	static u16 const CONTROL_REGISTER_ISOLATE_MASK     = (1U<<10);
	static u16 const CONTROL_REGISTER_RESTARTANEG_MASK = (1U<<9);
	static u16 const CONTROL_REGISTER_DUPLEX_MASK      = (1U<<8);
	static u16 const CONTROL_REGISTER_COLTEST_MASK     = (1U<<7);
	static u16 const CONTROL_REGISTER_SPEEDMSB_MASK    = (1U<<6);

static const u8 PHY_STATUS_REGISTER = 0x01U;

	static u16 const STATUS_LINK_CONNECTED = (1U<<2);

static const u8 PHY_1000BASET_CONTROL_REGISTER = 0x09U;

	static u16 const PHY_ADVERTISE_1000HALF = (1U<<8);

static const u8 BROADCOM_RESERVED_ONE_REGISTER = 0x15U;
static const u8 BROADCOM_EXPANSION_SECONDARY_SERDES_REGISTER = 0x17U;

	static u16 const PHY_EXPANSION_REGISTER_VALUE = 0x0F00U;
		/* ------------------------------------------
		 * For expansion registers, the expansion value must
		 * be written to register 17h [11:8], and the register
		 * number written to the lower bits. Then the register
		 * can be read/written through reserved register 15h
		 */
		static u8 const BROADCOM_PHY_SERDES_CONTROL_REGISTER = 0x50U;

/* This shadow register has selection bits in bits [2:0]. */
static const u8 BROADCOM_BASE_T_AUX_CONTROL_REGISTER = 0x18U;

	static u16 const SHADOW_VALUE_BASE_T_MISC_CONTROL = 0x07U;

	static u16 const MISC_CONTROL_REQUIRED_SETTINGS = 0xF1D7U;

/* This shadow register has selection bits in bits [14:10] */
static const u8 BROADCOM_BASE_T_SHADOW_REGISTER = 0x1CU;

	static u16 const SHADOW_VALUE_GLOBAL_WRITE_BIT = (1U<<15);

	static u16 const SHADOW_VALUE_100BASE_FX_CONTROL = 0x4C00U;

		static u16 const PHY_ENABLE_100BASE_FX = 0x0003U;

	static u16 const SHADOW_VALUE_SPARE_CTRL_THREE = 0x1400U;

		static u16 const PHY_CLK_REQUIRED_SETTINGS = 0x951CU;

	static u16 const SHADOW_VALUE_SGMII_SLAVE = 0x5400U;
		static u16 const SGMII_SLAVE_REQUIRED_SETTINGS = 0xD489U;

	static const u16 SHADOW_VALUE_LED_SELECTOR_ONE = 0x3400U;

		static u16 const EXTERNAL_LED_ONE_COPPER_REQUIRED_SETTINGS = 0xB41CU;
		static u16 const EXTERNAL_LED_ONE_FIBER_REQUIRED_SETTINGS  = 0xB411U;

	static const u16 SHADOW_VALUE_MODE_CONTROL = 0x7C00U;

		static u16 const PHY_MODE_SELECT_MASK = 0x0006U;
		static u16 const PHY_FIBER_MODE       = (1U<<1);


/* SFP Validated Part numbers */

/* ASCII -> 8109 */
#define PART_NUM_100_BASE_FX   0x38313039UL

/* ASCII -> 8104 */
#define PART_NUM_100_BASE_LX10 0x38313034UL

/* ASCII -> 8131 */
#define PART_NUM_1000_BASE_SX  0x38313331UL

/* ASCII -> 8130 */
#define PART_NUM_1000_BASE_LX  0x38313330UL

/**
 * enum sfp_status_control - SFP Status/Control Bits
 */
enum sfp_status_control {
	SFP_1_TX_FAULT       = (1UL<<0),
	SFP_1_LOS            = (1UL<<1),
	SFP_1_ENABLE         = (1UL<<2),
	SFP_1_DETECT         = (1UL<<3),
	SFP_1_AUTH_RESULT    = (1UL<<4),
	SFP_1_AUTH_DONE      = (1UL<<5),

	SFP_2_TX_FAULT       = (1UL<<8),
	SFP_2_LOS            = (1UL<<9),
	SFP_2_ENABLE         = (1UL<<10),
	SFP_2_DETECT         = (1UL<<11),
	SFP_2_AUTH_RESULT    = (1UL<<12),
	SFP_2_AUTH_DONE      = (1UL<<13),

	SFP_3_TX_FAULT       = (1UL<<16),
	SFP_3_LOS            = (1UL<<17),
	SFP_3_ENABLE         = (1UL<<18),
	SFP_3_DETECT         = (1UL<<19),
	SFP_3_AUTH_RESULT    = (1UL<<20),
	SFP_3_AUTH_DONE      = (1UL<<21),

	SFP_4_TX_FAULT       = (1UL<<24),
	SFP_4_LOS            = (1UL<<25),
	SFP_4_ENABLE         = (1UL<<26),
	SFP_4_DETECT         = (1UL<<27),
	SFP_4_AUTH_RESULT    = (1UL<<28),
	SFP_4_AUTH_DONE      = (1UL<<29)
};

/**
 * enum sfp_ready_control - SFP Read/Control Bits
 */
enum sfp_ready_control {
	/* Write this to also initiate an update */
	SFP_VALID_DATA = (1UL<<0)
};

/**
 * enum sel3390e4_diag_color_offsets - Diagnostics color offsets used to
 * determine what port colors are being adjusted.
 */
enum sel3390e4_diag_color_offsets {
	DIAG_COLOR_OFFSET_1 = 0x0UL,
	DIAG_COLOR_OFFSET_2 = 0x4UL,
	DIAG_COLOR_OFFSET_3 = 0x8UL,
	DIAG_COLOR_OFFSET_4 = 0xCUL
};

/**
 * enum led_modes - Led modes used when setting LEDs
 */
enum diag_led_modes {
	DIAG_NORMAL                  = (0x00UL),
	DIAG_DIRECT_CONTROL          = (0x01UL << 28),
	DIAG_DIRECT_CONTROL_BLINK    = (0x02UL << 28),
	DIAG_ALARM_STATE             = (0x03UL << 28)
};

/**
 * enum led_colors - Colors used when setting LEDs
 */
enum diag_led_colors {
	DIAG_COLOR_NONE    = 0UL,
	DIAG_COLOR_YELLOW  = 1UL,
	DIAG_COLOR_GREEN   = 2UL,
	DIAG_COLOR_ALL     = 3UL
};

/**
 * enum diag_reset_ctrl_flags
 */
enum diag_reset_ctrl_flags {
	diag_force_crc_err  = (1UL<<9),
	diag_crc_err        = (1UL<<8),
	diag_force_reconfig = (1UL<<7)
};

/**
 * enum diag_intr_ctrl_flags
 */
enum diag_intr_ctrl_flags {
	diag_crc_err_en       = (1UL<<8),
	diag_diag_adc_done_en = (1UL<<0)
};

/**
 * enum diag_int_status_flags
 */
enum diag_int_status_flags {
	diag_crc_err_int       = (1UL<<8),
	diag_diag_adc_done_int = (1UL<<0)
};

/**
 * struct led_settings - Interface used when setting LEDs
 */
struct led_settings {
	/* led mode to set */
	enum diag_led_modes led_mode;

	/* led colors to set */
	enum diag_led_colors led_colors;
};

/**
 * enum statistics_status_flags - eth_statistics status flags
 */
enum statistics_status_flags {
	sft_rst      = (1UL<<31),
	gen_par_err  = (1UL<<2),
	par_err      = (1UL<<1),
	sat_err      = (1UL<<0)
};

/* --------------------------------------
 * STRUCTURES FOR DEVICE REGISTERS
 * Below are the registers for the DIAG and MAC BARs in 
 * struct form. These are defined in b2077_top_cis
 * --------------------------------------
 */

/* We pack all the structures for device registers so that
 * the compiler does not add any padding to them
 */
#pragma pack(1)

/* Diagnostics BAR */

/* Number of diagnositcs registers */
#define NUM_DIAG_REGS 9U
#define NUM_DIAG_RESERVED ((SEL3390E4_PCI_BAR_DIAG_LEN / 4) - NUM_DIAG_REGS)

/**
 * struct sel3390e4_hw_diag - Diagnostics hardware registers
 *
 * Total packed size == 0x1000 bytes
 */
struct sel3390e4_hw_diag {
	/* firmware build id */
	__le32 build_id;

	/* led mode and colors */
	__le32 led_ctrl;

	/* voltage rail data */
	__le32 rail_data[4];

	/* ctrl bits */
	__le32 reset_ctrl;

	/* interrupt enable register */
	__le32 int_ctrl;

	/* interrupt status register */
	__le32 int_status;

	/* If the bar layout changes, this needs to changes as well */
	__le32 reserved[NUM_DIAG_RESERVED];
};

/* MAC BAR */

/**
 * struct sfp_info - SFP registers
 */
struct sfp_info {
	/* transceiver Ethernet compliance code */
	__le32 compliance_code;

	/* bit rate */
	__le32 bit_rate;

	/* link length capability (9/125 um fiber, km) */
	__le32 km_link_length_cap;

	/* link length capability (9/125 um fiber, 100m) */
	__le32 m_100m_link_length_cap;

	/* link length capability (50/125 um fiber, 10m) */
	__le32 m_50_10m_link_length_cap;

	/* link length capability (62.5/125 um fiber, 10m) */
	__le32 m_62_10m_link_length_cap;

	/* link length capability (copper, meters) */
	__le32 link_length_cap_copper;

	/* link length capability (50/125 um fiber OM3) */
	__le32 link_length_cap_fiber;

	/* laser wavelength */
	__le32 laser_wavelength;

	/* diagnostic monitoring type */
	__le32 diag_monitoring_type;

	/* RX Power Low alarm */
	__le32 rx_power_low_alarm;

	/* RX Power Low Warning */
	__le32 rx_power_low_warning;

	/* Internal Temperature */
	__le32 internal_temp;

	/* Supply Voltage */
	__le32 supply_voltage;

	/* TX Bias Current */
	__le32 tx_bias_current;

	/* TX Power */
	__le32 tx_power;

	/* RX Power */
	__le32 rx_power;

	/* RX Power Low Warning/Alarm */
	__le32 rx_low_power_warning_alarm;

	/* SEL Part Number in ASCII */
	__le32 sel_part_number;

	/* SEL Part Serial Number in ASCII Word3 */
	__le32 sel_part_serial_num_3;

	/* SEL Part Serial Number in ASCII Word2 */
	__le32 sel_part_serial_num_2;

	/* SEL Part Serial Number in ASCII Word1 */
	__le32 sel_part_serial_num_1;

	/* SEL Part Serial Number in ASCII Word0 */
	__le32 sel_part_serial_num_0;
};

/* The offsets (0x0100, 0x0180, etc) can be found in the
 * b2077_top_cis
 */
#define MAC_OFFSET             0x0000U
#define MII_OFFSET             0x0100U
#define INTR_MODERATION_OFFSET 0x0180U
#define SFP_OFFSET             0x0200U
#define STATS_OFFSET           0x0400U

#define INTR_THROTTLE_DEFAULT 4U

/**
 * struct sel3390e4_hw_mac - MAC hardware registers
 *
 * Total packed size == 0x1000 bytes (4 MACs = 0x4000 byte size)
 * 1024 possible registers (64-bit regs are counted as TWO regs below)
 *
 * mac             0x0000
 * reserved_1
 * smi (mii)       0x0100
 * reserved_2
 * intr moderation 0x0180
 * reserved_3
 * sfp             0x0200
 * reserved_4
 * statistics      0x0400
 * reserved_5
 */
struct sel3390e4_hw_mac {
	/* MAC interface */
	struct mac_interface {
		/* Model number */
		__le32 mac_model;

		/* revision number for mac */
		__le32 mac_revision;

		/* Interrupt event register */
		__le32 ievent;

		/* Interrupt mask */
		__le32 imask;

		/* Misc */
		__le32 misc;

		/* Transmit status register */
		__le32 tx_stat;

		/* Current TXBD pointer register */
		__le64 curr_tx_bd_ptr;

		/* TxBD base address */
		__le64 tx_bd_base_addr;

		/* Receive control register */
		__le32 rx_ctl;

		/* Receive status register */
		__le32 rx_stat;

		/* Current RXBD pointer register */
		__le64 curr_rx_bd_ptr;

		/* RxBD base address */
		__le64 rx_bd_base_addr;

		/* MAC configuration register 1 */
		__le32 mac_config;

		/* Maximum frame length register */
		__le32 max_frame_len;

		/* MACSTNADDR1 and MACSTNADDR2 registers */
		__le32 mac_stn_addr[2];

		/* Rx length register for external DMA controller */
		__le32 rx_len;

		/* Tx length register for external DMA controller */
		__le32 tx_len;

		/* mac status register for external DMA controller */
		__le32 mac_status;

#define NUM_GROUP_ADDR_REGS 8U
		/* group address registers */
		__le32 group_addr[NUM_GROUP_ADDR_REGS];
	} mac;

#define NUM_MAC_RESERVED_1 \
	(((MII_OFFSET - MAC_OFFSET) / 4) \
		- (sizeof(struct mac_interface) / 4))

	/* If the bar layout changes, this needs to changes as well */
	__le32 reserved_1[NUM_MAC_RESERVED_1];

	/* MII interface */
	struct mii_interface {
		/* MII configuration */
		__le32 cfg;

		/* MII communication register */
		__le32 comm;

		/* MII Address */
		__le32 address;

		/* MII control */
		__le32 control;

		/* MII status */
		__le32 stat;

		/* MII indicator register */
		__le32 ind;

	} mii_bus;

#define NUM_MAC_RESERVED_2 \
	(((INTR_MODERATION_OFFSET - MII_OFFSET) / 4) \
		- (sizeof(struct mii_interface) / 4))

	__le32 reserved_2[NUM_MAC_RESERVED_2];

	/* Interrupt moderation */
	struct intr_moderation_interface {
		/* RX absolute timer */
		__le32 rx_abs;

		/* RX packet inactivity timer */
		__le32 rx_packet;

		/* TX absolute timer */
		__le32 tx_abs;

		/* TX packet inactivity timer */
		__le32 tx_packet;

		/* Max interrupts allowed per second */
		__le32 intr_throttle;

		/* Timer tick rate */
		__le32 intr_tick;
	} intr_moderation;

#define NUM_MAC_RESERVED_3 \
	(((SFP_OFFSET - INTR_MODERATION_OFFSET) / 4) \
		- (sizeof(struct intr_moderation_interface) / 4))

	__le32 reserved_3[NUM_MAC_RESERVED_3];

	/* SFP Management */
	struct sfp_interface {
		/* r/w SFP status and control */
		__le32 status_control;

		/* SFP EEPROM read control */
		__le32 read_control;

		/* SFP Info for port 0 */
		struct sfp_info sfp_0;

		__le32 reserved_1[9];

		/* SFP Info for port 1 */
		struct sfp_info sfp_1;

		__le32 reserved_2[9];

		/* SFP Info for port 2 */
		struct sfp_info sfp_2;

		__le32 reserved_3[9];

		/* SFP Info for port 3 */
		struct sfp_info sfp_3;

		__le32 reserved_4[7];

	} sfp_mgmt;

#define NUM_MAC_RESERVED_4 \
	(((STATS_OFFSET - SFP_OFFSET) / 4) \
		- (sizeof(struct sfp_interface) / 4))

	__le32 reserved_4[NUM_MAC_RESERVED_4];

	/* Statistics */
	struct stats_interface {
		/* Status register */
		__le32 status;

		/* Number of packets sent that pass CRC check */
		__le32 out_packets;

		/* Number of bad packets sent, including those due to
		 * collisions, retransmissions, buffer underflow, and
		 * discard frames.
		 */
		__le32 out_frag_packets;

		/* Number of half-duplex collisions */
		__le32 restart_frames;

		/* Number of frames aborted due to excessive collisions */
		__le32 excessive_collisions;

		/* Number of packets received that pass CRC check */
		__le32 in_packets;

		/* Number of frames received with CRC errors */
		__le32 in_crc_err;

		/* Number of events where data was lost due to buffer overflow */
		__le32 in_buff_ovf;

		/* Number of packets received with size less than 64 bytes */
		__le32 in_runt_packets;

		/* Number of packets received with exactly 64 bytes */
		__le32 in_64_packets;

		/* Number of packets received with size between 65 and 127 bytes */
		__le32 in_65_127_packets;

		/* Number of packets received with size between 128 and 255 bytes */
		__le32 in_128_255_packets;

		/* Number of packets received with size between 256 and 511 bytes */
		__le32 in_256_511_packets;

		/* Number of packets received with size between 512 and 1023 bytes */
		__le32 in_512_1023_packets;

		/* Number of packets received with size 1024 and 1518 bytes */
		__le32 in_1024_1518_packets;

		/* Number of packets received with size greater than 1518 bytes */
		__le32 jumbo_packets;

		/* Number of broadcast packets received */
		__le32 in_broadcast_packets;

		/* Number of multicast packets received */
		__le32 in_multicast_packets;

		/* Number of unicast packets received */
		__le32 in_unicast_packets;

		/* Number of packets received that were neither broadcast, nor
		 * multicast, nor unicast, and were rejected because promiscuous
		 * mode is disabled.
		 */
		__le32 in_misses;

		/* Number of packets received that were only accepted because
		 * promiscuous mode was enabled.
		 */
		__le32 in_promiscuous_only_packets;

		/* Number of packets discarded due to uncorrectable parity errors
		 * in the transmit FIFO.
		 */
		__le32 out_discards;

		/* Number of packets discarded due to uncorrectable parity errors
		* in the received FIFO.
		*/
		__le32 in_discards;

		/* Number of output octets (good or bad) */
		__le32 out_octets;

		/* Number of bytes received, included CRC bytes */
		__le32 in_octets;

	} stats;

#define NUM_MAC_RESERVED_5 \
	(((SEL3390E4_MAC_REG_SIZE - STATS_OFFSET) / 4) \
		- (sizeof(struct stats_interface) / 4))

	__le32 reserved_5[NUM_MAC_RESERVED_5];
};

/* Done packing device registers */
#pragma pack()

#endif /* SEL3390E4_HW_REGS_H_INCLUDED */
