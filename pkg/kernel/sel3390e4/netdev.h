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
 * Provides Access to the network interface
 ******************************************************************************
 */

#ifndef SEL3390E4_NETDEV_H_INCLUDED
#define SEL3390E4_NETDEV_H_INCLUDED

#include <linux/types.h> /* types */

#include "sel3390e4.h"   /* 3390 definitions */

/**
 * sel3390e4_up() - Initialize and start the network interface
 *
 * @mac: net device context
 *
 * Return: 0 if successful, otherwise appropriate negative error value
 */
int sel3390e4_up(struct sel3390e4_mac *mac);

/**
 * sel3390e4_down() - Shutdown the network interface
 *
 * @mac: net device context
 */
void sel3390e4_down(struct sel3390e4_mac *mac);

/**
 * sel3390e4_unregister_net_devices() - Unregister all the netdevices
 *
 * @board: pci device context
 */
void sel3390e4_unregister_net_devices(struct sel3390e4_board *board);

/**
 * sel3390e4_register_net_devices() - Register all the netdevices
 *
 * @board: pci device context
 *
 * Return: 0 if successful, otherwise negative error code
 */
int sel3390e4_register_net_devices(struct sel3390e4_board *board);

/**
 * sel3390e4_free_net_devices() - Free all the netdevices
 *
 * @board: pci device context
 */
void sel3390e4_free_net_devices(struct sel3390e4_board *board);

/**
 * sel3390e4_allocate_net_devices() - Allocate and setup all the netdevices
 *
 * @board: pci device context
 *
 * Return: 0 if successful, otherwise negative error code
 */
int sel3390e4_allocate_net_devices(struct sel3390e4_board *board);

#endif /* SEL3390E4_NETDEV_H_INCLUDED */
