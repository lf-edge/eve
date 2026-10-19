// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package utils

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// CreateTUN creates a new TUN (network tunnel) interface with the specified name.
// The interface is configured in TUN mode (no packet information header) and
// opened for read/write access via /dev/net/tun.
//
// The caller is responsible for configuring IP addresses, MTU, and routes,
// as well as closing the returned file descriptor when no longer needed.
//
// See: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
func CreateTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	var ifr [unix.IFNAMSIZ + 64]byte
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	f := os.NewFile(uintptr(fd), name)
	return f, nil
}

// CreateBridge creates a Linux bridge with the given name, brings it up,
// and assigns the specified IP addresses to it. IPs can be IPv4 or IPv6.
func CreateBridge(name string, addrs []*net.IPNet, groupFwdMask uint16) error {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if groupFwdMask != 0 {
		br.GroupFwdMask = &groupFwdMask
	}
	if err := netlink.LinkAdd(br); err != nil {
		return fmt.Errorf("failed to add bridge %q: %w", name, err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return fmt.Errorf("failed to set bridge %q UP: %w", name, err)
	}
	for _, ipnet := range addrs {
		addr := &netlink.Addr{IPNet: ipnet}
		if err := netlink.AddrAdd(br, addr); err != nil {
			return fmt.Errorf("failed to assign IP %s to bridge %q: %w",
				ipnet.String(), name, err)
		}
	}
	return nil
}

// DeleteBridge brings a bridge DOWN and deletes it.
func DeleteBridge(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link for bridge %q: %w", name, err)
	}
	if err = netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("failed to set bridge %q DOWN: %w", name, err)
	}
	if err = netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete bridge %q: %w", name, err)
	}
	return nil
}

// CreateTap creates a TAP interface and brings it UP.
func CreateTap(name string) error {
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Mode: netlink.TUNTAP_MODE_TAP,
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return fmt.Errorf("failed to create TAP %q: %w", name, err)
	}
	if err := netlink.LinkSetUp(tap); err != nil {
		return fmt.Errorf("failed to set TAP %q UP: %w", name, err)
	}
	return nil
}

// DeleteTap deletes a TAP interface.
func DeleteTap(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link for TAP %q: %w", name, err)
	}
	if err = netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("failed to set TAP %q DOWN: %w", name, err)
	}
	if err = netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete TAP %q: %w", name, err)
	}
	return nil
}

// ConnectTapToBridge attaches a TAP interface to a Linux bridge by setting
// the bridge as the TAP interface's master.
func ConnectTapToBridge(bridgeName, tapName string) error {
	br, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return fmt.Errorf("bridge %q not found: %w", bridgeName, err)
	}
	tap, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("TAP %q not found: %w", tapName, err)
	}
	if err = netlink.LinkSetMaster(tap, br); err != nil {
		return fmt.Errorf("failed to attach TAP %q to bridge %q: %w",
			tapName, bridgeName, err)
	}
	return nil
}

// CreateDummyInterface creates a dummy interface with the given name and assigns
// the provided IP addresses.
// Each IP should include the CIDR mask (/32 for IPv4, /128 for IPv6).
func CreateDummyInterface(name string, ips []net.IPNet) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("failed to create dummy %q: %w", name, err)
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		return fmt.Errorf("failed to bring up dummy %q: %w", name, err)
	}
	for _, ip := range ips {
		addr := &netlink.Addr{IPNet: &ip}
		err := netlink.AddrAdd(dummy, addr)
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to add IP %s to dummy %q: %w",
				ip.String(), name, err)
		}
	}
	return nil
}
