// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package maclookup

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

const (
	// siocEthtool is the ioctl request code for ethtool operations.
	siocEthtool = 0x8946
	// ethtoolGpermaddr is the ethtool command to get the permanent hardware address.
	ethtoolGpermaddr = 0x20
)

// MacLookup : lookup network interface by its (permanent) MAC address.
// Information about network interfaces is cached. Call RefreshCache() to flush
// and reload the cache content.
type MacLookup struct {
	sync.Mutex
	cachedIfs []NetIf
}

// NetIf : network interface.
type NetIf struct {
	IfIndex int
	IfName  string
	MAC     net.HardwareAddr
}

// GetInterfaceByMAC : lookup network interface by its MAC address.
func (m *MacLookup) GetInterfaceByMAC(mac net.HardwareAddr, prefix bool) (
	netIf NetIf, found bool) {
	m.Lock()
	defer m.Unlock()
	for _, cachedIf := range m.cachedIfs {
		if prefix {
			if bytes.HasPrefix(cachedIf.MAC, mac) {
				return cachedIf, true
			}
		} else {
			if bytes.Equal(cachedIf.MAC, mac) {
				return cachedIf, true
			}
		}
	}
	return NetIf{}, false
}

// GetInterfaceByIndex : get network interface by its index
// (Linux kernel interface handle).
func (m *MacLookup) GetInterfaceByIndex(ifIndex int) (netIf NetIf, found bool) {
	m.Lock()
	defer m.Unlock()
	for _, cachedIf := range m.cachedIfs {
		if cachedIf.IfIndex == ifIndex {
			return cachedIf, true
		}
	}
	return NetIf{}, false
}

// GetInterfaceByName : get network interface by its name.
func (m *MacLookup) GetInterfaceByName(ifName string) (netIf NetIf, found bool) {
	m.Lock()
	defer m.Unlock()
	for _, cachedIf := range m.cachedIfs {
		if cachedIf.IfName == ifName {
			return cachedIf, true
		}
	}
	return NetIf{}, false
}

// RefreshCache should be called initially and when the cached data
// are suspected to be stale.
func (m *MacLookup) RefreshCache() {
	m.Lock()
	defer m.Unlock()
	m.cachedIfs = []NetIf{}
	netIfs, err := net.Interfaces()
	if err != nil {
		log.Warnf("failed to list network interfaces: %v", err)
		return
	}
	for _, networkIf := range netIfs {
		netIf := NetIf{
			IfIndex: networkIf.Index,
			IfName:  networkIf.Name,
			MAC:     networkIf.HardwareAddr,
		}
		mac, err := m.getPermanentMAC(networkIf.Name)
		if err != nil {
			log.Warnf("getPermanentMAC(%s) failed: %v", networkIf.Name, err)
		} else if mac != nil {
			netIf.MAC = mac
		}
		m.cachedIfs = append(m.cachedIfs, netIf)
	}
}

// Get interface permanent MAC address - not the one assigned by bonding driver for example.
func (m *MacLookup) getPermanentMAC(ifName string) (net.HardwareAddr, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
		if err != nil {
			return nil, err
		}
	}
	var data struct {
		cmd  uint32
		size uint32
		data [128]byte
	}
	var ifr struct {
		IfrName [16]byte
		IfrData unsafe.Pointer
	}
	data.cmd = ethtoolGpermaddr
	data.size = 128
	copy(ifr.IfrName[:], ifName)
	ifr.IfrData = unsafe.Pointer(&data)
	_, _, sysErr := syscall.RawSyscall(syscall.SYS_IOCTL,
		uintptr(fd), uintptr(siocEthtool), uintptr(unsafe.Pointer(&ifr)))
	if sysErr != 0 {
		return nil, fmt.Errorf("RawSyscall failed with errno %d", sysErr)
	}
	// If mac address is all zero, this is a virtual adapter and we ignore it.
	virtIf := true
	var i uint32
	for i = 0; i < data.size; i++ {
		if data.data[i] != 0x00 {
			virtIf = false
			break
		}
	}
	if virtIf {
		return nil, nil
	}
	mac := strings.ToUpper(hex.EncodeToString(data.data[0:data.size]))
	if len(mac) > 12 {
		return nil, nil
	}
	for i := 10; i > 0; i = i - 2 {
		mac = fmt.Sprintf("%s:%s", mac[:i], mac[i:])
	}
	return net.ParseMAC(mac)
}
