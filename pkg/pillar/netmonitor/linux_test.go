// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmonitor_test

import (
	"net"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

func TestParseDHCPv4Lease(t *testing.T) {
	tests := []struct {
		name           string
		leaseData      string
		wantSubnet     *net.IPNet
		wantNTPServers []netutils.HostnameOrIP
	}{
		{
			name: "With one NTP server",
			leaseData: `
				network_number=192.168.1.0
				subnet_cidr=24
				ntp_servers=132.163.96.5
			`,
			wantSubnet: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.CIDRMask(24, 32),
			},
			wantNTPServers: netutils.NewHostnameOrIPs("132.163.96.5"),
		},
		{
			name: "With multiple NTP servers",
			leaseData: `
				network_number=10.0.0.0
				subnet_cidr=8
				ntp_servers=8.8.8.8 1.1.1.1
			`,
			wantSubnet: &net.IPNet{
				IP:   net.IPv4(10, 0, 0, 0),
				Mask: net.CIDRMask(8, 32),
			},
			wantNTPServers: netutils.NewHostnameOrIPs("8.8.8.8", "1.1.1.1"),
		},
		{
			name: "No NTP servers",
			leaseData: `
				network_number=172.16.0.0
				subnet_cidr=12
			`,
			wantSubnet: &net.IPNet{
				IP:   net.IPv4(172, 16, 0, 0),
				Mask: net.CIDRMask(12, 32),
			},
			wantNTPServers: nil,
		},
		{
			name: "Missing subnet_cidr",
			leaseData: `
				network_number=192.168.5.0
			`,
			wantSubnet:     nil,
			wantNTPServers: nil,
		},
		{
			name: "Missing network_number",
			leaseData: `
				subnet_cidr=24
			`,
			wantSubnet:     nil,
			wantNTPServers: nil,
		},
		{
			name: "With NTP hostname address",
			leaseData: `
				network_number=192.168.1.0
				subnet_cidr=24
				ntp_servers=pool.ntp.org 1.2.3.4 1.ubnt.pool.ntp.org
			`,
			wantSubnet: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.CIDRMask(24, 32),
			},
			wantNTPServers: netutils.NewHostnameOrIPs(
				"1.2.3.4", "pool.ntp.org", "1.ubnt.pool.ntp.org"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet, ntpServers, err :=
				netmonitor.ParseDHCPv4Lease(tt.leaseData)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !netutils.EqualIPNets(subnet, tt.wantSubnet) {
				t.Errorf("Expected subnet %v, got %v", tt.wantSubnet, subnet)
			}
			if !generics.EqualSetsFn(
				ntpServers, tt.wantNTPServers, netutils.EqualHostnameOrIPs) {
				t.Errorf("Expected NTP servers %v, got %v", tt.wantNTPServers, ntpServers)
			}
		})
	}
}

func TestParseDHCPv6Lease(t *testing.T) {
	tests := []struct {
		name           string
		leaseData      string
		wantSubnets    []*net.IPNet
		wantNTPServers []netutils.HostnameOrIP
	}{
		{
			name: "Single router with one prefix and multiple NTP servers",
			leaseData: `
				nd1_prefix_information1_length=64
				nd1_prefix_information1_prefix=fd00::
				nd1_prefix_information1_vltime=2592000
				nd1_prefix_information1_pltime=604800
				dhcp6_ntp_server_addr=2001:4860:4860::64 2001:4860:4860::65
			`,
			wantSubnets: []*net.IPNet{
				{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)},
			},
			wantNTPServers: netutils.NewHostnameOrIPs(
				"2001:4860:4860::64", "2001:4860:4860::65"),
		},
		{
			name: "Multiple routers and prefixes",
			leaseData: `
				nd1_prefix_information1_length=64
				nd1_prefix_information1_prefix=fd00::
				nd2_prefix_information1_length=48
				nd2_prefix_information1_prefix=fd01::
				nd2_prefix_information2_length=48
				nd2_prefix_information2_prefix=fd02::
			`,
			wantSubnets: []*net.IPNet{
				{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)},
				{IP: net.ParseIP("fd01::"), Mask: net.CIDRMask(48, 128)},
				{IP: net.ParseIP("fd02::"), Mask: net.CIDRMask(48, 128)},
			},
		},
		{
			name: "Missing prefix length",
			leaseData: `
				nd1_prefix_information1_prefix=fd00::
			`,
			wantSubnets: nil,
		},
		{
			name: "Invalid length value",
			leaseData: `
				nd1_prefix_information1_length=bogus
				nd1_prefix_information1_prefix=fd00::
			`,
			wantSubnets: nil,
		},
		{
			name: "Unrelated RA entries only",
			leaseData: `
				protocol=ra
				nd1_flags=O
			`,
			wantSubnets: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnets, ntpServers, err := netmonitor.ParseDHCPv6Lease(tt.leaseData)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !generics.EqualSetsFn(subnets, tt.wantSubnets, netutils.EqualIPNets) {
				t.Errorf("Expected subnets %v, got %v", tt.wantSubnets, subnets)
			}
			if !generics.EqualSetsFn(
				ntpServers, tt.wantNTPServers, netutils.EqualHostnameOrIPs) {
				t.Errorf("Expected NTP servers %v, got %v", tt.wantNTPServers, ntpServers)
			}
		})
	}
}
