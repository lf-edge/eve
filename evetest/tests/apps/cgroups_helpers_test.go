// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Helpers for the tests of EVE's cgroups and of where its processes run.

package apps_test

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
)

// deviceFacts runs script on the device and returns the key=value pairs it
// prints, one per line.
func deviceFacts(t *WithT, device *evetest.EdgeDevice, script string) map[string]string {
	stdout, stderr, err := device.RunShellScript(script, 2*time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "device script failed: %s", stderr)
	facts := make(map[string]string)
	for _, line := range strings.Split(stdout, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			facts[k] = strings.TrimSpace(v)
		}
	}
	return facts
}

// kernelArg returns the value of name=<value> on the kernel command line.
func kernelArg(cmdline, name string) string {
	m := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(name) + `=(\S*)`).FindStringSubmatch(cmdline)
	if m == nil {
		return ""
	}
	return m[1]
}

// memArg returns, in bytes, the soft and hard values of a "<soft>[,max:<hard>]"
// memory argument (dom0_mem, eve_mem, ctrd_mem) as 010-eve-cgroup applies it:
// hard defaults to soft, soft to def.
func memArg(cmdline, name string, def uint64) (soft, hard uint64) {
	softStr, hardStr, _ := strings.Cut(kernelArg(cmdline, name), ",max:")
	soft = sizeBytes(softStr, def)
	return soft, sizeBytes(hardStr, soft)
}

// sizeBytes parses a size with an optional K, M or G suffix; def when empty.
func sizeBytes(s string, def uint64) uint64 {
	if s == "" {
		return def
	}
	mult := map[string]uint64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[strings.ToUpper(s[len(s)-1:])]
	if mult != 0 {
		s = s[:len(s)-1]
	} else {
		mult = 1
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	return n * mult
}

// cpusArg returns the CPU count of name=<n> capped at ceiling, 1 when absent
// or 0, as 010-eve-cgroup applies it.
func cpusArg(cmdline, name string, ceiling int) int {
	n, err := strconv.Atoi(kernelArg(cmdline, name))
	if err != nil || n == 0 {
		n = 1
	}
	if n > ceiling {
		n = ceiling
	}
	return n
}

// cpuList is the cpuset list of the first n CPUs.
func cpuList(n int) string {
	if n == 1 {
		return "0"
	}
	return fmt.Sprintf("0-%d", n-1)
}

// addMgmtPort makes eth0 a DHCP management and apps port.
func addMgmtPort(devConfig *evetest.EdgeDeviceConfig) {
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
}

// addLoggerApp adds the management port, a local NI and a small container
// app (1 vCPU, 256 MiB): enough for EVE to run a task, its shim and its
// cgroup.
func addLoggerApp(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	addMgmtPort(devConfig)
	niUUID := addLocalNI(devConfig)
	return devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "cgroup-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: loggerCtrImage,
			Tag:       loggerCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})
}
