// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "edge-dev"

	// Image of the general-purpose test container (ships sshd, curl, iproute2, ...).
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"
	ubuntuCtrTag   = "1.0"

	// Image of the container that prints a startup banner and periodic
	// heartbeats, used by the application log test.
	loggerCtrImage = "lfedge/evetest-logger-ctr"
	loggerCtrTag   = "1.0"

	// Local network instance shared by the tests in this package.
	niDisplayName = "local-ni"
	niSubnet      = "10.11.12.0/24"
	niGateway     = "10.11.12.1"

	// Port on the edge node forwarded to the app's sshd.
	appSSHFwdPort = 2222
)

// Credentials baked into the evetest-ubuntu-ctr image.
var appAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

// addLocalNI adds the local network instance shared by the tests in this
// package: 10.11.12.0/24 on ethernet0, which is also where the metadata
// server (169.254.169.254) is reachable from connected apps.
func addLocalNI(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: niDisplayName,
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet(niSubnet),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress(niGateway),
		MTU:     1500,
	})
}

// singleVIFWithSSH describes the app network adapter used by tests that need
// to run commands inside the application: a VIF on the local NI, the sshd
// port forwarded from the edge node, and an allow-all ACL (needed among other
// things to reach the metadata server).
func singleVIFWithSSH(niUUID uuid.UUID) []evetest.AppNetworkAdapter {
	return singleVIFWithSSHOnPort(niUUID, appSSHFwdPort)
}

// singleVIFWithSSHOnPort is singleVIFWithSSH with the forwarded port spelled
// out. The forwarded port belongs to the edge node, not to the app, so a test
// deploying several reachable apps at once must give each one its own -- two
// apps forwarding the same port cannot both be reached.
func singleVIFWithSSHOnPort(niUUID uuid.UUID,
	edgeNodePort uint16) []evetest.AppNetworkAdapter {
	return []evetest.AppNetworkAdapter{
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif0",
			NetworkInstanceUUID: niUUID,
			PortFwdRules: []evetest.PortFwdRule{
				{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: edgeNodePort,
					AppPort:      22,
				},
			},
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
		},
	}
}

// deleteAppAndWait removes the application from the device configuration,
// applies it, and blocks until the device reports the instance as gone. Tests
// wait for this rather than just applying the deletion, so that teardown
// cannot race the device-config reset performed before the next test in the
// suite.
func deleteAppAndWait(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, appUUID uuid.UUID) {
	const timeout = 5 * time.Minute
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Application instance is deleted",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
}

// waitForAppSSH blocks until commands can be executed inside the application
// over the port-forwarded sshd. Reaching RUNNING only means the domain was
// created; sshd inside the container needs more time to accept connections.
func waitForAppSSH(t *WithT, device *evetest.EdgeDevice, appUUID uuid.UUID) {
	const (
		sshTimeout = 20 * time.Second
		timeout    = 3 * time.Minute
		polling    = 5 * time.Second
	)
	evetest.Logger().Infof("Waiting for app %q SSH to become reachable...", appUUID)
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo hello", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("hello"))
	}, timeout, polling).Should(Succeed())
}
