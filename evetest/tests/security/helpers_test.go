// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Shared constants and helpers for the device-security tests.

package security

import (
	"encoding/base64"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	evecerts "github.com/lf-edge/eve-api/go/certs"
	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	devName = "edge-dev"

	// General-purpose test container image (ships sshd).
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"
	ubuntuCtrTag   = "1.0"

	niDisplayName = "local-ni"
	niSubnet      = "10.11.12.0/24"
	niGateway     = "10.11.12.1"

	// EVE turns plain "key=value" user data into environment variables of the
	// container's init process, so finding it there proves the block was decrypted.
	userDataMarkerKey = "EVETEST_CERT_ROTATION_MARKER"

	appRunningTimeout = 10 * time.Minute

	appMarkerReadTimeout = 5 * time.Minute

	appSSHTimeout = 20 * time.Second

	controllerCertTimeout = 3 * time.Minute

	// The framework lowers the metric publishing interval to 20s.
	cipherMetricsTimeout = 2 * time.Minute

	pollingInterval = 5 * time.Second
)

// Credentials baked into the evetest-ubuntu-ctr image.
var appAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

// addLocalNI adds the network instance shared by this package's applications.
func addLocalNI(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: niDisplayName,
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet(niSubnet),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress(niGateway),
		MTU:     1500,
	})
}

// deployEncryptedUserDataApp adds a container application whose user data is
// delivered inside a CipherBlock (encrypted against the controller's current ECDH
// certificate). sshFwdPort must be unique: it identifies the application's sshd.
func deployEncryptedUserDataApp(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, niUUID uuid.UUID, appName string,
	sshFwdPort uint16, marker string) uuid.UUID {

	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: appName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: sshFwdPort,
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
		},
		// EVE base64-decodes user data on the object-encrypted path too.
		UserData: base64.StdEncoding.EncodeToString(
			[]byte(userDataMarkerKey + "=" + marker + "\n")),
	})
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	assertUserDataDecrypted(t, device, appUUID, marker)
	return appUUID
}

// assertUserDataDecrypted asserts that the container's init-process environment
// carries the marker from the object-encrypted user data. /proc/1/environ rather
// than the session environment, which sshd sanitizes. Retried as a whole: RUNNING
// only means the domain was created, sshd needs longer, and the port-forward can
// fail transiently.
func assertUserDataDecrypted(t *WithT, device *evetest.EdgeDevice,
	appUUID uuid.UUID, marker string) {

	evetest.Logger().Infof("Reading back the user-data marker of app %q...", appUUID)
	t.Eventually(func(g Gomega) {
		environ, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"tr '\\0' '\\n' < /proc/1/environ", appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(strings.Split(environ, "\n")).To(
			ContainElement(userDataMarkerKey+"="+marker),
			"the application's object-encrypted user data was not decrypted")
	}, appMarkerReadTimeout, pollingInterval).Should(Succeed())
}

// assertDeviceHasControllerCert reads EVE's ephemeral (/run) ControllerCert
// publication and so requires EVE >= 16.9.3, where the topic stopped being
// persisted; on older builds it fails as if the device held no certificate.
func assertDeviceHasControllerCert(t *WithT, device *evetest.EdgeDevice,
	certType evecerts.ZCertType, expectedCertPEM []byte) {

	device.WaitUntilHasControllerCert(certType, expectedCertPEM,
		controllerCertTimeout)
}

// assertCipherDecryptionSucceeded checks domainmgr's cipher counters in a
// DeviceMetric published after this call. This is the only assertion in these
// tests that fails when decryption silently does nothing: a failed decrypt leaves
// no error on the cipher block, none on the application, and boots it with an
// empty environment -- but it does increment these counters.
//
// Tc carries only the non-zero counters, and none may be non-zero: domainmgr
// enters the cipher path only for applications carrying user data, which the
// framework always encrypts once onboarded, so even CIPHER_ERROR_NO_CIPHER is a
// failure here.
func assertCipherDecryptionSucceeded(t *WithT, device *evetest.EdgeDevice) {
	metricUpdates, stopMetricWatch := device.WatchDeviceMetrics()
	defer stopMetricWatch()
	evetest.Logger().Infof("Waiting for domainmgr cipher metrics...")
	var cipherMetric *evemetrics.CipherMetric
	t.Eventually(metricUpdates, cipherMetricsTimeout).Should(
		Receive(matchers.SatisfyPredicate(
			"Device reports cipher metrics for domainmgr",
			func(dm *evemetrics.DeviceMetric) bool {
				for _, cm := range dm.GetCipher() {
					if cm.GetAgentName() == "domainmgr" {
						cipherMetric = cm
						return true
					}
				}
				return false
			})))
	t.Expect(cipherMetric.GetSuccessCount()).To(BeNumerically(">", 0),
		"domainmgr did not decrypt a single cipher block")
	t.Expect(cipherMetric.GetFailureCount()).To(BeZero())
	t.Expect(cipherMetric.GetTc()).To(BeEmpty(),
		"domainmgr recorded cipher errors: %v", cipherMetric.GetTc())
}

// appBootTime returns the boot time the controller reports for the application.
// EVE stamps it anew on every domain create, so unlike liveness it tells a
// recreated application apart from an undisturbed one.
func appBootTime(t *WithT, device *evetest.EdgeDevice, appUUID uuid.UUID) time.Time {
	info := device.GetAppInfo(appUUID)
	t.Expect(info).ToNot(BeNil())
	t.Expect(info.GetBootTime().IsValid()).To(BeTrue(),
		"the device reports no boot time for application %v", appUUID)
	return info.GetBootTime().AsTime()
}

// singleMgmtPortWithLocalNI builds and applies the device configuration shared by
// the certificate rotation tests.
func singleMgmtPortWithLocalNI(device *evetest.EdgeDevice,
	hypervisor evetest.Hypervisor) (*evetest.EdgeDeviceConfig, uuid.UUID) {

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Pin the periodic /certs refetch to EVE's 24h default, so the fast trigger is
	// the only path that can satisfy these tests.
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.CertInterval, 86400)
	devConfig.SetConfigProperties(cfgProps)

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
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	return devConfig, addLocalNI(devConfig)
}

// deleteAppAndWait removes the application and blocks until the device reports the
// instance gone, so teardown cannot race the next test's device-config reset.
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
			return info.GetState() == eveinfo.ZSwState_INVALID
		})))
}
