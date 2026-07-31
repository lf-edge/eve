// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
	"fmt"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/evetest"
)

// LPS token used by every LPS test in this package.
const lpsServerToken = "server_token_123"

// Shared management-API paths, reused by every LPS test in this package.
const (
	lpsLocalBaseURL         = "http://localhost:8888"
	lpsManageURL            = lpsLocalBaseURL + "/manage/v1"
	lpsManageTokenURL       = lpsManageURL + "/token"
	lpsManageProfileURL     = lpsManageURL + "/profile"
	lpsManageRadioStatusURL = lpsManageURL + "/radio-status"
	lpsManageRadioConfigURL = lpsManageURL + "/radio-config"
	lpsManageAppInfoURL     = lpsManageURL + "/appinfo"
	lpsManageAppCommandURL  = lpsManageURL + "/app-command"
	lpsManageDevInfoURL     = lpsManageURL + "/devinfo"
	lpsManageDevCommandURL  = lpsManageURL + "/dev-command"
	lpsManageNetConfigURL   = lpsManageURL + "/network-config"
)

// lpsAppAuth is the fixed SSH credential baked into the evetest-lps image.
var lpsAppAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

// newLPSAppConfig returns the ApplicationInstanceConfig for the evetest-lps
// container app, wired to niUUID with SSH (port sshPort) and management-API
// (port 8888) port-forwarding. The caller adds it to a devConfig and is
// responsible for calling ApplyConfig / WaitUntilAppIsRunning.
func newLPSAppConfig(displayName string, niUUID uuid.UUID, sshPort uint16) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: displayName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-lps",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: sshPort,
						AppPort:      22,
					},
					{
						// For developers troubleshooting LPS who need access to the
						// UI: pause the test once the app is running, then run
						// `evetest eve portfwd 8888:8888` and open
						// http://localhost:8888 in a browser.
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 8888,
						AppPort:      8888,
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
	}
}

// waitLPSAppReady waits for the LPS app to become reachable over SSH,
// configures the LPS server token via its management API, and returns the
// app's IP address (used to build LPSConfig.Address for SetLPS).
func waitLPSAppReady(
	t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, token string) string {
	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	timeout := 3 * time.Minute
	log := evetest.Logger()

	log.Infof("Waiting for LPS app SSH to become reachable...")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, lpsAppAuth,
			"echo hello", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("hello"))
	}, timeout, polling).Should(Succeed())

	_, _, err := device.RunShellScriptInsideApp(appUUID, lpsAppAuth,
		fmt.Sprintf(`curl -sS -X PUT -d '{"token":"%s"}' `+lpsManageTokenURL, token),
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	output, _, err := device.RunShellScriptInsideApp(appUUID, lpsAppAuth,
		"hostname -I | awk '{print $1}'", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	ip := strings.TrimSpace(output)
	log.Infof("LPS app IP: %s", ip)
	return ip
}

// runInLPSApp runs a shell command inside the LPS app over SSH and fails the
// assertion (via t) on any transport-level error.
func runInLPSApp(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, script string) string {
	output, _, err := device.RunShellScriptInsideApp(appUUID, lpsAppAuth,
		script, 20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
	return output
}

// getLPSRadioStatus retrieves and parses the radio status that EVE posted
// to the LPS (GET /manage/v1/radio-status).
func getLPSRadioStatus(
	t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) *profile.RadioStatus {
	output := runInLPSApp(t, device, appUUID, "curl -sS "+lpsManageRadioStatusURL)
	var status profile.RadioStatus
	t.Expect(protojson.Unmarshal([]byte(output), &status)).To(Succeed())
	return &status
}

// getLPSAppInfo retrieves and parses the app info list that EVE posted to
// the LPS (GET /manage/v1/appinfo).
func getLPSAppInfo(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) *profile.LocalAppInfoList {
	output := runInLPSApp(t, device, appUUID, "curl -sS "+lpsManageAppInfoURL)
	var list profile.LocalAppInfoList
	t.Expect(protojson.Unmarshal([]byte(output), &list)).To(Succeed())
	return &list
}

// getLPSDevInfo retrieves and parses the device info that EVE posted to the
// LPS (GET /manage/v1/devinfo).
func getLPSDevInfo(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) *profile.LocalDevInfo {
	output := runInLPSApp(t, device, appUUID, "curl -sS "+lpsManageDevInfoURL)
	var info profile.LocalDevInfo
	t.Expect(protojson.Unmarshal([]byte(output), &info)).To(Succeed())
	return &info
}

// getLPSNetworkInfo retrieves and parses the network info that EVE posted to the LPS.
func getLPSNetworkInfo(t Gomega, device *evetest.EdgeDevice,
	appUUID uuid.UUID) *profile.NetworkInfo {
	output := runInLPSApp(t, device, appUUID, "curl -sS "+lpsManageURL+"/network")
	var netInfo profile.NetworkInfo
	t.Expect(protojson.Unmarshal([]byte(output), &netInfo)).To(Succeed())
	return &netInfo
}

// putLPSProfile sets the local profile the LPS reports back to EVE
// (PUT /manage/v1/profile).
func putLPSProfile(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, profileName string) {
	runInLPSApp(t, device, appUUID, fmt.Sprintf(
		`curl -sS -X PUT -d '{"profile":"%s"}' `+lpsManageProfileURL, profileName))
}

// putLPSRadioSilence sets the radio-silence config the LPS reports back to
// EVE (PUT /manage/v1/radio-config).
func putLPSRadioSilence(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, silence bool) {
	runInLPSApp(t, device, appUUID, fmt.Sprintf(
		`curl -sS -X PUT -d '{"radioSilence":%t}' `+lpsManageRadioConfigURL, silence))
}

// putLPSAppCommand submits a single-element AppCommand list via
// PUT /manage/v1/app-command (the endpoint always takes a JSON array).
// command must be one of the org.lfedge.eve.profile.AppCommand_Command
// symbolic names (e.g. "COMMAND_PURGE", "COMMAND_RESTART").
func putLPSAppCommand(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	appDisplayName string, timestamp uint64, command string) {
	body := fmt.Sprintf(`[{"displayname":"%s","timestamp":%d,"command":"%s"}]`,
		appDisplayName, timestamp, command)
	runInLPSApp(t, device, appUUID, fmt.Sprintf(
		`curl -sS -X PUT -H 'Content-Type: application/json' -d '%s' `+lpsManageAppCommandURL,
		body))
}

// putLPSDevCommand submits a device command via PUT /manage/v1/dev-command.
// command must be one of the org.lfedge.eve.profile.LocalDevCmd_Command
// symbolic names (e.g. "COMMAND_SHUTDOWN", "COMMAND_GRACEFUL_POWEROFF").
func putLPSDevCommand(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	timestamp uint64, command string) {
	body := fmt.Sprintf(`{"timestamp":%d,"command":"%s"}`, timestamp, command)
	runInLPSApp(t, device, appUUID, fmt.Sprintf(
		`curl -sS -X PUT -d '%s' `+lpsManageDevCommandURL, body))
}

// putLPSNetworkConfig sets the local network config the LPS reports back to
// EVE (PUT /manage/v1/network-config). portsJSON is the raw JSON array for
// the "ports" field (e.g. "[]" to revert to the controller-supplied config).
func putLPSNetworkConfig(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, portsJSON string) {
	body := fmt.Sprintf(`{"ports":%s}`, portsJSON)
	runInLPSApp(t, device, appUUID, fmt.Sprintf(
		`curl -sS -X PUT -H 'Content-Type: application/json' -d '%s' `+lpsManageNetConfigURL,
		body))
}

// appInfoByName returns the LocalAppInfo entry matching the given
// displayname, or nil if the LPS has no entry for it yet.
func appInfoByName(list *profile.LocalAppInfoList, name string) *profile.LocalAppInfo {
	for _, info := range list.GetAppsInfo() {
		if info.GetName() == name {
			return info
		}
	}
	return nil
}

// portStatusByLabel returns the NetworkPortStatus entry matching the given
// logical label. Fails the assertion if no such entry is present in the
// NetworkInfo published by EVE.
func portStatusByLabel(t Gomega, netInfo *profile.NetworkInfo,
	label string) *profile.NetworkPortStatus {
	for _, ps := range netInfo.PortStatus {
		if ps.LogicalLabel == label {
			return ps
		}
	}
	t.Expect(netInfo.PortStatus).To(ContainElement(
		HaveField("LogicalLabel", label)),
		"NetworkInfo.PortStatus should include "+label)
	return nil
}
