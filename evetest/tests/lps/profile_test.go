// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestProfile verifies that EVE filters which applications run based on the
// currently active profile -- both a device-config-only GlobalProfile
// override and a Local Profile Server (LPS)-reported local profile -- by
// matching it against each app's ProfileList (an app with an empty
// ProfileList always runs, regardless of the active profile).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, used only for
//     controller reachability and the LPS app's Local NI. The three
//     ProfileList apps under test have no network adapter of their own
//     (only their RUNNING/HALTED state matters here).
//
// Phases
// ------
//  1. Deploy four apps on Local NI "local-ni": "lps-app" (the evetest-lps
//     app, ProfileList empty --> always runs), "app-profile-1"
//     (ProfileList=[profile-1]), "app-profile-2" (ProfileList=[profile-2]),
//     "app-profile-1-2" (ProfileList=[profile-1, profile-2]).
//     WaitUntilAppIsRunning for all four -- with no profile active yet
//     (GlobalProfile and LocalProfileServer both empty), every app runs.
//  2. GlobalProfile-only phase (no LPS involved yet): SetLPS with only
//     GlobalProfile set, re-applying for "profile-1", "profile-2" and
//     "profile-3" in turn. After each apply, assert exactly the apps whose
//     ProfileList does not contain the active profile are HALTED and the
//     rest (including lps-app, always) are RUNNING.
//  3. Manual activate/deactivate sanity check: with GlobalProfile still
//     "profile-3" (so app-profile-* are all HALTED), DeactivateApplication
//     then ActivateApplication lps-app (whose empty ProfileList makes it
//     immune to profile filtering) to confirm ordinary controller-driven
//     activation still works independently of the profile mechanism.
//  4. LPS-driven phase: configure the LPS address/token via SetLPS
//     (GlobalProfile is deliberately left at "profile-3" -- this also
//     proves that once a LocalProfileServer is configured, EVE is driven
//     entirely by whatever profile the LPS reports, not by GlobalProfile).
//     Submit "profile-1", "profile-2", "profile-3" via PUT /manage/v1/profile in
//     turn, asserting the same HALTED/RUNNING pattern as phase 2 -- but
//     this time driven by the LPS instead of the static device config.
//  5. Revert: SetLPS with all fields empty (clears GlobalProfile,
//     LocalProfileServer and ProfileServerToken). Assert all four apps
//     return to RUNNING.
//  6. Cleanup: delete all four apps and the NI, waiting for each to be gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestLPSSuite.
func TestProfile(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		Gateway:     evetest.IPAddress("10.11.12.1"),
		MTU:         1500,
	})

	// Step 1: deploy the LPS app plus three plain apps distinguished only
	// by their ProfileList.
	lpsAppUUID := devConfig.AddApplication(newLPSAppConfig("lps-app", niUUID, 2222))
	app1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "app-profile-1",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
		ProfileList:        []string{"profile-1"},
	})
	app2UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "app-profile-2",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
		ProfileList:        []string{"profile-2"},
	})
	app12UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "app-profile-1-2",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
		ProfileList:        []string{"profile-1", "profile-2"},
	})

	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(lpsAppUUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app2UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app12UUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-running-no-profile")

	log := evetest.Logger()
	timeout := 10 * time.Minute
	polling := 3 * time.Second

	// waitAppState polls EdgeDevice.GetAppInfo -- a synchronous snapshot of
	// the app's latest known state -- until it reports the expected SwState.
	// Used for HALTED/INVALID waits below (WaitUntilAppIsRunning only
	// targets RUNNING); a WatchAppInfo channel wouldn't work here either:
	// several apps have overlapping ProfileLists (e.g. app-profile-1-2
	// matches both "profile-1" and "profile-2"), so switching between two
	// profiles it both matches causes no state transition and thus no new
	// channel event at all.
	waitAppState := func(appUUID uuid.UUID, desc string, expected eveinfo.ZSwState) {
		log.Infof("Waiting for: %s...", desc)
		t.Eventually(func() eveinfo.ZSwState {
			if info := device.GetAppInfo(appUUID); info != nil {
				return info.GetState()
			}
			return eveinfo.ZSwState_INVALID
		}, timeout, polling).Should(Equal(expected), desc)
	}

	// Step 2: GlobalProfile-only phase (no LPS configured yet).
	log.Infof("Setting GlobalProfile=profile-1")
	devConfig.SetLPS(evetest.LPSConfig{GlobalProfile: "profile-1"})
	device.ApplyConfig(devConfig, false, false)
	waitAppState(app2UUID, "app-profile-2 is HALTED (profile-1 active)", eveinfo.ZSwState_HALTED)
	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(app12UUID, timeout)
	evetest.Checkpoint("global-profile-1")

	log.Infof("Setting GlobalProfile=profile-2")
	devConfig.SetLPS(evetest.LPSConfig{GlobalProfile: "profile-2"})
	device.ApplyConfig(devConfig, false, false)
	waitAppState(app1UUID, "app-profile-1 is HALTED (profile-2 active)", eveinfo.ZSwState_HALTED)
	device.WaitUntilAppIsRunning(app2UUID, timeout)
	device.WaitUntilAppIsRunning(app12UUID, timeout)
	evetest.Checkpoint("global-profile-2")

	log.Infof("Setting GlobalProfile=profile-3")
	devConfig.SetLPS(evetest.LPSConfig{GlobalProfile: "profile-3"})
	device.ApplyConfig(devConfig, false, false)
	waitAppState(app1UUID, "app-profile-1 is HALTED (profile-3 active)", eveinfo.ZSwState_HALTED)
	waitAppState(app2UUID, "app-profile-2 is HALTED (profile-3 active)", eveinfo.ZSwState_HALTED)
	waitAppState(app12UUID, "app-profile-1-2 is HALTED (profile-3 active)", eveinfo.ZSwState_HALTED)
	device.WaitUntilAppIsRunning(lpsAppUUID, timeout)
	evetest.Checkpoint("global-profile-3")

	// Step 3: manual activate/deactivate still works independently of the
	// profile mechanism (lps-app has an empty ProfileList, so it is immune
	// to the currently-active "profile-3").
	log.Infof("Manually deactivating and reactivating lps-app")
	device.DeactivateApplication(lpsAppUUID, true, timeout)
	device.ActivateApplication(lpsAppUUID, true, timeout)
	evetest.Checkpoint("lps-app-manually-cycled")

	// Step 4: LPS-driven phase. GlobalProfile is deliberately left at
	// "profile-3" -- configuring a LocalProfileServer must make EVE defer
	// entirely to whatever profile the LPS reports, ignoring GlobalProfile.
	lpsIP := waitLPSAppReady(t, device, lpsAppUUID, lpsServerToken)
	devConfig.SetLPS(evetest.LPSConfig{
		GlobalProfile: "profile-3",
		Address:       lpsIP + ":8888",
		AuthToken:     lpsServerToken,
	})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("lps-configured")

	log.Infof("Submitting local profile 'profile-1' via LPS")
	putLPSProfile(t, device, lpsAppUUID, "profile-1")
	waitAppState(app2UUID, "app-profile-2 is HALTED (LPS profile-1)", eveinfo.ZSwState_HALTED)
	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(app12UUID, timeout)
	evetest.Checkpoint("lps-profile-1")

	log.Infof("Submitting local profile 'profile-2' via LPS")
	putLPSProfile(t, device, lpsAppUUID, "profile-2")
	waitAppState(app1UUID, "app-profile-1 is HALTED (LPS profile-2)", eveinfo.ZSwState_HALTED)
	device.WaitUntilAppIsRunning(app2UUID, timeout)
	device.WaitUntilAppIsRunning(app12UUID, timeout)
	evetest.Checkpoint("lps-profile-2")

	log.Infof("Submitting local profile 'profile-3' via LPS")
	putLPSProfile(t, device, lpsAppUUID, "profile-3")
	waitAppState(app1UUID, "app-profile-1 is HALTED (LPS profile-3)", eveinfo.ZSwState_HALTED)
	waitAppState(app2UUID, "app-profile-2 is HALTED (LPS profile-3)", eveinfo.ZSwState_HALTED)
	waitAppState(app12UUID, "app-profile-1-2 is HALTED (LPS profile-3)", eveinfo.ZSwState_HALTED)
	device.WaitUntilAppIsRunning(lpsAppUUID, timeout)
	evetest.Checkpoint("lps-profile-3")

	// Step 5: revert to empty profiles -- all apps come back RUNNING.
	log.Infof("Reverting to empty GlobalProfile/LocalProfileServer")
	devConfig.SetLPS(evetest.LPSConfig{})
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(app2UUID, timeout)
	device.WaitUntilAppIsRunning(app12UUID, timeout)
	evetest.Checkpoint("profiles-cleared")

	// Cleanup.
	devConfig.DeleteApplication(lpsAppUUID)
	devConfig.DeleteApplication(app1UUID)
	devConfig.DeleteApplication(app2UUID)
	devConfig.DeleteApplication(app12UUID)
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	waitAppState(lpsAppUUID, "lps-app is gone", eveinfo.ZSwState_INVALID)
	waitAppState(app1UUID, "app-profile-1 is gone", eveinfo.ZSwState_INVALID)
	waitAppState(app2UUID, "app-profile-2 is gone", eveinfo.ZSwState_INVALID)
	waitAppState(app12UUID, "app-profile-1-2 is gone", eveinfo.ZSwState_INVALID)
}
