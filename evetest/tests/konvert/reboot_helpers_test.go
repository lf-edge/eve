// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
)

// rebootEVEKTimeout bounds a controller-requested reboot of the converted device
// until EVE answers SSH on the new boot. The framework's own reboot wait is five
// minutes; this leaves room for an EVE-K boot on a slower runner.
const rebootEVEKTimeout = 20 * time.Minute

// rebootAfterConversionParameter declares whether a test reboots the converted
// device and re-runs its gates. The conversion boot is EVE-K's first; only a
// second one shows the cluster and Longhorn coming back on an existing node and
// re-attaching the app's volume.
func rebootAfterConversionParameter() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          rebootAfterConversionParamKey,
		DefaultValue: true,
		Description: evetest.TestParameterDescription{
			Summary: "After the conversion, reboot EVE-K and re-run the storage and app gates",
			Default: "true",
		},
	}
}

// rebootAfterConversionRequested reports the rebootAfterConversionParameter value.
func rebootAfterConversionRequested() bool {
	return evetest.GetTestParameter[bool](rebootAfterConversionParamKey)
}

// readAppBootID returns the app guest's kernel boot ID.
func readAppBootID(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) string {
	var id string
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"cat /proc/sys/kernel/random/boot_id", sshTimeout, 0)
		g.Expect(err).NotTo(HaveOccurred())
		id = strings.TrimSpace(out)
		g.Expect(id).NotTo(BeEmpty())
	}, appSSHTimeout, 10*time.Second).Should(Succeed())
	return id
}

// rebootEVEK reboots the device through the controller and returns once EVE
// answers SSH with an uptime shorter than the time since the request, which no
// session left over from the previous boot can report. It returns the app's
// guest boot ID from before the reboot, for assertAppFreshBoot.
func rebootEVEK(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) string {
	bootID := readAppBootID(t, device, appUUID)
	evetest.Logger().Infof("rebooting EVE-K after the conversion")
	issued := time.Now()
	device.RequestReboot(false)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript("cut -d. -f1 /proc/uptime", eveShellTimeout, 0)
		g.Expect(err).NotTo(HaveOccurred())
		up, err := strconv.Atoi(strings.TrimSpace(out))
		g.Expect(err).NotTo(HaveOccurred(), "uptime %q", out)
		g.Expect(time.Duration(up)*time.Second).To(BeNumerically("<", time.Since(issued)),
			"EVE has not rebooted yet")
	}, rebootEVEKTimeout, 15*time.Second).Should(Succeed())
	evetest.Checkpoint("evek-rebooted")
	return bootID
}

// assertAppFreshBoot asserts the app runs on a guest boot newer than the one
// before rebootEVEK, so the gates that passed were answered by the restarted app.
func assertAppFreshBoot(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	before string) {
	t.Expect(readAppBootID(t, device, appUUID)).NotTo(Equal(before),
		"the app answered with its pre-reboot guest boot ID")
}

// rebootAndReassertEVEK reboots the converted device, then re-runs the storage
// and app gates and requires the app to be on a fresh guest boot.
func rebootAndReassertEVEK(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) {
	bootID := rebootEVEK(t, device, appUUID)
	waitClusterStorageReady(t, device)
	assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
	assertAppFreshBoot(t, device, appUUID, bootID)
	evetest.Checkpoint("evek-reboot-reasserted")
}
