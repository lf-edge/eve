// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
)

const (
	// midUploadPodWait bounds the wait, from the end of the conversion, for the
	// CDI upload pod of the carried data volume to run. EVE-K brings up k3s
	// and Longhorn first, which takes minutes.
	midUploadPodWait = 30 * time.Minute
	// The cut lands this long after the upload pod is seen running. On kernel
	// 6.12 the pod finishes a 2 GiB upload within 20 s of that, so the range
	// keeps the cut mid-transfer.
	midUploadCutMin = 2 * time.Second
	midUploadCutMax = 8 * time.Second
)

// midUploadPowerCycleParameter declares whether TestKvmToKRepartitionTopology
// power-cycles EVE-K while the carried data volume is being uploaded into its
// PVC, so the next boot finds a partly uploaded claim.
func midUploadPowerCycleParameter() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          midUploadPowerCycleParamKey,
		DefaultValue: false,
		Description: evetest.TestParameterDescription{
			Summary: "Power-cycle EVE-K while the carried data volume is uploading into its PVC",
			Default: "false",
		},
	}
}

// midUploadPowerCycleRequested reports the midUploadPowerCycleParameter value.
func midUploadPowerCycleRequested() bool {
	return evetest.GetTestParameter[bool](midUploadPowerCycleParamKey)
}

// powerCycleMidUpload waits for the CDI upload into volUUID's claim to start,
// lets it run for a random 2-8 s and, if it is still running, power-cycles
// the device and waits for EVE to answer SSH on the new boot. It logs one
// [MID-UPLOAD] line and fails the test when the cut cannot land mid-upload,
// since such a run would not exercise the partly uploaded claim.
func powerCycleMidUpload(t Gomega, device *evetest.EdgeDevice, volUUID uuid.UUID) {
	log := evetest.Logger()
	podPrefix := "cdi-upload-" + volUUID.String() + "-pvc-"
	podScript := fmt.Sprintf(`eve exec kube kubectl -n eve-kube-app get pods --no-headers 2>/dev/null | awk '$1 ~ /^%s/ {print $1, $3; exit}'`, podPrefix)

	var pod string
	waitStart := time.Now()
	for time.Since(waitStart) < midUploadPodWait {
		out, err := runEVE(device, podScript)
		if f := strings.Fields(out); err == nil && len(f) == 2 && f[1] == "Running" {
			pod = f[0]
			break
		}
		time.Sleep(time.Second)
	}
	if pod == "" {
		log.Errorf("[MID-UPLOAD] cut=missed reason=no-running-upload-pod waited=%s",
			midUploadPodWait)
		t.Expect(pod).NotTo(BeEmpty(),
			"no CDI upload pod for volume %s ran within %s, so nothing could be cut mid-upload",
			volUUID, midUploadPodWait)
		return
	}
	pvc := strings.TrimPrefix(pod, "cdi-upload-")
	delay := midUploadCutMin + time.Duration(rand.Int63n(int64(midUploadCutMax-midUploadCutMin)))
	log.Infof("upload pod %s running after %s; cutting power in %s",
		pod, time.Since(waitStart).Round(time.Second), delay.Round(time.Second))
	time.Sleep(delay)

	out, _ := runEVE(device, podScript+fmt.Sprintf(
		`; eve exec kube kubectl -n eve-kube-app get pvc %s -o jsonpath='{.metadata.annotations.cdi\.kubevirt\.io/storage\.pod\.phase}' 2>/dev/null`, pvc))
	state := strings.TrimSpace(out)
	if !strings.Contains(state, "Running") || strings.Contains(state, "Succeeded") ||
		strings.Contains(state, "Upload Complete") {
		log.Errorf("[MID-UPLOAD] cut=missed reason=upload-finished pvc=%s state=%q", pvc, state)
		t.Expect(false).To(BeTrue(),
			"the upload into %s finished within %s, before the power cut", pvc, delay)
		return
	}

	log.Infof("[MID-UPLOAD] cut=yes pvc=%s after=%s state=%q",
		pvc, delay.Round(time.Second), strings.Join(strings.Fields(state), " "))
	issued := time.Now()
	device.PowerOff()
	device.PowerOn(false)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript("cut -d. -f1 /proc/uptime", eveShellTimeout, 0)
		g.Expect(err).NotTo(HaveOccurred())
		up, err := strconv.Atoi(strings.TrimSpace(out))
		g.Expect(err).NotTo(HaveOccurred(), "uptime %q", out)
		g.Expect(time.Duration(up)*time.Second).To(BeNumerically("<", time.Since(issued)),
			"EVE has not rebooted yet")
	}, rebootEVEKTimeout, 15*time.Second).Should(Succeed())
}
