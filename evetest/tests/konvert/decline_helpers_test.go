// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/json"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// assertConversionDeclined asserts EVE refused the conversion and is no worse
// off for it.
//
// Three things have to hold together, and each rules out a different way of
// "refusing" that would not be acceptable: an error must be reported, so the
// refusal is a decision and not a silent stall; the device must still be running
// the image it was, so nothing was installed; and it must still answer its
// controller, so a refused conversion has not cost remote management -- which is
// the whole reason to refuse rather than attempt.
func assertConversionDeclined(t Gomega, device *evetest.EdgeDevice, kvmVersion string) {
	log := evetest.Logger()

	// While waiting for the error, a device that leaves the kvm image has
	// already failed: it accepted the update. Watching for that during the wait
	// turns an eight-minute timeout into an immediate, accurate failure.
	var reported string
	t.Eventually(func(g Gomega) {
		running, err := runEVE(device, "cat /run/eve-release")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(running)).To(Equal(kvmVersion),
			"the device left the kvm image, so the conversion was not declined")
		reported = baseOSError(device)
		g.Expect(reported).NotTo(BeEmpty(),
			"no error reported yet; a decline must be reported, not a silent stall")
	}, 8*time.Minute, 10*time.Second).Should(Succeed())
	log.Infof("EVE declined the conversion: %s", reported)

	running, err := runEVE(device, "cat /run/eve-release")
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(strings.TrimSpace(running)).To(Equal(kvmVersion),
		"the device is not on the kvm image after declining")

	log.Infof("the device must still reach its controller")
	assertControllerReachable(t, device)
}

// baseOSError returns the errors baseosmgr is reporting for the base-OS
// updates it knows about, joined, or "" while it reports none.
func baseOSError(device *evetest.EdgeDevice) string {
	out, err := runEVE(device,
		`eve exec pillar sh -c "cat /run/baseosmgr/BaseOsStatus/*.json 2>/dev/null"`)
	if err != nil {
		return ""
	}
	var errors []string
	for _, status := range decodeJSONStream(out) {
		if msg, _ := status["Error"].(string); msg != "" {
			errors = append(errors, msg)
		}
	}
	return strings.Join(errors, " | ")
}

// decodeJSONStream decodes back-to-back JSON objects, which is what
// concatenating a directory of pubsub files produces.
func decodeJSONStream(raw string) []map[string]any {
	var out []map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	for {
		var obj map[string]any
		if err := decoder.Decode(&obj); err != nil {
			return out
		}
		out = append(out, obj)
	}
}

// assertControllerReachable asserts EVE can still reach its controller, which is
// what "still manageable" means in practice: a device that declined a conversion
// but lost its way back would need a truck roll all the same.
func assertControllerReachable(t Gomega, device *evetest.EdgeDevice) {
	const pingController = `eve exec pillar curl -sk --max-time 5 ` +
		`https://$(tr -d "\r\n" < /config/server)/api/v2/edgedevice/ping ` +
		`-o /dev/null -w "%{http_code}"`
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, pingController)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(HaveSuffix("200"),
			"the device cannot reach its controller after declining the conversion")
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
}
