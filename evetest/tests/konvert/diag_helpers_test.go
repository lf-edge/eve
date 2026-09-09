// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"github.com/lf-edge/eve/evetest"
)

// Everything here is best-effort: it runs when an assertion is already about to
// fail, and must never turn a diagnosable failure into a second one. Each probe
// logs whatever it gets, including its error.

// probe is one diagnostic command and the label its output is filed under.
type probe struct {
	what   string
	script string
}

// runProbes logs each probe's output under label. Errors are logged, not
// raised.
func runProbes(device *evetest.EdgeDevice, label string, probes []probe) {
	log := evetest.Logger()
	log.Errorf("=== %s ===", label)
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, eveShellTimeout, 0)
		log.Errorf("[%s] %s:\n%s%s(err=%v)", label, p.what, out, errOut, err)
	}
}

// dumpConversionFailure captures why EVE marked the conversion failed. By the
// time this runs the device is back online on the unconverted partition, so it
// can still be asked directly -- which is the only window in which the resizer's
// own verdict is readable.
func dumpConversionFailure(device *evetest.EdgeDevice) {
	runProbes(device, "conversion FAILED", []probe{
		{"resize-failed.json", "cat /config/resize-failed.json 2>/dev/null || echo NONE"},
		{"resize flags", "echo repartition-inprogress=$(cat /config/repartition-inprogress 2>/dev/null); " +
			"echo resize-reboots=$(cat /config/resize-reboots 2>/dev/null)"},
		{"zboot status", "zboot status 2>&1 || true"},
		{"BaseOsStatus", "eve exec pillar sh -c 'cat /run/baseosmgr/BaseOsStatus/*.json 2>/dev/null' || echo NONE"},
		{"partitions", partsLsblk},
	})
}

// dumpAppNetwork snapshots what stands between the controller and the app: the
// port-forward rules, the app's own network status, and the node's addresses.
// Taken on both flavors so a working baseline can be diffed against a failure.
func dumpAppNetwork(device *evetest.EdgeDevice, label string) {
	runProbes(device, "app network: "+label, []probe{
		{"NAT port map", "eve exec pillar iptables -t nat -S 2>/dev/null | grep -aiE '2222|DNAT|to-destination' || echo none"},
		{"AppNetworkStatus", "eve exec pillar sh -c 'cat /run/zedrouter/AppNetworkStatus/*.json 2>/dev/null' || echo none"},
		{"addresses", "eve exec pillar ip -br addr 2>/dev/null || echo none"},
	})
}

// dumpClusterStorage captures the EVE-K storage stack when an app is stuck
// waiting for a volume: which stage is not ready, and what Longhorn and CDI
// think of the PVC.
func dumpClusterStorage(device *evetest.EdgeDevice) {
	runProbes(device, "EVE-K cluster storage", []probe{
		{"volumemgr", "eve exec pillar cat /run/volumemgr/VolumeMgrStatus/volumemgr.json 2>/dev/null || echo NONE"},
		{"storage classes", "eve exec kube kubectl get sc 2>&1 || true"},
		{"PVCs", "eve exec kube kubectl get pvc -A 2>&1 || true"},
		{"pods", "eve exec kube kubectl get pods -A 2>&1 || true"},
		{"longhorn volumes", "eve exec kube kubectl get volumes.longhorn.io -A 2>&1 || true"},
		{"persist usage", "df -h /persist 2>&1 || true"},
	})
}

// dumpRestoreState captures what early boot made of a damaged /persist: whether
// the backup was there to restore from, and what came back.
func dumpRestoreState(device *evetest.EdgeDevice) {
	runProbes(device, "identity restore", []probe{
		{"config backup", "ls -lR /config/backup-persist 2>&1 || echo NONE"},
		{"restore flag", "ls -l /config/repartition-inprogress 2>&1 || echo NONE"},
		{"uuid", "cat /persist/status/uuid 2>/dev/null || echo NONE"},
		{"certs", "ls -l /persist/certs 2>&1 || echo NONE"},
		{"checkpoint", "ls -l /persist/checkpoint 2>&1 || echo NONE"},
		{"onboarding", "eve exec pillar sh -c 'cat /persist/status/zedclient/OnboardingStatus/global.json 2>/dev/null' || echo NONE"},
		{"cipher status", "eve exec pillar sh -c 'cat /run/nim/CipherBlockStatus/*.json 2>/dev/null' || echo NONE"},
	})
}
