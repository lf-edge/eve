// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Raw access plumbing: the only place in this package that shells out to a
// device.
//
// Rule for this file: nothing here knows what an app, a volume or a purge is,
// and conversely no other file in the package may call RunShellScript directly -
// add a primitive here and call it instead. That keeps the count of ad-hoc SSH
// invocations bounded and gives one place to fix quoting, timeouts and
// error-vs-absent semantics.
//
// Every reader here is deliberately NON-FATAL: it warns and reports "not found"
// rather than failing the test, so callers can retry inside Eventually while a
// device is still converging. The framework's own readers now return errors
// too, so the two behave alike; these exist for paths the framework does not
// cover, such as kubectl and the hypervisor state directories.
//
// Promotion trigger: when a second suite needs kubectl access, move
// kubectlListItems to an EdgeDevice method in evetest/edgedevice.go. Do not copy
// it. It is kept local for now because tests/cluster has no kubectl calls at all,
// so the shape is unsettled after two consumers, and because the framework has no
// non-fatal read family to fit it into yet.

package apps_test

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

const (
	// sshCmdTimeout bounds a single kubectl/cat/ls invocation run over SSH.
	sshCmdTimeout = 20 * time.Second

	// eveKubeAppNamespace is the Kubernetes namespace EVE runs app workloads in;
	// both VMIRS objects and their PVCs live there. See
	// pkg/pillar/kubeapi.EVEKubeNameSpace.
	eveKubeAppNamespace = "eve-kube-app"
)

// kubeItemList is the minimal shape needed from any `kubectl get <resource>
// -o json`: a name per item, the item's own labels, the selector labels, and
// its status phase. A VMIRS is attributed by its selector, which is the only
// place EVE puts the App-Domain-Name label; a PVC has neither label field but
// does have Status.Phase.
type kubeItemList struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
		} `json:"spec"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

// kubectlListItems lists one Kubernetes resource type from the EVE app
// namespace. found is false, with a warning logged, if the device is
// unreachable, k3s is not up, or the output does not parse - all of which are
// transient states a caller inside Eventually should retry rather than fail on.
//
// Reaching into Kubernetes at all is a deliberate exception to the framework
// guideline "assert against the EVE API, not internal state" (README "Writing
// Tests -> Guidelines"): there is no EVE-API-exposed signal for "how many
// generations of this app's workload exist" - the cluster-status topic zedkube
// publishes carries only the single name of the desired generation. Until that
// gap is closed, this is the only vantage point from which a stale generation
// surviving a purge is observable at all.
func kubectlListItems(
	dev *evetest.EdgeDevice, resource string) (list kubeItemList, found bool) {
	stdout, stderr, err := dev.RunShellScript(
		"eve exec kube kubectl -n "+eveKubeAppNamespace+" get "+resource+" -o json",
		sshCmdTimeout, 0)
	if err != nil {
		evetest.Logger().Warnf(
			"kubectlListItems: kubectl get %s failed: %v (stderr: %s)",
			resource, err, stderr)
		return list, false
	}
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		evetest.Logger().Warnf(
			"kubectlListItems: failed to parse kubectl %s output: %v", resource, err)
		return list, false
	}
	return list, true
}

// kubeEventList is the minimal shape needed from `kubectl get events -o json`:
// the reason, the human-readable message, and the name of the object the
// event is about.
type kubeEventList struct {
	Items []struct {
		Reason         string `json:"reason"`
		Message        string `json:"message"`
		InvolvedObject struct {
			Name string `json:"name"`
		} `json:"involvedObject"`
	} `json:"items"`
}

// kubectlEvents lists every event in the EVE app namespace. found is false on
// the same conditions as kubectlListItems.
func kubectlEvents(dev *evetest.EdgeDevice) (list kubeEventList, found bool) {
	stdout, stderr, err := dev.RunShellScript(
		"eve exec kube kubectl -n "+eveKubeAppNamespace+" get events -o json",
		sshCmdTimeout, 0)
	if err != nil {
		evetest.Logger().Warnf(
			"kubectlEvents: kubectl get events failed: %v (stderr: %s)", err, stderr)
		return list, false
	}
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		evetest.Logger().Warnf(
			"kubectlEvents: failed to parse kubectl events output: %v", err)
		return list, false
	}
	return list, true
}

// restartCSIProvisioner deletes Longhorn's csi-provisioner pod(s), forcing a
// fresh leader election and cache. See the REMOVE ME note atop
// longhorn_provisioner_workaround_test.go for why this exists.
func restartCSIProvisioner(dev *evetest.EdgeDevice) {
	if _, stderr, err := dev.RunShellScript(
		"eve exec kube kubectl -n longhorn-system delete pod -l app=csi-provisioner",
		sshCmdTimeout, 0); err != nil {
		evetest.Logger().Warnf("restartCSIProvisioner: delete failed: %v (stderr: %s)", err, stderr)
	}
}

// listDirEntries returns the sorted names of the entries in a directory on the
// device. A missing directory yields an empty list, not an error: several of the
// directories inspected by this suite only exist once a particular hypervisor or
// storage backend has created them.
func listDirEntries(dev *evetest.EdgeDevice, dir string) []string {
	stdout, _, err := dev.RunShellScript(
		"ls -1 "+dir+" 2>/dev/null || true", sshCmdTimeout, 0)
	if err != nil {
		evetest.Logger().Warnf("listDirEntries: ls %s failed: %v", dir, err)
		return nil
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// readDeviceFile reads a file off the device. found is false if the file does not
// exist or is empty, which callers use to express "not published yet" without
// failing the test.
func readDeviceFile(
	dev *evetest.EdgeDevice, path string) (contents string, found bool) {
	stdout, _, err := dev.RunShellScript(
		"cat "+path+" 2>/dev/null || true", sshCmdTimeout, 0)
	if err != nil || strings.TrimSpace(stdout) == "" {
		return "", false
	}
	return stdout, true
}

// syncDisks flushes the device's filesystem caches.
//
// Needed before a hard power-off. EVE unpacks an app's container image layers
// without fsyncing them and containerd marks the snapshots Committed regardless,
// so pulling power inside the writeback window leaves the extracted layers as a
// complete directory tree of zero-length files - measured at ~150MB before a
// power-off and ~3MB after. Nothing ever re-extracts them, every later volume
// built from that image is hollow, and the app boot-loops while EVE reports it
// RUNNING. That is an EVE durability bug in its own right; syncing here keeps it
// out of tests whose subject is something else.
func syncDisks(dev *evetest.EdgeDevice) {
	if _, _, err := dev.RunShellScript("sync", sshCmdTimeout, 0); err != nil {
		evetest.Logger().Warnf("syncDisks: sync failed: %v", err)
	}
}

// pathExists reports whether a path exists on the device. ok is false if the
// check itself could not be run, so a caller can tell "the file is gone" apart
// from "the device did not answer".
func pathExists(dev *evetest.EdgeDevice, target string) (exists, ok bool) {
	stdout, _, err := dev.RunShellScript(
		"test -e "+target+" && echo present || echo gone", sshCmdTimeout, 0)
	if err != nil {
		return false, false
	}
	switch strings.TrimSpace(stdout) {
	case "present":
		return true, true
	case "gone":
		return false, true
	}
	return false, false
}
