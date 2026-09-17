// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Where and whether the app is actually running, as the hypervisor itself sees
// it: VMIRS objects on eve-k, qemu domain state directories on kvm/xen.
//
// Rule for this file: readers that enumerate the app's WORKLOAD instances. This
// is the one place a stale generation is observable, because pillar's own
// DomainStatus is keyed by app UUID and so can only ever describe one
// (appstate_helpers_test.go).
//
// Everything generic - reading a file, listing a directory, testing for a path,
// flushing caches, reaching the cluster's kubectl - is an EdgeDevice method in
// the framework (evetest/edgedevice.go); this file only adds what is specific
// to EVE's workload objects. Note the two error conventions that follow from
// that: helpers backed by a framework method surface its error to Gomega,
// because an error there is a transport failure, while a failed kubectl call is
// reported as found=false, because "k3s is not up yet" is an expected transient
// state a caller inside Eventually should retry on rather than fail.
//
// Split trigger: if a xen-specific reader is ever needed, break this into
// kube- and local-domain helper files. Two backends sharing one file is
// deliberate while callers choose between them purely by hypervisor and a
// reviewer needs both in view at once.

package apps_test

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	uuid "github.com/satori/go.uuid"
)

const (
	// sshCmdTimeout bounds a single kubectl invocation run over SSH.
	sshCmdTimeout = 20 * time.Second

	// kvmDomainStateDir mirrors hypervisor/kvm.go's kvmStateDir: qemu gets one
	// directory per domain, holding that domain's pidfile. EVE bind-mounts /run
	// into the pillar container, so this path is readable from dom0 - the same
	// assumption evetest.ReadAllPublications already makes for /run/<agent>.
	kvmDomainStateDir = "/run/hypervisor/kvm"
)

// kubeItemList is the minimal shape needed from `kubectl get <resource> -o
// json`: a name per item.
type kubeItemList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
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
	stdout, err := dev.RunKubectl(
		"-n "+evetest.EVEKubeAppNamespace+" get "+resource+" -o json", sshCmdTimeout)
	if err != nil {
		evetest.Logger().Warnf("kubectlListItems: %v", err)
		return list, false
	}
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		evetest.Logger().Warnf(
			"kubectlListItems: failed to parse kubectl %s output: %v", resource, err)
		return list, false
	}
	return list, true
}

// listKVMDomainDirs returns the qemu per-domain state directories belonging to
// appUUID, found by prefix on the domain name ("<uuid>.<version>.<appnum>", see
// types.DomainConfig.GetTaskName).
//
// Note the asymmetry with EdgeDevice.ListAppVMIRS: a kvm domain name carries no purge
// counter, so two generations of the same app at the same version would share one
// directory name and be indistinguishable here. That is also why a surviving
// generation cannot take this shape on kvm at all. What this does catch is a
// directory left behind for a different version/appnum, and any directory for an
// app that should be gone entirely.
func listKVMDomainDirs(
	g Gomega, dev *evetest.EdgeDevice, appUUID uuid.UUID) []string {
	entries, err := dev.ListDirEntries(kvmDomainStateDir)
	g.Expect(err).ToNot(HaveOccurred(), "listing %s", kvmDomainStateDir)
	prefix := appUUID.String() + "."
	var names []string
	for _, name := range entries {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// kvmDomainPid reads the pid qemu wrote for domainName. An error means the
// pidfile is absent or unparsable, which a caller inside Eventually can retry
// while the domain is still being created.
func kvmDomainPid(dev *evetest.EdgeDevice, domainName string) (int, error) {
	pidFile := path.Join(kvmDomainStateDir, domainName, "pid")
	contents, err := dev.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil {
		return 0, err
	}
	if pid <= 0 {
		return 0, fmt.Errorf("%s holds a non-positive pid %d", pidFile, pid)
	}
	return pid, nil
}
