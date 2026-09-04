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
// flushing caches, running kubectl - is an EdgeDevice method in the framework
// (evetest/edgedevice.go); this file only adds what is specific to EVE's
// workload objects. Note the two error conventions that follow from that: a
// transport failure surfaces to Gomega, while a failed kubectl call is reported
// as found=false, because "k3s is not up yet" is an expected transient state a
// caller inside Eventually should retry on rather than fail.
//
// Split trigger: if a xen-specific reader is ever needed, break this into
// kube- and local-domain helper files. Two backends sharing one file is
// deliberate while callers choose between them purely by hypervisor and a
// reviewer needs both in view at once.

package apps_test

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	uuid "github.com/satori/go.uuid"
)

const (
	// appDomainNameLabel holds the owning app's DomainName,
	// "<uuid>.<version>.<appnum>". See the eveLabelKey constant in
	// hypervisor/kubevirt.go.
	//
	// EVE puts this label in the VMIRS spec.selector.matchLabels and in the VMI
	// template, but not in the VMIRS metadata.labels. Read the selector. Pillar
	// attributes a VMIRS the same way, in sweepStaleGenerations.
	appDomainNameLabel = "App-Domain-Name"

	// kvmDomainStateDir mirrors hypervisor/kvm.go's kvmStateDir: qemu gets one
	// directory per domain, holding that domain's pidfile. EVE bind-mounts /run
	// into the pillar container, so this path is readable from dom0 - the same
	// assumption evetest.ReadAllPublications already makes for /run/<agent>.
	kvmDomainStateDir = "/run/hypervisor/kvm"
)

// listAppVMIRS returns the names of every VMIRS (any generation) that belongs to
// appUUID. It matches the prefix "<uuid>." on the App-Domain-Name selector
// label, because the label value also carries a version and an appnum that do
// not matter here. Names are sorted, so a caller can compare the whole set.
//
// found is false if the list could not be read. An empty list then means "no
// VMIRS", and not "the device did not answer".
func listAppVMIRS(
	dev *evetest.EdgeDevice, appUUID uuid.UUID) (names []string, found bool) {
	list, err := dev.KubectlListItems("vmirs")
	if err != nil {
		// k3s may still be starting; a caller inside Eventually retries.
		evetest.Logger().Warnf("listAppVMIRS: %v", err)
		return nil, false
	}
	prefix := appUUID.String() + "."
	for _, item := range list.Items {
		if strings.HasPrefix(
			item.Spec.Selector.MatchLabels[appDomainNameLabel], prefix) {
			names = append(names, item.Metadata.Name)
		}
	}
	sort.Strings(names)
	return names, true
}

// listKVMDomainDirs returns the qemu per-domain state directories belonging to
// appUUID, found by prefix on the domain name ("<uuid>.<version>.<appnum>", see
// types.DomainConfig.GetTaskName).
//
// Note the asymmetry with listAppVMIRS: a kvm domain name carries no purge
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
