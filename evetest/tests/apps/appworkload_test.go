// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Where and whether the app is actually running, as the hypervisor itself sees
// it: VMIRS objects on eve-k, qemu domain state directories on kvm/xen.
//
// Rule for this file: readers that enumerate the app's WORKLOAD instances. This
// is the one place a stale generation is observable, because pillar's own
// DomainStatus is keyed by app UUID and so can only ever describe one
// (appstate_test.go). Kube readers first, local-hypervisor readers second; the
// access mechanism itself lives in deviceaccess_test.go.
//
// Split trigger: if a xen-specific reader is ever needed, break this into
// kubeworkload_test.go and localdomain_test.go. Two backends sharing one file is
// deliberate while callers choose between them purely by hypervisor and a
// reviewer needs both in view at once.

package apps_test

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/evetest"
	uuid "github.com/satori/go.uuid"
)

const (
	// appDomainNameLabel is the selector label every VMIRS carries with the
	// owning app's DomainName ("<uuid>.<version>.<appnum>"). See the eveLabelKey
	// constant in hypervisor/kubevirt.go.
	appDomainNameLabel = "App-Domain-Name"

	// kvmDomainStateDir mirrors hypervisor/kvm.go's kvmStateDir: qemu gets one
	// directory per domain, holding that domain's pidfile. EVE bind-mounts /run
	// into the pillar container, so this path is readable from dom0 - the same
	// assumption evetest.ReadAllPublications already makes for /run/<agent>.
	kvmDomainStateDir = "/run/hypervisor/kvm"
)

// listAppVMIRS returns the names of every VMIRS (any generation) belonging to
// appUUID, filtered on the App-Domain-Name label prefix "<uuid>." - the label
// value is "<uuid>.<version>.<appnum>" and the version/appnum suffix does not
// matter here. Names are sorted, so a caller can compare the whole set.
func listAppVMIRS(dev *evetest.EdgeDevice, appUUID uuid.UUID) []string {
	list, ok := kubectlListItems(dev, "vmirs")
	if !ok {
		return nil
	}
	prefix := appUUID.String() + "."
	var names []string
	for _, item := range list.Items {
		if strings.HasPrefix(item.Metadata.Labels[appDomainNameLabel], prefix) {
			names = append(names, item.Metadata.Name)
		}
	}
	sort.Strings(names)
	return names
}

// listKVMDomainDirs returns the qemu per-domain state directories belonging to
// appUUID, found by prefix on the domain name ("<uuid>.<version>.<appnum>", see
// types.DomainConfig.GetTaskName).
//
// Note the asymmetry with listAppVMIRS: a kvm domain name carries no purge
// counter, so two generations of the same app at the same version would share one
// directory name and be indistinguishable here. That is also why the
// duplicate-generation defect cannot take this shape on kvm at all. What this
// does catch is a directory left behind for a different version/appnum, and any
// directory for an app that should be gone entirely.
func listKVMDomainDirs(dev *evetest.EdgeDevice, appUUID uuid.UUID) []string {
	prefix := appUUID.String() + "."
	var names []string
	for _, name := range listDirEntries(dev, kvmDomainStateDir) {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// kvmDomainPid reads the pid qemu wrote for domainName. found is false if the
// pidfile is absent or unparseable.
func kvmDomainPid(
	dev *evetest.EdgeDevice, domainName string) (pid int, found bool) {
	contents, found := readDeviceFile(
		dev, path.Join(kvmDomainStateDir, domainName, "pid"))
	if !found {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(contents))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
