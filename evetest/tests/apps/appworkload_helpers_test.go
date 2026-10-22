// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Where and whether the app is actually running, as the hypervisor itself sees
// it: qemu domain state directories on kvm/xen.
//
// Rule for this file: readers that enumerate the app's WORKLOAD instances. This
// is the one place a stale generation is observable, because pillar's own
// DomainStatus is keyed by app UUID and so can only ever describe one
// (appstate_helpers_test.go).
//
// Everything generic - reading a file, listing a directory, testing for a path,
// flushing caches - is an EdgeDevice method in the framework
// (evetest/edgedevice.go); this file only adds what is specific to EVE's
// workload objects. Helpers backed by a framework method surface its error to
// Gomega, because an error there is a transport failure.

package apps_test

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	uuid "github.com/satori/go.uuid"
)

const (
	// kvmDomainStateDir mirrors hypervisor/kvm.go's kvmStateDir: qemu gets one
	// directory per domain, holding that domain's pidfile. EVE bind-mounts /run
	// into the pillar container, so this path is readable from dom0 - the same
	// assumption evetest.ReadAllPublications already makes for /run/<agent>.
	kvmDomainStateDir = "/run/hypervisor/kvm"
)

// listKVMDomainDirs returns the qemu per-domain state directories belonging to
// appUUID, found by prefix on the domain name ("<uuid>.<version>.<appnum>", see
// types.DomainConfig.GetTaskName).
//
// A kvm domain name carries no purge counter, so two generations of the same
// app at the same version would share one directory name and be
// indistinguishable here. What this does catch is a
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
