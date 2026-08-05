// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package prereqs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// EVE confines itself to a cpuset derived from eve_max_vcpus, which is 1
// by default (pkg/grub/rootfs.cfg). That puts kube-init and the whole k3s
// control plane — API server, etcd, scheduler, kubelet — on a single core
// while the rest of the machine sits idle. Pods are unaffected: kubelet
// places them under /sys/fs/cgroup/cpuset/kubepods, which keeps the full
// host mask.
//
// A first boot is the one time that hurts and the one time nothing is
// competing: no app workloads exist yet, and the deploy drives hundreds of
// API writes, CRD establishments and pod admissions through that single
// core. So the confinement is lifted for the deploy and restored on
// reaching RUNNING.
var cpusetRoot = "/sys/fs/cgroup/cpuset"

// cpusetAncestors is ordered parent-first. cgroup v1 requires a child's
// cpus to be a subset of its parent's, so widening walks it forwards and
// restoring walks it backwards.
var cpusetAncestors = []string{"eve", "eve/services"}

// cpusetServices are the per-service leaves under eve/services.
//
// Widening an ancestor only raises its ceiling — each leaf keeps its own
// cpuset.cpus, which 010-eve-cgroup writes from eve_max_vcpus (1 by
// default). So freeing the ancestors alone frees nothing, and freeing
// only "kube" leaves every sibling pinned to CPU 0.
//
// pillar matters as much as kube here: it downloads and hash-verifies
// the images a first boot needs. Empty means "every leaf present",
// mirroring what eve_max_vcpus does, rather than hard-coding a service
// list that would drift from EVESERVICES.
var cpusetServices []string

// CPUSetLoan is the widened cpuset, held so it can be given back.
type CPUSetLoan struct {
	saved map[string]string
}

// WidenEVECPUs gives the EVE base services the host's full CPU mask —
// kube-init and k3s, and equally pillar, which downloads and verifies the
// images a first boot needs. Returns nil (not an error) when there is
// nothing to widen: a cgroup v2 host, or an already-unconfined cpuset.
//
// A crash before Restore leaves the mask wide until the next reboot, when
// dom0-ztools' 010-eve-cgroup rewrites it from the kernel cmdline.
func WidenEVECPUs() *CPUSetLoan {
	all, err := readCPUSet("")
	if err != nil {
		log.Printf("cpuset: cannot read host mask, leaving CPU limits alone: %v", err)
		return nil
	}

	loan := &CPUSetLoan{saved: make(map[string]string)}
	// Ancestors first, and a failure there aborts: cgroup v1 will not let a
	// leaf exceed its parent, so widening leaves under an un-widened parent
	// cannot work.
	for _, cg := range cpusetAncestors {
		if !loan.widen(cg, all) {
			log.Printf("cpuset: cannot widen ancestor %s; leaving CPU limits alone", cg)
			loan.Restore()
			return nil
		}
	}
	// Then every leaf. One unreadable leaf must not abandon its siblings —
	// each is independent once the ancestors are open.
	for _, cg := range cpusetLeavesNow() {
		if !loan.widen(cg, all) {
			log.Printf("cpuset: skipping leaf %s", cg)
		}
	}

	if len(loan.saved) == 0 {
		log.Printf("cpuset: nothing to widen (already %q)", all)
		return nil
	}
	// Name a representative before-mask and both CPU counts so a log
	// reader can confirm the widening actually took effect, and compare
	// one boot against another.
	was := loan.saved[cpusetAncestors[0]]
	if was == "" {
		for _, v := range loan.saved {
			was = v
			break
		}
	}
	names := make([]string, 0, len(loan.saved))
	for cg := range loan.saved {
		names = append(names, cg)
	}
	sort.Strings(names)
	log.Printf("cpuset: widened %d cgroup(s) %q -> %q (%d -> %d cpus) for first boot: %s",
		len(loan.saved), was, all, countCPUList(was), countCPUList(all),
		strings.Join(names, " "))
	return loan
}

// widen records the current mask and replaces it with all. Reports false
// when the group could not be read or written; a group already at all is
// a no-op success with nothing to give back.
func (l *CPUSetLoan) widen(cgroup, all string) bool {
	cur, err := readCPUSet(cgroup)
	if err != nil {
		log.Printf("cpuset: read %s: %v", cgroup, err)
		return false
	}
	if cur == all {
		return true
	}
	if err := writeCPUSet(cgroup, all); err != nil {
		log.Printf("cpuset: write %s: %v", cgroup, err)
		return false
	}
	l.saved[cgroup] = cur
	return true
}

// Restore puts back the masks WidenKubeCPUs replaced. Safe on a nil loan
// and safe to call twice.
func (l *CPUSetLoan) Restore() {
	if l == nil || len(l.saved) == 0 {
		return
	}
	restored := 0
	// Child-first: a parent cannot narrow below what a child still holds.
	chain := append(append([]string(nil), cpusetAncestors...), cpusetLeavesNow()...)
	for i := len(chain) - 1; i >= 0; i-- {
		cg := chain[i]
		was, ok := l.saved[cg]
		if !ok {
			continue
		}
		if err := writeCPUSet(cg, was); err != nil {
			log.Printf("cpuset: cannot restore %s to %q: %v", cg, was, err)
			continue
		}
		delete(l.saved, cg)
		restored++
	}
	log.Printf("cpuset: restored first-boot CPU limits on %d cgroup(s)", restored)
}

// KubeCPUCount reports how many CPUs the kube cgroup may currently use.
// Read live rather than via runtime.NumCPU, which caches the mask at
// process start and so cannot see a widening.
func KubeCPUCount() int {
	s, err := readCPUSet("eve/services/kube")
	if err != nil {
		return 0
	}
	return countCPUList(s)
}

// cpusetLeavesNow returns every per-service leaf under eve/services, read
// from the filesystem rather than a hard-coded list so it cannot drift
// from EVESERVICES in 010-eve-cgroup.
func cpusetLeavesNow() []string {
	if len(cpusetServices) > 0 {
		out := make([]string, 0, len(cpusetServices))
		for _, l := range cpusetServices {
			out = append(out, filepath.Join("eve", "services", l))
		}
		return out
	}
	entries, err := os.ReadDir(filepath.Join(cpusetRoot, "eve", "services"))
	if err != nil {
		return nil
	}
	var leaves []string
	for _, e := range entries {
		if e.IsDir() {
			leaves = append(leaves, filepath.Join("eve", "services", e.Name()))
		}
	}
	sort.Strings(leaves)
	return leaves
}

func cpusetPath(cgroup string) string {
	return filepath.Join(cpusetRoot, cgroup, "cpuset.cpus")
}

func readCPUSet(cgroup string) (string, error) {
	b, err := os.ReadFile(cpusetPath(cgroup))
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", cpusetPath(cgroup))
	}
	return s, nil
}

func writeCPUSet(cgroup, mask string) error {
	return os.WriteFile(cpusetPath(cgroup), []byte(mask), 0644)
}

// countCPUList counts the CPUs in a cpuset list such as "0", "0-7" or
// "0,2-4". Malformed segments are skipped rather than failing the caller,
// which only wants a concurrency hint.
func countCPUList(s string) int {
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		start, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		if !isRange {
			n++
			continue
		}
		end, err := strconv.Atoi(hi)
		if err != nil || end < start {
			continue
		}
		n += end - start + 1
	}
	return n
}
