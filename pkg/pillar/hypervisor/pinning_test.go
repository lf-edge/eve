// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
	"github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// fakeProc points procDir at a temp tree and adds threads to process pid.
type fakeProc struct {
	t   *testing.T
	dir string
}

func newFakeProc(t *testing.T) *fakeProc {
	old := procDir
	procDir = t.TempDir()
	t.Cleanup(func() { procDir = old })
	return &fakeProc{t: t, dir: procDir}
}

func (f *fakeProc) thread(pid, tid, comm string) {
	dir := filepath.Join(f.dir, pid, "task", tid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

type threadMove struct {
	group string
	tid   int
	// cpus is the group's cpuset.cpus when the thread joined it.
	cpus string
}

// recordMoves records the threads moved instead of moving them, failing the
// move of a tid in fail with its error.
func recordMoves(t *testing.T, fail map[int]error) *[]threadMove {
	var mu sync.Mutex
	moves := &[]threadMove{}
	old := addThread
	addThread = func(group string, tid int) error {
		mu.Lock()
		defer mu.Unlock()
		if err := fail[tid]; err != nil {
			return err
		}
		cpus, _ := os.ReadFile(cgroup.Path(group, "cpuset.cpus"))
		*moves = append(*moves, threadMove{group, tid, string(cpus)})
		return nil
	}
	t.Cleanup(func() { addThread = old })
	return moves
}

// fakeDomain stands in for QEMU 1318 of domain "dom" with vCPU threads vcpus
// and other threads others, and a cgroup tree with the files of its groups.
func fakeDomain(t *testing.T, vcpus, others []int) {
	p := newFakeProc(t)
	for _, tid := range others {
		p.thread("1318", strconv.Itoa(tid), "qemu-system-x86")
	}
	for i, tid := range vcpus {
		p.thread("1318", strconv.Itoa(tid), fmt.Sprintf("CPU %d/KVM", i))
	}
	oldIDs, oldPid := vcpuThreadIDs, domainPid
	vcpuThreadIDs = func(string) ([]int, error) { return vcpus, nil }
	domainPid = func(string) (int, error) { return 1318, nil }
	t.Cleanup(func() { vcpuThreadIDs, domainPid = oldIDs, oldPid })
	files := map[string]string{"eve-user-apps/dom/cpuset.cpus": "2"}
	for _, g := range []string{"emulator", "vcpu0", "vcpu1"} {
		files["eve-user-apps/dom/"+g+"/cpuset.cpus"] = ""
	}
	cgrouptest.FakeTree(t, files)
}

func readGroupFile(t *testing.T, group, file string) string {
	b, err := os.ReadFile(cgroup.Path(group, file))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// A pinned workload with io_placement=housekeeping: each vCPU thread alone on
// its CPU, every other thread on the IO CPUs, each group given its CPUs before
// a thread joins it, and the domain widened to all its CPUs last.
func TestArrangeDomainThreads_Pinned(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeDomain(t, []int{1320, 1321}, []int{1318, 1330})
	moves := recordMoves(t, nil)
	a := types.CPUAssignment{CPUs: []uint32{6, 7}, IOCPUs: []uint32{2}}

	g.Expect(arrangeDomainThreads("dom", "qmp", a)).To(gomega.Succeed())

	for _, grp := range []string{"emulator", "vcpu0", "vcpu1"} {
		g.Expect(readGroupFile(t, "eve-user-apps/dom/"+grp, "cgroup.type")).To(gomega.Equal("threaded"))
	}
	g.Expect(readGroupFile(t, "eve-user-apps/dom", "cgroup.subtree_control")).To(gomega.Equal("+cpuset"))
	g.Expect(*moves).To(gomega.ConsistOf(
		threadMove{"eve-user-apps/dom/emulator", 1318, "2"},
		threadMove{"eve-user-apps/dom/vcpu0", 1320, "6"},
		threadMove{"eve-user-apps/dom/vcpu1", 1321, "7"},
		threadMove{"eve-user-apps/dom/emulator", 1330, "2"},
	))
	g.Expect(readGroupFile(t, "eve-user-apps/dom", "cpuset.cpus")).To(gomega.Equal("6,7,2"))
}

// With io_placement=dedicated the emulator group follows the domain: its own
// CPUs.
func TestArrangeDomainThreads_PinnedIODedicated(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeDomain(t, []int{1320, 1321}, []int{1318})
	recordMoves(t, nil)

	g.Expect(arrangeDomainThreads("dom", "qmp",
		types.CPUAssignment{CPUs: []uint32{6, 7}})).To(gomega.Succeed())

	g.Expect(readGroupFile(t, "eve-user-apps/dom/emulator", "cpuset.cpus")).To(gomega.BeEmpty())
	g.Expect(readGroupFile(t, "eve-user-apps/dom", "cpuset.cpus")).To(gomega.Equal("6,7"))
}

// An unpinned domain gets the same tree, every group following the domain,
// whose CPUs domainmgr keeps on the housekeeping set.
func TestArrangeDomainThreads_Unpinned(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeDomain(t, []int{1320, 1321}, []int{1318})
	moves := recordMoves(t, nil)

	g.Expect(arrangeDomainThreads("dom", "qmp", types.CPUAssignment{})).To(gomega.Succeed())

	g.Expect(*moves).To(gomega.ConsistOf(
		threadMove{"eve-user-apps/dom/emulator", 1318, ""},
		threadMove{"eve-user-apps/dom/vcpu0", 1320, ""},
		threadMove{"eve-user-apps/dom/vcpu1", 1321, ""},
	))
	g.Expect(readGroupFile(t, "eve-user-apps/dom", "cpuset.cpus")).To(gomega.Equal("2"))
}

// QEMU running a different number of vCPUs than were placed is refused before
// any thread moves.
func TestArrangeDomainThreads_VCPUCountMismatch(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeDomain(t, []int{1320, 1321}, []int{1318})
	moves := recordMoves(t, nil)

	err := arrangeDomainThreads("dom", "qmp", types.CPUAssignment{CPUs: []uint32{6, 7, 8}})
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("vcpu count mismatch")))
	g.Expect(*moves).To(gomega.BeEmpty())
}

// A thread that exited after the listing is skipped; any other failure to move
// one fails the arrangement, so the guest stays paused.
func TestArrangeDomainThreads_MoveFailures(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeDomain(t, []int{1320, 1321}, []int{1318, 1330})
	recordMoves(t, map[int]error{1330: unix.ESRCH})
	g.Expect(arrangeDomainThreads("dom", "qmp",
		types.CPUAssignment{CPUs: []uint32{6, 7}})).To(gomega.Succeed())

	fakeDomain(t, []int{1320, 1321}, []int{1318, 1330})
	recordMoves(t, map[int]error{1330: unix.EINVAL})
	g.Expect(arrangeDomainThreads("dom", "qmp",
		types.CPUAssignment{CPUs: []uint32{6, 7}})).To(gomega.MatchError(unix.EINVAL))
}

// A failed QMP query fails the arrangement.
func TestArrangeDomainThreads_QMPError(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeDomain(t, nil, []int{1318})
	old := vcpuThreadIDs
	vcpuThreadIDs = func(string) ([]int, error) { return nil, errors.New("no qmp") }
	t.Cleanup(func() { vcpuThreadIDs = old })
	g.Expect(arrangeDomainThreads("dom", "qmp", types.CPUAssignment{})).
		To(gomega.MatchError(gomega.ContainSubstring("no qmp")))
}

func TestThreadByComm(t *testing.T) {
	g := gomega.NewWithT(t)
	p := newFakeProc(t)
	p.thread("1318", "1318", "qemu-system-x86")
	p.thread("1318", "1373", kvmNXRecoveryComm)
	g.Expect(threadByComm(1318, kvmNXRecoveryComm)).To(gomega.Equal(1373))
	g.Expect(threadByComm(1318, "absent")).To(gomega.Equal(0))
	g.Expect(threadByComm(4242, kvmNXRecoveryComm)).To(gomega.Equal(0))
}

// The thread is created by the first vCPU to run, after cont, in that vCPU's
// group: placement waits for it and then moves it into the emulator group.
func TestPlaceNXRecoveryThreadWaitsForIt(t *testing.T) {
	g := gomega.NewWithT(t)
	p := newFakeProc(t)
	p.thread("1318", "1318", "qemu-system-x86")
	moves := recordMoves(t, nil)
	go func() {
		time.Sleep(30 * time.Millisecond)
		p.thread("1318", "1373", kvmNXRecoveryComm)
	}()
	placeNXRecoveryThread("dom", 1318, "eve-user-apps/dom/emulator")
	g.Expect(*moves).To(gomega.Equal([]threadMove{{"eve-user-apps/dom/emulator", 1373, ""}}))
}

// No thread (a kernel that runs it elsewhere): give up after nxRecoveryWait.
func TestPlaceNXRecoveryThreadGivesUp(t *testing.T) {
	g := gomega.NewWithT(t)
	p := newFakeProc(t)
	p.thread("1318", "1318", "qemu-system-x86")
	moves := recordMoves(t, nil)
	old := nxRecoveryWait
	nxRecoveryWait = 50 * time.Millisecond
	t.Cleanup(func() { nxRecoveryWait = old })
	start := time.Now()
	placeNXRecoveryThread("dom", 1318, "eve-user-apps/dom/emulator")
	g.Expect(*moves).To(gomega.BeEmpty())
	g.Expect(time.Since(start)).To(gomega.BeNumerically("<", time.Second))
}

// x86 KVM starts the thread unless the mitigation is hard-disabled.
func TestNXRecoveryThreadExpected(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the thread exists on x86 KVM only")
	}
	g := gomega.NewWithT(t)
	param := filepath.Join(t.TempDir(), "nx_huge_pages")
	old := kvmNXHugePages
	kvmNXHugePages = param
	t.Cleanup(func() { kvmNXHugePages = old })

	g.Expect(nxRecoveryThreadExpected()).To(gomega.BeFalse(), "no kvm module")
	for val, want := range map[string]bool{"Y\n": true, "N\n": true, "never\n": false} {
		g.Expect(os.WriteFile(param, []byte(val), 0o644)).To(gomega.Succeed())
		g.Expect(nxRecoveryThreadExpected()).To(gomega.Equal(want), "nx_huge_pages=%q", val)
	}
}

// A running domain's IO threads follow the housekeeping set: the domain gets
// its vCPUs' CPUs and the new set, the emulator group the new set.
func TestSetIOCPUs(t *testing.T) {
	g := gomega.NewWithT(t)
	cgrouptest.FakeTree(t, map[string]string{
		"eve-user-apps/dom/cpuset.cpus":          "6,7,2",
		"eve-user-apps/dom/emulator/cpuset.cpus": "2",
	})
	a := types.CPUAssignment{CPUs: []uint32{6, 7}, IOCPUs: []uint32{2, 3, 4}}

	g.Expect(SetIOCPUs("dom", a)).To(gomega.Succeed())

	g.Expect(readGroupFile(t, "eve-user-apps/dom", "cpuset.cpus")).To(gomega.Equal("6,7,2,3,4"))
	g.Expect(readGroupFile(t, "eve-user-apps/dom/emulator", "cpuset.cpus")).To(gomega.Equal("2,3,4"))
}

// The domain's group is written before its emulator group: when the domain
// cannot take the set, the emulator group keeps the CPUs it had.
func TestSetIOCPUs_DomainFirst(t *testing.T) {
	g := gomega.NewWithT(t)
	cgrouptest.FakeTree(t, map[string]string{
		"eve-user-apps/dom/emulator/cpuset.cpus": "2",
	})
	domainFile := cgroup.Path("eve-user-apps/dom", "cpuset.cpus")
	g.Expect(os.Mkdir(domainFile, 0o755)).To(gomega.Succeed()) // a write to it fails
	a := types.CPUAssignment{CPUs: []uint32{6, 7}, IOCPUs: []uint32{3}}

	g.Expect(SetIOCPUs("dom", a)).ToNot(gomega.Succeed())

	g.Expect(readGroupFile(t, "eve-user-apps/dom/emulator", "cpuset.cpus")).To(gomega.Equal("2"))
}

// io_uring serves only a domain whose non-vCPU threads never move; the others
// use QEMU's thread pool, whose workers follow the emulator group.
func TestAioType(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    types.CPUAssignment
		want string
	}{
		{"no CPUs of its own: follows the housekeeping set", types.CPUAssignment{}, "threads"},
		{"own CPUs, io_placement=dedicated", types.CPUAssignment{CPUs: []uint32{6, 7}}, "io_uring"},
		{"own CPUs, io_placement=housekeeping",
			types.CPUAssignment{CPUs: []uint32{6, 7}, IOCPUs: []uint32{0, 1}}, "threads"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var status types.DomainStatus
			status.Placement.Assigned = tc.a
			if got := aioType(status); got != tc.want {
				t.Errorf("aioType = %q, want %q", got, tc.want)
			}
		})
	}
}
