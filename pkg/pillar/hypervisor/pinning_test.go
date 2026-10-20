// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
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

// stubAffinity records setAffinity calls instead of making them.
func stubAffinity(t *testing.T) *[]affinityCall {
	var mu sync.Mutex
	calls := &[]affinityCall{}
	old := setAffinity
	setAffinity = func(tid int, cpus []uint32) error {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, affinityCall{tid, cpus})
		return nil
	}
	t.Cleanup(func() { setAffinity = old })
	return calls
}

type affinityCall struct {
	tid  int
	cpus []uint32
}

// Non-vCPU threads of a pinned workload go to the emulator set under
// io_placement=housekeeping and to the workload's own CPUs otherwise; a
// workload without CPUs of its own is left alone.
func TestLateThreadCPUs(t *testing.T) {
	g := NewWithT(t)
	g.Expect(lateThreadCPUs([]uint32{30, 31}, []uint32{0})).To(Equal([]uint32{0}))
	g.Expect(lateThreadCPUs([]uint32{30, 31}, nil)).To(Equal([]uint32{30, 31}))
	g.Expect(lateThreadCPUs(nil, []uint32{0})).To(BeNil())
}

func TestThreadByComm(t *testing.T) {
	g := NewWithT(t)
	p := newFakeProc(t)
	p.thread("1318", "1318", "qemu-system-x86")
	p.thread("1318", "1373", kvmNXRecoveryComm)
	g.Expect(threadByComm(1318, kvmNXRecoveryComm)).To(Equal(1373))
	g.Expect(threadByComm(1318, "absent")).To(Equal(0))
	g.Expect(threadByComm(4242, kvmNXRecoveryComm)).To(Equal(0))
}

// The thread is created by the first vCPU to run, after cont: placement waits
// for it and then gives it the workload's non-vCPU CPUs.
func TestPlaceNXRecoveryThreadWaitsForIt(t *testing.T) {
	g := NewWithT(t)
	p := newFakeProc(t)
	p.thread("1318", "1318", "qemu-system-x86")
	calls := stubAffinity(t)
	go func() {
		time.Sleep(30 * time.Millisecond)
		p.thread("1318", "1373", kvmNXRecoveryComm)
	}()
	placeNXRecoveryThread("dom", 1318, []uint32{0})
	g.Expect(*calls).To(Equal([]affinityCall{{1373, []uint32{0}}}))
}

// No thread (a kernel that runs it elsewhere): give up after nxRecoveryWait.
func TestPlaceNXRecoveryThreadGivesUp(t *testing.T) {
	g := NewWithT(t)
	p := newFakeProc(t)
	p.thread("1318", "1318", "qemu-system-x86")
	calls := stubAffinity(t)
	old := nxRecoveryWait
	nxRecoveryWait = 50 * time.Millisecond
	t.Cleanup(func() { nxRecoveryWait = old })
	start := time.Now()
	placeNXRecoveryThread("dom", 1318, []uint32{0})
	g.Expect(*calls).To(BeEmpty())
	g.Expect(time.Since(start)).To(BeNumerically("<", time.Second))
}

// x86 KVM starts the thread unless the mitigation is hard-disabled.
func TestNXRecoveryThreadExpected(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the thread exists on x86 KVM only")
	}
	g := NewWithT(t)
	param := filepath.Join(t.TempDir(), "nx_huge_pages")
	old := kvmNXHugePages
	kvmNXHugePages = param
	t.Cleanup(func() { kvmNXHugePages = old })

	g.Expect(nxRecoveryThreadExpected()).To(BeFalse(), "no kvm module")
	for val, want := range map[string]bool{"Y\n": true, "N\n": true, "never\n": false} {
		g.Expect(os.WriteFile(param, []byte(val), 0o644)).To(Succeed())
		g.Expect(nxRecoveryThreadExpected()).To(Equal(want), "nx_huge_pages=%q", val)
	}
}
