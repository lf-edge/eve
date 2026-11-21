// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luthermonson/go-proxmox"
	"github.com/sirupsen/logrus"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

func TestIsVMNotFoundErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			// Verbatim from PVE, as go-proxmox returns it (the HTTP status line).
			"missing VM",
			errors.New("500 Configuration file 'nodes/r660xs/qemu-server/99999.conf' does not exist"),
			true,
		},
		{
			"wrapped missing VM",
			fmt.Errorf("lookup: %w",
				errors.New("500 Configuration file 'nodes/pve/qemu-server/7.conf' does not exist")),
			true,
		},
		{
			// PVE failing to fork an API worker on a host out of memory.
			"worker failure",
			errors.New("500 got no worker upid - start worker failed"),
			false,
		},
		{
			"transport failure",
			&url.Error{Op: "Get", URL: "https://pve:8006/api2/json", Err: io.ErrUnexpectedEOF},
			false,
		},
		{
			"other missing object",
			errors.New("500 storage 'local-zfs' does not exist"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isVMNotFoundErr(tt.err); got != tt.want {
				t.Fatalf("isVMNotFoundErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// fakeTaskStatus is a Proxmox task status endpoint that answers each poll with
// the next of replies, repeating the last one: a JSON body, or "" for an HTTP
// 500. It counts the polls.
type fakeTaskStatus struct {
	mu      sync.Mutex
	replies []string
	polls   int
}

func (f *fakeTaskStatus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	reply := f.replies[min(f.polls, len(f.replies)-1)]
	f.polls++
	f.mu.Unlock()
	if !strings.HasSuffix(r.URL.Path, "/status") || reply == "" {
		http.Error(w, "fake failure", http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, reply)
}

// The status of a qmstart task that failed on a real PVE host.
const (
	testTaskUPID = "UPID:farfalle:00133FF7:7A3B88BA:6AE9140C:qmstart:110:root@pam:"
	taskRunning  = `{"data":{"upid":"` + testTaskUPID + `","status":"running"}}`
	taskOK       = `{"data":{"upid":"` + testTaskUPID + `","status":"stopped","exitstatus":"OK"}}`
	taskFailed   = `{"data":{"upid":"` + testTaskUPID + `","type":"qmstart","node":"farfalle",` +
		`"id":"110","user":"root@pam","exitstatus":"start failed: QEMU exited with code 1",` +
		`"status":"stopped","pid":1261559}}`
)

func waitFakeTask(ctx context.Context, t *testing.T, replies ...string) (int, error) {
	t.Helper()
	saved := proxmoxTaskPollInterval
	proxmoxTaskPollInterval = time.Millisecond
	defer func() { proxmoxTaskPollInterval = saved }()
	fake := &fakeTaskStatus{replies: replies}
	srv := httptest.NewServer(fake)
	client := proxmox.NewClient(srv.URL+"/api2/json", proxmox.WithHTTPClient(srv.Client()))
	err := waitTask(ctx, proxmox.NewTask(proxmox.UPID(testTaskUPID), client))
	// Close waits for handlers still serving a poll that a cancelled wait
	// abandoned.
	srv.Close()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.polls, err
}

func TestWaitTaskReportsFailedTask(t *testing.T) {
	_, err := waitFakeTask(context.Background(), t, taskRunning, taskFailed)
	if !errors.Is(err, errTaskFailed) {
		t.Fatalf("expected errTaskFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "start failed: QEMU exited with code 1") {
		t.Fatalf("error does not carry the task's exit status: %v", err)
	}
}

func TestWaitTaskSucceeds(t *testing.T) {
	if _, err := waitFakeTask(context.Background(), t, taskRunning, taskRunning, taskOK); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestWaitTaskToleratesFailedPolls(t *testing.T) {
	_, err := waitFakeTask(context.Background(), t, taskRunning, "", "", "", taskRunning, "", taskOK)
	if err != nil {
		t.Fatalf("expected the wait to ride out failed polls, got %v", err)
	}
}

func TestWaitTaskGivesUpOnPersistentPollFailures(t *testing.T) {
	polls, err := waitFakeTask(context.Background(), t, "")
	if err == nil || errors.Is(err, errTaskFailed) {
		t.Fatalf("expected a status read failure, got %v", err)
	}
	if polls != proxmoxTaskMaxPollErrors {
		t.Fatalf("expected %d polls, got %d", proxmoxTaskMaxPollErrors, polls)
	}
}

func TestWaitTaskStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := waitFakeTask(ctx, t, taskRunning); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the context's error, got %v", err)
	}
}

// fakeVMAPI serves the Proxmox API calls that getVM makes for VM 110 on node
// "pve", reporting the VM in the state set by setStatus, or as missing.
type fakeVMAPI struct {
	mu      sync.Mutex
	status  string
	missing bool
}

func (f *fakeVMAPI) setStatus(status string) {
	f.mu.Lock()
	f.status = status
	f.mu.Unlock()
}

func (f *fakeVMAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	status, missing := f.status, f.missing
	f.mu.Unlock()
	switch r.URL.Path {
	case "/api2/json/nodes/pve/status":
		_, _ = io.WriteString(w, `{"data":{}}`)
	case "/api2/json/nodes/pve/qemu/110/status/current":
		if missing {
			// PVE puts its error message in the status line, which
			// net/http's ResponseWriter cannot set.
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = buf.WriteString("HTTP/1.1 500 Configuration file " +
				"'nodes/pve/qemu-server/110.conf' does not exist\r\n" +
				"Content-Length: 0\r\nConnection: close\r\n\r\n")
			_ = buf.Flush()
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":{"vmid":110,"status":%q}}`, status)
	case "/api2/json/nodes/pve/qemu/110/config":
		_, _ = io.WriteString(w, `{"data":{"name":"ev-eve-test"}}`)
	default:
		http.NotFound(w, r)
	}
}

func newFakeVMProvider(t *testing.T, api *fakeVMAPI) (*ProxmoxProvider, *proxmoxDevice) {
	t.Helper()
	saved := proxmoxRetryDelay
	proxmoxRetryDelay = time.Millisecond
	t.Cleanup(func() { proxmoxRetryDelay = saved })
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	p := &ProxmoxProvider{
		conf:   ProxmoxProviderConf{Node: "pve"},
		client: proxmox.NewClient(srv.URL+"/api2/json", proxmox.WithHTTPClient(srv.Client())),
	}
	return p, &proxmoxDevice{name: "edge-dev", vmID: 110}
}

func TestSetVMPowerStateSkipsVMInTargetState(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{status: "running"})
	calls := 0
	err := p.setVMPowerState(context.Background(), dev, "start", vmRunning,
		func(context.Context, *proxmox.VirtualMachine) error { calls++; return nil })
	if err != nil || calls != 0 {
		t.Fatalf("expected success without calling op, got err=%v calls=%d", err, calls)
	}
}

func TestSetVMPowerStateRetriesFailure(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{status: "stopped"})
	calls := 0
	err := p.setVMPowerState(context.Background(), dev, "start", vmRunning,
		func(context.Context, *proxmox.VirtualMachine) error {
			calls++
			if calls == 1 {
				return fmt.Errorf("%w: start failed: QEMU exited with code 1", errTaskFailed)
			}
			return nil
		})
	if err != nil || calls != 2 {
		t.Fatalf("expected success on the second attempt, got err=%v calls=%d", err, calls)
	}
}

// A failed attempt that nevertheless got the VM to its target state, e.g.
// one whose response was lost, must count as done instead of being repeated.
func TestSetVMPowerStateAcceptsTargetReachedDespiteError(t *testing.T) {
	api := &fakeVMAPI{status: "running"}
	p, dev := newFakeVMProvider(t, api)
	calls := 0
	err := p.setVMPowerState(context.Background(), dev, "stop", vmStopped,
		func(context.Context, *proxmox.VirtualMachine) error {
			calls++
			api.setStatus("stopped")
			return errors.New("unexpected end of JSON input")
		})
	if err != nil || calls != 1 {
		t.Fatalf("expected success after one attempt, got err=%v calls=%d", err, calls)
	}
}

func TestSetVMPowerStateDoesNotRetryPermanentFailure(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{status: "running"})
	calls := 0
	err := p.setVMPowerState(context.Background(), dev, "shut down", vmStopped,
		func(context.Context, *proxmox.VirtualMachine) error {
			calls++
			return permanent(fmt.Errorf("%w: VM quit/powerdown failed - got timeout", errTaskFailed))
		})
	if !errors.Is(err, errTaskFailed) || calls != 1 {
		t.Fatalf("expected the permanent failure after one attempt, got err=%v calls=%d", err, calls)
	}
}

func TestSetVMPowerStateMissingVM(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{missing: true})
	calls := 0
	err := p.setVMPowerState(context.Background(), dev, "start", vmRunning,
		func(context.Context, *proxmox.VirtualMachine) error { calls++; return nil })
	if !isVMNotFoundErr(err) || calls != 0 {
		t.Fatalf("expected a not-found error without calling op, got err=%v calls=%d", err, calls)
	}
}

// PVE starts QEMU with one thread per core whatever the device asks for, so a
// requested SMT layout has to reach QEMU through args, as the -smp the qemu
// provider passes; a device that asks for none gets no -smp of its own.
func TestBuildVMOptionsThreadsPerCore(t *testing.T) {
	for _, tc := range []struct {
		name           string
		threadsPerCore uint
		want           string
	}{
		{"SMT", 2, " -smp 8,sockets=1,cores=4,threads=2"},
		{"no SMT", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &ProxmoxProvider{conf: ProxmoxProviderConf{Storage: "local-lvm"}}
			dev := &proxmoxDevice{name: "dev", vmID: 100, spec: DeviceSpec{
				CPUs: 8, ThreadsPerCore: tc.threadsPerCore, MemoryBytes: 8 << 30,
				Arch: api.ArchType_ARCH_AMD64,
			}}
			options, err := p.buildVMOptions(dev, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			var args string
			for _, o := range options {
				if o.Name == "args" {
					args = fmt.Sprint(o.Value)
				}
			}
			if tc.want == "" {
				if strings.Contains(args, "-smp") {
					t.Errorf("args carry a -smp for a device without SMT: %s", args)
				}
			} else if !strings.Contains(args, tc.want) {
				t.Errorf("args lack %q: %s", tc.want, args)
			}
		})
	}
}

// A delete that PVE completes after the teardown gave up leaves only the
// device entry behind, which the next setup of the same name must clear.
func TestRemoveLeftoverDeviceWithVMGone(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{missing: true})
	p.devices = map[string]*proxmoxDevice{dev.name: dev}
	if err := p.removeLeftoverDevice(
		context.Background(), logrus.NewEntry(logrus.New()), dev); err != nil {
		t.Fatalf("removeLeftoverDevice: %v", err)
	}
	if _, ok := p.devices[dev.name]; ok {
		t.Error("leftover device entry was not removed")
	}
}

func TestRemoveLeftoverDeviceKeepsEntryOnFailure(t *testing.T) {
	// The fake API does not serve the VM delete, so the teardown fails.
	p, dev := newFakeVMProvider(t, &fakeVMAPI{status: "stopped"})
	p.devices = map[string]*proxmoxDevice{dev.name: dev}
	if err := p.removeLeftoverDevice(
		context.Background(), logrus.NewEntry(logrus.New()), dev); err == nil {
		t.Fatal("expected an error when the VM cannot be deleted")
	}
	if _, ok := p.devices[dev.name]; !ok {
		t.Error("device entry was dropped although its VM was not removed")
	}
}

// A failed teardown marks the device as a leftover for the next setup to
// remove, while a setup of a device that was never torn down still fails
// without touching its VM.
func TestSetupDeviceRemovesOnlyLeftovers(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{status: "stopped"})
	p.devices = map[string]*proxmoxDevice{dev.name: dev}
	p.pending = map[string]*proxmoxDevice{}
	ctx := context.Background()

	err := p.SetupDevice(ctx, dev.name, DeviceSpec{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("setup of a live device: got %v, want an already-exists error", err)
	}
	if p.devices[dev.name] != dev {
		t.Error("setup of a live device replaced its entry")
	}
	if _, ok := p.pending[dev.name]; ok {
		t.Error("rejected setup left its name reserved")
	}

	if err := p.TeardownDevice(ctx, dev.name); err == nil {
		t.Fatal("expected the teardown to fail when the VM cannot be deleted")
	}
	if !p.devices[dev.name].teardownFailed {
		t.Error("failed teardown did not mark the device as a leftover")
	}
}

func TestAttemptContext(t *testing.T) {
	savedDelay, savedMin := proxmoxRetryDelay, proxmoxMinAttemptTime
	proxmoxRetryDelay, proxmoxMinAttemptTime = 10*time.Second, 30*time.Second
	t.Cleanup(func() { proxmoxRetryDelay, proxmoxMinAttemptTime = savedDelay, savedMin })

	for _, tc := range []struct {
		name         string
		timeLeft     time.Duration
		attemptsLeft int
		want         time.Duration
		wantLast     bool
	}{
		// (320s - 2 pauses) / 3
		{"split among 3", 320 * time.Second, 3, 100 * time.Second, false},
		// (320s - 1 pause) / 2
		{"split among 2", 320 * time.Second, 2, 155 * time.Second, false},
		{"last gets all", 320 * time.Second, 1, 320 * time.Second, true},
		// (75s - 2 pauses) / 3 < 30s, so only 2 attempts: (75s - 1 pause) / 2.
		{"too short for 3", 75 * time.Second, 3, 32500 * time.Millisecond, false},
		// Too short even for 2 attempts: one gets all the time left.
		{"too short for 2", 50 * time.Second, 3, 50 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeLeft)
			defer cancel()
			attemptCtx, attemptCancel, last := attemptContext(ctx, tc.attemptsLeft)
			defer attemptCancel()
			deadline, _ := attemptCtx.Deadline()
			if got := time.Until(deadline); got > tc.want || got < tc.want-time.Second {
				t.Errorf("attempt deadline in %v, want %v", got, tc.want)
			}
			if last != tc.wantLast {
				t.Errorf("last = %v, want %v", last, tc.wantLast)
			}
		})
	}

	attemptCtx, attemptCancel, last := attemptContext(context.Background(), 3)
	defer attemptCancel()
	if _, ok := attemptCtx.Deadline(); ok || last {
		t.Errorf("attempt of a call without a deadline: deadline set %v, last %v, "+
			"want neither", ok, last)
	}
}

// A call with too little time left for several attempts is made once, with
// all of it, instead of being cut into attempts too short to succeed.
func TestRetryProxmoxCallMakesOneAttemptWhenShortOfTime(t *testing.T) {
	savedDelay, savedMin := proxmoxRetryDelay, proxmoxMinAttemptTime
	proxmoxRetryDelay, proxmoxMinAttemptTime = time.Millisecond, time.Hour
	t.Cleanup(func() { proxmoxRetryDelay, proxmoxMinAttemptTime = savedDelay, savedMin })

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	attempts := 0
	_, err := retryProxmoxCall(ctx, logrus.NewEntry(logrus.New()), "delete",
		func(context.Context) (struct{}, error) {
			attempts++
			return struct{}{}, errors.New("transient failure")
		})
	if err == nil || attempts != 1 {
		t.Fatalf("expected one failed attempt, got err=%v attempts=%d", err, attempts)
	}
}

// An attempt that hangs until its share of the deadline runs out must leave
// time for the retries, e.g. for a VM delete that PVE completes just after
// the first attempt gave up waiting for it.
func TestRetryProxmoxCallRetriesAfterAttemptTimeout(t *testing.T) {
	savedDelay, savedMin := proxmoxRetryDelay, proxmoxMinAttemptTime
	proxmoxRetryDelay, proxmoxMinAttemptTime = time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { proxmoxRetryDelay, proxmoxMinAttemptTime = savedDelay, savedMin })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	attempts := 0
	_, err := retryProxmoxCall(ctx, logrus.NewEntry(logrus.New()), "delete",
		func(ctx context.Context) (struct{}, error) {
			attempts++
			if attempts == 1 {
				<-ctx.Done()
				return struct{}{}, ctx.Err()
			}
			return struct{}{}, nil
		})
	if err != nil || attempts != 2 {
		t.Fatalf("expected success on the second attempt, got err=%v attempts=%d",
			err, attempts)
	}
}
