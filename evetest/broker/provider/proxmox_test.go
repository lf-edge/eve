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
	"reflect"
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

// A create that PVE fails transiently, e.g. when it cannot fork the create
// worker, is retried with a fresh VMID once the failed one has been cleaned
// up.
func TestCreateVMRetriesWithNewVMID(t *testing.T) {
	saved := proxmoxRetryDelay
	proxmoxRetryDelay = time.Millisecond
	t.Cleanup(func() { proxmoxRetryDelay = saved })

	var mu sync.Mutex
	nextID, creates := 111, 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api2/json/cluster/nextid":
			_, _ = fmt.Fprintf(w, `{"data":"%d"}`, nextID)
			nextID++
		case "/api2/json/nodes/pve/qemu":
			creates++
			if creates == 1 {
				http.Error(w, "got no worker upid - start worker failed",
					http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(w,
				`{"data":"UPID:pve:00000001:00000002:00000003:qmcreate:112:root@pam:"}`)
		case "/api2/json/nodes/pve/qemu/111/status/current":
			// The failed create left nothing behind.
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = buf.WriteString("HTTP/1.1 500 Configuration file " +
				"'nodes/pve/qemu-server/111.conf' does not exist\r\n" +
				"Content-Length: 0\r\nConnection: close\r\n\r\n")
			_ = buf.Flush()
		default:
			http.NotFound(w, r)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	client := proxmox.NewClient(srv.URL+"/api2/json", proxmox.WithHTTPClient(srv.Client()))
	p := &ProxmoxProvider{
		conf:   ProxmoxProviderConf{Node: "pve", Storage: "local-lvm"},
		client: client,
	}
	node := (&proxmox.Node{}).New(client, "pve")
	cluster := (&proxmox.Cluster{}).New(client)
	dev := &proxmoxDevice{name: "dev", spec: DeviceSpec{
		CPUs: 2, MemoryBytes: 1 << 30, Arch: api.ArchType_ARCH_AMD64,
	}}
	log := logrus.NewEntry(logrus.New())

	_, err := retryProxmoxCall(context.Background(), log, "create",
		func(ctx context.Context) (*proxmox.Task, error) {
			return p.createVM(ctx, ctx, log, node, cluster, dev, nil, "")
		})
	if err != nil {
		t.Fatalf("expected the second create to succeed, got: %v", err)
	}
	if creates != 2 || dev.vmID != 112 {
		t.Errorf("got %d creates and VMID %d, want 2 creates and VMID 112",
			creates, dev.vmID)
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

// fakeCreateAPI serves VMID allocation, VM creation and the status of the
// create tasks, whose exit status taskExit gives per VMID; the status of a task
// missing there cannot be read. A VM that is looked up, which removeVM does
// first, is recorded in lookups and reported missing.
type fakeCreateAPI struct {
	mu       sync.Mutex
	nextID   int
	creates  []int
	lookups  []string
	taskExit map[int]string
	// onFailedTask, if set, is called when the failure of the create task of
	// a VM is reported.
	onFailedTask func(vmID int)
}

func (f *fakeCreateAPI) upid(vmID int) string {
	return fmt.Sprintf("UPID:pve:00000001:00000002:00000003:qmcreate:%d:root@pam:", vmID)
}

func (f *fakeCreateAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/api2/json/cluster/nextid":
		_, _ = fmt.Fprintf(w, `{"data":"%d"}`, f.nextID)
		f.nextID++
	case r.URL.Path == "/api2/json/nodes/pve/qemu":
		vmID := f.nextID - 1
		f.creates = append(f.creates, vmID)
		_, _ = fmt.Fprintf(w, `{"data":%q}`, f.upid(vmID))
	case strings.HasPrefix(r.URL.Path, "/api2/json/nodes/pve/tasks/"):
		for vmID, exit := range f.taskExit {
			if strings.Contains(r.URL.Path, f.upid(vmID)) {
				if exit != "OK" && f.onFailedTask != nil {
					f.onFailedTask(vmID)
				}
				_, _ = fmt.Fprintf(w,
					`{"data":{"status":"stopped","exitstatus":%q}}`, exit)
				return
			}
		}
		http.NotFound(w, r)
	case strings.HasSuffix(r.URL.Path, "/status/current"):
		f.lookups = append(f.lookups, strings.TrimSuffix(
			strings.TrimPrefix(r.URL.Path, "/api2/json/nodes/pve/qemu/"),
			"/status/current"))
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 500 Configuration file " +
			"'nodes/pve/qemu-server/1.conf' does not exist\r\n" +
			"Content-Length: 0\r\nConnection: close\r\n\r\n")
		_ = buf.Flush()
	default:
		http.NotFound(w, r)
	}
}

func createWithRetry(t *testing.T, fake *fakeCreateAPI,
	prepare ...func(*ProxmoxProvider)) error {
	t.Helper()
	savedDelay, savedPoll := proxmoxRetryDelay, proxmoxTaskPollInterval
	proxmoxRetryDelay, proxmoxTaskPollInterval = time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		proxmoxRetryDelay, proxmoxTaskPollInterval = savedDelay, savedPoll
	})
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client := proxmox.NewClient(srv.URL+"/api2/json", proxmox.WithHTTPClient(srv.Client()))
	p := &ProxmoxProvider{
		conf:    ProxmoxProviderConf{Node: "pve", Storage: "local-lvm"},
		client:  client,
		devices: map[string]*proxmoxDevice{},
		pending: map[string]*proxmoxDevice{},
	}
	for _, prep := range prepare {
		prep(p)
	}
	node := (&proxmox.Node{}).New(client, "pve")
	cluster := (&proxmox.Cluster{}).New(client)
	dev := &proxmoxDevice{name: "dev", spec: DeviceSpec{
		CPUs: 2, MemoryBytes: 1 << 30, Arch: api.ArchType_ARCH_AMD64,
	}}
	log := logrus.NewEntry(logrus.New())
	ctx := context.Background()
	_, err := retryProxmoxCall(ctx, log, "create",
		func(callCtx context.Context) (struct{}, error) {
			return struct{}{}, p.createAndWaitVM(
				callCtx, ctx, log, node, cluster, dev, nil, "")
		})
	return err
}

// A create task that PVE completed as failed, e.g. because creates that import
// disks at the same time timed out on PVE's storage lock, is retried with a
// new VMID once the failed VM is removed.
func TestCreateAndWaitVMRetriesFailedTask(t *testing.T) {
	for _, exit := range []string{
		"unable to create VM 111 - cannot import from 'local:import/disk.qcow2' - " +
			"can't lock file '/var/lock/pve-manager/pve-storage-pool' - got timeout",
		"unable to create VM 111 - unable to allocate disk",
	} {
		t.Run(exit, func(t *testing.T) {
			api := &fakeCreateAPI{nextID: 111,
				taskExit: map[int]string{111: exit, 112: "OK"}}
			if err := createWithRetry(t, api); err != nil {
				t.Fatalf("expected the second create to succeed, got %v", err)
			}
			if !reflect.DeepEqual(api.creates, []int{111, 112}) {
				t.Errorf("got creates of VMs %v, want [111 112]", api.creates)
			}
			if !reflect.DeepEqual(api.lookups, []string{"111"}) {
				t.Errorf("got lookups of VMs %v, want the failed VM 111 removed",
					api.lookups)
			}
		})
	}
}

// A wait for the create task that fails on the client side is not retried, as
// PVE may still be creating the VM; the VM is still removed.
func TestCreateAndWaitVMDoesNotRetryFailedWait(t *testing.T) {
	api := &fakeCreateAPI{nextID: 111, taskExit: map[int]string{}}
	err := createWithRetry(t, api)
	if err == nil || errors.Is(err, errTaskFailed) {
		t.Fatalf("expected the wait for the task to fail, got %v", err)
	}
	if !reflect.DeepEqual(api.creates, []int{111}) {
		t.Errorf("got creates of VMs %v, want [111]", api.creates)
	}
	if !reflect.DeepEqual(api.lookups, []string{"111"}) {
		t.Errorf("got lookups of VMs %v, want VM 111 removed", api.lookups)
	}
}

// When PVE removes the VM of a failed create task itself, its VMID can be
// allocated to another device before the cleanup runs, which must then leave
// that device's VM alone.
func TestCreateAndWaitVMSkipsRecycledVMID(t *testing.T) {
	api := &fakeCreateAPI{nextID: 111, taskExit: map[int]string{
		111: "can't lock file '/var/lock/pve-manager/pve-storage-local' - got timeout",
		112: "OK",
	}}
	err := createWithRetry(t, api, func(p *ProxmoxProvider) {
		api.onFailedTask = func(vmID int) {
			p.devMutex.Lock()
			p.pending["other"] = &proxmoxDevice{name: "other", vmID: vmID}
			p.devMutex.Unlock()
		}
	})
	if err != nil {
		t.Fatalf("expected the retry to succeed, got: %v", err)
	}
	if len(api.lookups) != 0 {
		t.Errorf("cleanup looked up VMs %v, although another device holds VMID 111",
			api.lookups)
	}
}

// A VM is removed only on behalf of the device that holds its VMID: the
// sweep (nil owner) and a device whose VMID was allocated again leave it
// alone.
func TestRemoveVMSparesVMIDOfAnotherDevice(t *testing.T) {
	api := &fakeCreateAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	client := proxmox.NewClient(srv.URL+"/api2/json", proxmox.WithHTTPClient(srv.Client()))
	holder := &proxmoxDevice{name: "holder", vmID: 120}
	p := &ProxmoxProvider{
		conf:    ProxmoxProviderConf{Node: "pve"},
		client:  client,
		devices: map[string]*proxmoxDevice{holder.name: holder},
	}
	node := (&proxmox.Node{}).New(client, "pve")
	log := logrus.NewEntry(logrus.New())
	ctx := context.Background()

	for _, owner := range []*proxmoxDevice{nil, {name: "previous", vmID: 120}} {
		removed, err := p.removeVM(ctx, log, node, owner, 120)
		if removed || err != nil {
			t.Errorf("removeVM for owner %v: got removed=%t err=%v, want neither",
				owner, removed, err)
		}
	}
	if len(api.lookups) != 0 {
		t.Fatalf("looked up VMs %v of another device", api.lookups)
	}
	if _, err := p.removeVM(ctx, log, node, holder, 120); err != nil {
		t.Fatalf("removeVM for the holder: %v", err)
	}
	if !reflect.DeepEqual(api.lookups, []string{"120"}) {
		t.Errorf("holder's removal looked up %v, want [120]", api.lookups)
	}
}
