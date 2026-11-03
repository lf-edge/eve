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
		func(*proxmox.VirtualMachine) error { calls++; return nil })
	if err != nil || calls != 0 {
		t.Fatalf("expected success without calling op, got err=%v calls=%d", err, calls)
	}
}

func TestSetVMPowerStateRetriesFailure(t *testing.T) {
	p, dev := newFakeVMProvider(t, &fakeVMAPI{status: "stopped"})
	calls := 0
	err := p.setVMPowerState(context.Background(), dev, "start", vmRunning,
		func(*proxmox.VirtualMachine) error {
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
		func(*proxmox.VirtualMachine) error {
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
		func(*proxmox.VirtualMachine) error {
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
		func(*proxmox.VirtualMachine) error { calls++; return nil })
	if !isVMNotFoundErr(err) || calls != 0 {
		t.Fatalf("expected a not-found error without calling op, got err=%v calls=%d", err, calls)
	}
}
