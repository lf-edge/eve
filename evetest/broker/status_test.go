// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/evetest/broker/provider"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/peer"
)

// fakeHostProvider implements only HostStatus; the embedded nil interface
// makes any other call panic.
type fakeHostProvider struct {
	provider.DeviceProvider
	st    *api.HostStatus
	err   error
	block chan struct{}
}

func (p *fakeHostProvider) HostStatus(ctx context.Context) (*api.HostStatus, error) {
	if p.block != nil {
		<-p.block
	}
	return p.st, p.err
}

func newStatusTestBroker() *broker {
	return &broker{
		globalLog:       logrus.New(),
		provider:        &fakeHostProvider{st: &api.HostStatus{Name: "pve1"}},
		providerName:    "proxmox",
		maxClients:      -1,
		sessions:        make(map[string]*session),
		closingSessions: make(map[string]*session),
		imageClaims:     newImageClaims(imageClaimStartLease, imageClaimProgressLease),
	}
}

func getStatus(t *testing.T, b *broker) *api.GetStatusResponse {
	t.Helper()
	resp, err := b.GetStatus(context.Background(), &api.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	return resp
}

// TestGetStatusReportsSession covers what a session reports over its life:
// the client identity from Connect, the test from KeepAlive, and the devices
// as published by the end of each device operation.
func TestGetStatusReportsSession(t *testing.T) {
	b := newStatusTestBroker()
	ctx := peer.NewContext(context.Background(),
		&peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 41000}})
	connectResp, err := b.Connect(ctx, &api.ConnectRequest{
		ClientInfo: &api.ClientInfo{Hostname: "runner-1", CiJob: "run-suite"},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	clientID := connectResp.ClientId

	resp := getStatus(t, b)
	if len(resp.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(resp.Sessions))
	}
	s := resp.Sessions[0]
	if s.ClientId != clientID || s.PeerAddress != "10.0.0.7:41000" ||
		s.ClientInfo.GetHostname() != "runner-1" || s.ClientInfo.GetCiJob() != "run-suite" {
		t.Errorf("unexpected session identity: %v", s)
	}
	if s.LastKeepAlive != nil || s.Operation != "" || len(s.Devices) != 0 {
		t.Errorf("unexpected state of a fresh session: %v", s)
	}

	sess := b.sessions[clientID]
	sess.recordKeepAlive(&api.KeepAlivePing{ClientId: clientID, CurrentTest: "TestSuite/TestA"})

	// While an operation runs, GetStatus must neither block on the session
	// mutex nor read the devices it is changing.
	sess.mutex.Lock()
	endOperation := sess.beginOperation("SetupDevices")
	sess.sdnDevice = &device{deviceName: "sdn", providerDevName: "sdn-" + clientID,
		created: true, image: "lfedge/evetest-sdn:abc"}
	sess.eveDevices = map[string]*device{
		"edge-dev2": {deviceName: "edge-dev2"},
		"edge-dev1": {deviceName: "edge-dev1", created: true,
			DeviceSpec: provider.DeviceSpec{Arch: api.ArchType_ARCH_AMD64, CPUs: 4}},
	}
	s = getStatus(t, b).Sessions[0]
	if s.CurrentTest != "TestSuite/TestA" || s.LastKeepAlive == nil {
		t.Errorf("keep-alive not recorded: %v", s)
	}
	if s.Operation != "SetupDevices" || s.OperationStartedAt == nil || len(s.Devices) != 0 {
		t.Errorf("unexpected state during SetupDevices: %v", s)
	}
	endOperation()
	sess.mutex.Unlock()

	s = getStatus(t, b).Sessions[0]
	if s.Operation != "" || s.OperationStartedAt != nil {
		t.Errorf("operation not cleared: %v", s)
	}
	var names []string
	for _, d := range s.Devices {
		names = append(names, d.Name)
	}
	if len(names) != 3 || names[0] != "sdn" || names[1] != "edge-dev1" || names[2] != "edge-dev2" {
		t.Fatalf("got devices %v, want [sdn edge-dev1 edge-dev2]", names)
	}
	if !s.Devices[0].IsSdn || s.Devices[0].Image != "lfedge/evetest-sdn:abc" ||
		!s.Devices[1].Created || s.Devices[1].Cpus != 4 || s.Devices[2].Created {
		t.Errorf("unexpected devices: %v", s.Devices)
	}
}

// TestGetStatusListsClosingSessions covers that a session whose devices are
// still being torn down stays visible after it is removed from b.sessions.
func TestGetStatusListsClosingSessions(t *testing.T) {
	b := newStatusTestBroker()
	closing := &session{clientID: "c1"}
	closing.beginOperation(closeOperation)
	b.closingSessions["c1"] = closing
	b.sessions["c2"] = &session{clientID: "c2"}

	resp := getStatus(t, b)
	if len(resp.Sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(resp.Sessions))
	}
	for _, s := range resp.Sessions {
		wantOp := map[string]string{"c1": closeOperation, "c2": ""}[s.ClientId]
		if s.Operation != wantOp {
			t.Errorf("session %s has operation %q, want %q", s.ClientId, s.Operation, wantOp)
		}
	}
}

func TestEVEImageDescription(t *testing.T) {
	cases := []struct {
		req  *api.BuildImageRequest
		want string
	}{
		{&api.BuildImageRequest{}, "lfedge/eve:1-kvm-amd64"},
		{&api.BuildImageRequest{MakeInstaller: true}, "lfedge/eve:1-kvm-amd64 (installer)"},
		{&api.BuildImageRequest{NetworkBoot: true}, "lfedge/eve:1-kvm-amd64 (network boot)"},
		{&api.BuildImageRequest{LiveImage: &api.LiveImageRef{Version: "0.0.0-dev"}},
			"local live image 0.0.0-dev"},
		{&api.BuildImageRequest{LiveImage: &api.LiveImageRef{Sha256: "0123456789abcdef"}},
			"local live image 0123456789ab"},
	}
	for _, c := range cases {
		if got := eveImageDescription(c.req, "lfedge/eve:1-kvm-amd64"); got != c.want {
			t.Errorf("eveImageDescription(%v) = %q, want %q", c.req, got, c.want)
		}
	}
}

// TestGetStatusHostStatus covers that a provider failing or hanging to report
// its host fills host_error, and never fails or blocks GetStatus.
func TestGetStatusHostStatus(t *testing.T) {
	b := newStatusTestBroker()
	if resp := getStatus(t, b); resp.Host.GetName() != "pve1" || resp.HostError != "" {
		t.Errorf("got host %v, error %q; want pve1 and no error", resp.Host, resp.HostError)
	}

	b.provider = &fakeHostProvider{err: errors.New("API unreachable")}
	if resp := getStatus(t, b); resp.Host != nil || resp.HostError != "API unreachable" {
		t.Errorf("got host %v, error %q; want no host and the provider error", resp.Host, resp.HostError)
	}

	saved := hostStatusTimeout
	hostStatusTimeout = 50 * time.Millisecond
	defer func() { hostStatusTimeout = saved }()
	block := make(chan struct{})
	defer close(block)
	b.provider = &fakeHostProvider{block: block}
	start := time.Now()
	resp := getStatus(t, b)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("GetStatus took %v with a hung provider", elapsed)
	}
	if resp.Host != nil || !strings.Contains(resp.HostError, "did not report its host in time") {
		t.Errorf("got host %v, error %q; want a timeout error", resp.Host, resp.HostError)
	}
}

// TestBusyReasons covers what keeps the broker from being upgraded: sessions,
// including closing ones, and claimed image uploads, also before the upload
// starts.
func TestBusyReasons(t *testing.T) {
	b := newStatusTestBroker()
	if reasons := busyReasons(getStatus(t, b)); len(reasons) != 0 {
		t.Fatalf("an idle broker is busy: %v", reasons)
	}

	closing := &session{clientID: "c1"}
	closing.beginOperation(closeOperation)
	b.closingSessions["c1"] = closing
	b.sessions["c2"] = &session{clientID: "c2"}
	b.imageClaims.claim("lfedge/eve:1-kvm-amd64")
	uploading, _ := b.imageClaims.claim("lfedge/eve:1-k-amd64")
	b.imageClaims.started("lfedge/eve:1-k-amd64", uploading, 0)

	got := strings.Join(busyReasons(getStatus(t, b)), "\n")
	for _, want := range []string{
		"session of client c1 is being closed",
		"client c2 is connected",
		"a client claimed the upload of image lfedge/eve:1-kvm-amd64",
		"image lfedge/eve:1-k-amd64 is being uploaded",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("busy reasons lack %q:\n%s", want, got)
		}
	}
}
