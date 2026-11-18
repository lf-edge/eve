// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// hostStatusTimeout is a variable for tests.
var hostStatusTimeout = 10 * time.Second

// sessionStatus is what GetStatus reports about a session. It is guarded by
// session.statusMu, not session.mutex, which device operations hold for
// minutes.
type sessionStatus struct {
	peerAddress        string
	clientInfo         *api.ClientInfo
	connectedAt        time.Time
	lastKeepAlive      time.Time
	currentTest        string
	operation          string
	operationStartedAt time.Time
	devices            []*api.DeviceStatus
}

// beginOperation records a long-running device operation for GetStatus. Call
// it with s.mutex held and defer the returned function before s.mutex is
// released: it clears the operation and publishes the session's devices as
// the operation left them.
func (s *session) beginOperation(name string) (end func()) {
	s.statusMu.Lock()
	s.status.operation = name
	s.status.operationStartedAt = time.Now()
	s.statusMu.Unlock()
	return func() {
		devices := s.deviceStatuses()
		s.statusMu.Lock()
		s.status.operation = ""
		s.status.operationStartedAt = time.Time{}
		s.status.devices = devices
		s.statusMu.Unlock()
	}
}

// recordKeepAlive records a KeepAlivePing for GetStatus.
func (s *session) recordKeepAlive(ping *api.KeepAlivePing) {
	s.statusMu.Lock()
	s.status.lastKeepAlive = time.Now()
	s.status.currentTest = ping.GetCurrentTest()
	s.statusMu.Unlock()
}

// deviceStatuses describes the session's devices, the SDN device first.
// Requires s.mutex.
func (s *session) deviceStatuses() []*api.DeviceStatus {
	var devices []*api.DeviceStatus
	if s.sdnDevice != nil {
		devices = append(devices, s.sdnDevice.status(true))
	}
	names := make([]string, 0, len(s.eveDevices))
	for name := range s.eveDevices {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		devices = append(devices, s.eveDevices[name].status(false))
	}
	return devices
}

func (d *device) status(isSDN bool) *api.DeviceStatus {
	return &api.DeviceStatus{
		Name:        d.deviceName,
		IsSdn:       isSDN,
		VmName:      d.providerDevName,
		Created:     d.created,
		Arch:        d.Arch,
		Cpus:        uint32(d.CPUs),
		MemoryBytes: d.MemoryBytes,
		Image:       d.image,
	}
}

// eveImageDescription describes the image an EVE device boots, for GetStatus.
func eveImageDescription(req *api.BuildImageRequest, dockerImageName string) string {
	if live := req.GetLiveImage(); live != nil {
		id := live.GetVersion()
		if id == "" {
			id = live.GetSha256()
			if len(id) > 12 {
				id = id[:12]
			}
		}
		return fmt.Sprintf("local live image %s", id)
	}
	switch {
	case req.GetNetworkBoot():
		return dockerImageName + " (network boot)"
	case req.GetMakeInstaller():
		return dockerImageName + " (installer)"
	}
	return dockerImageName
}

func (s *session) statusProto() *api.ClientSessionStatus {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	st := &api.ClientSessionStatus{
		ClientId:    s.clientID,
		PeerAddress: s.status.peerAddress,
		ConnectedAt: timestamppb.New(s.status.connectedAt),
		CurrentTest: s.status.currentTest,
		Operation:   s.status.operation,
		Devices:     make([]*api.DeviceStatus, 0, len(s.status.devices)),
	}
	if s.status.clientInfo != nil {
		st.ClientInfo = proto.Clone(s.status.clientInfo).(*api.ClientInfo)
	}
	if !s.status.lastKeepAlive.IsZero() {
		st.LastKeepAlive = timestamppb.New(s.status.lastKeepAlive)
	}
	if !s.status.operationStartedAt.IsZero() {
		st.OperationStartedAt = timestamppb.New(s.status.operationStartedAt)
	}
	for _, d := range s.status.devices {
		st.Devices = append(st.Devices, proto.Clone(d).(*api.DeviceStatus))
	}
	return st
}

// GetStatus reports the broker and all its client sessions, including those
// being closed, whose devices are still being torn down.
func (b *broker) GetStatus(
	ctx context.Context, req *api.GetStatusRequest) (resp *api.GetStatusResponse, err error) {
	b.mutex.Lock()
	sessions := make([]*session, 0, len(b.sessions)+len(b.closingSessions))
	for _, s := range b.sessions {
		sessions = append(sessions, s)
	}
	for _, s := range b.closingSessions {
		sessions = append(sessions, s)
	}
	b.mutex.Unlock()

	resp = &api.GetStatusResponse{
		BrokerVersion: version,
		Provider:      b.providerName,
		StartedAt:     timestamppb.New(b.startedAt),
		MaxClients:    int32(b.maxClients),
	}
	for _, s := range sessions {
		resp.Sessions = append(resp.Sessions, s.statusProto())
	}
	resp.ImageUploads = b.imageClaims.status()
	resp.Host, err = b.hostStatus(ctx)
	if err != nil {
		resp.HostError = err.Error()
	}
	sort.Slice(resp.Sessions, func(i, j int) bool {
		ti, tj := resp.Sessions[i].ConnectedAt.AsTime(), resp.Sessions[j].ConnectedAt.AsTime()
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return resp.Sessions[i].ClientId < resp.Sessions[j].ClientId
	})
	return resp, nil
}

// hostStatus asks the provider about its host, giving up after
// hostStatusTimeout: a provider may hold a lock across slow device work, which
// must not hang GetStatus.
func (b *broker) hostStatus(ctx context.Context) (*api.HostStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, hostStatusTimeout)
	defer cancel()
	type result struct {
		st  *api.HostStatus
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		st, err := b.provider.HostStatus(ctx)
		resCh <- result{st, err}
	}()
	select {
	case res := <-resCh:
		return res.st, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("the %s provider did not report its host in time: %w",
			b.providerName, ctx.Err())
	}
}
