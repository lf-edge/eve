// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func newHandlerCtx(sender *fakeControllerSender) *clientContext {
	return &clientContext{
		sender:              sender,
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
	}
}

func TestHandleDNSDelete_ResetsState(t *testing.T) {
	ctx := newHandlerCtx(&fakeControllerSender{})
	ctx.deviceNetworkStatus = &types.DeviceNetworkStatus{
		State: types.DPCStateSuccess,
	}
	ctx.usableAddressCount = 5
	ctx.networkState = types.DPCStateSuccess

	handleDNSDelete(ctx, "global", types.DeviceNetworkStatus{})

	if ctx.deviceNetworkStatus.State != types.DPCStateNone {
		t.Errorf("state = %v, want zero (DPCStateNone)", ctx.deviceNetworkStatus.State)
	}
	if ctx.usableAddressCount != 0 {
		t.Errorf("usableAddressCount = %d, want 0", ctx.usableAddressCount)
	}
}

func TestHandleDNSDelete_IgnoresNonGlobalKey(t *testing.T) {
	ctx := newHandlerCtx(&fakeControllerSender{})
	ctx.deviceNetworkStatus = &types.DeviceNetworkStatus{State: types.DPCStateSuccess}
	ctx.usableAddressCount = 5

	handleDNSDelete(ctx, "other-key", types.DeviceNetworkStatus{})

	if ctx.deviceNetworkStatus.State != types.DPCStateSuccess {
		t.Error("state was reset for a non-global key")
	}
	if ctx.usableAddressCount != 5 {
		t.Error("usableAddressCount was reset for a non-global key")
	}
}

// dnsStatusWithAddrs builds a minimal DeviceNetworkStatus with the given
// state and a single port carrying the provided non-link-local IPv4 addrs.
// Each addr counts as one usable address.
func dnsStatusWithAddrs(state types.DPCState, addrs ...string) types.DeviceNetworkStatus {
	addrInfos := make([]types.AddrInfo, 0, len(addrs))
	for _, a := range addrs {
		addrInfos = append(addrInfos, types.AddrInfo{Addr: net.ParseIP(a)})
	}
	return types.DeviceNetworkStatus{
		State: state,
		Ports: []types.NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, IsL3Port: true, AddrInfoList: addrInfos},
		},
	}
}

func TestHandleDNSImpl_StateAndAddressTransitions(t *testing.T) {
	ctx := newHandlerCtx(&fakeControllerSender{})

	// First update: no addresses, state PCIWait.
	first := dnsStatusWithAddrs(types.DPCStatePCIWait)
	handleDNSImpl(ctx, "global", first)
	if ctx.networkState != types.DPCStatePCIWait {
		t.Errorf("networkState = %v, want PCIWait", ctx.networkState)
	}
	if ctx.usableAddressCount != 0 {
		t.Errorf("usableAddressCount = %d, want 0", ctx.usableAddressCount)
	}

	// Second update: same state, gain one address.
	second := dnsStatusWithAddrs(types.DPCStatePCIWait, "10.0.0.1")
	handleDNSImpl(ctx, "global", second)
	if ctx.usableAddressCount != 1 {
		t.Errorf("usableAddressCount = %d, want 1", ctx.usableAddressCount)
	}

	// Third update: state advances to Success, same one address.
	third := dnsStatusWithAddrs(types.DPCStateSuccess, "10.0.0.1")
	handleDNSImpl(ctx, "global", third)
	if ctx.networkState != types.DPCStateSuccess {
		t.Errorf("networkState = %v, want Success", ctx.networkState)
	}
	if ctx.usableAddressCount != 1 {
		t.Errorf("usableAddressCount = %d, want 1 unchanged", ctx.usableAddressCount)
	}

	// Identical update returns early via MostlyEqual.
	handleDNSImpl(ctx, "global", third)
	if ctx.networkState != types.DPCStateSuccess {
		t.Errorf("identical update changed state")
	}
}

func TestHandleDNSImpl_IgnoresNonGlobalKey(t *testing.T) {
	ctx := newHandlerCtx(&fakeControllerSender{})
	original := *ctx.deviceNetworkStatus
	handleDNSImpl(ctx, "other-key", dnsStatusWithAddrs(types.DPCStateSuccess, "10.0.0.1"))
	if ctx.deviceNetworkStatus.State != original.State {
		t.Error("non-global key altered state")
	}
}

func TestHandleDNSImpl_ProxyCertsPropagatedToTLSConfigs(t *testing.T) {
	pool := x509.NewCertPool()
	sender := &fakeControllerSender{
		updateProxyCert: true,
		proxyCertPool:   pool,
	}
	ctx := newHandlerCtx(sender)
	ctx.onboardTLSConfig = &tls.Config{}
	ctx.devtlsConfig = &tls.Config{}

	handleDNSImpl(ctx, "global", dnsStatusWithAddrs(types.DPCStateSuccess, "10.0.0.1"))

	if ctx.onboardTLSConfig.RootCAs != pool {
		t.Error("onboardTLSConfig.RootCAs not updated from sender")
	}
	if ctx.devtlsConfig.RootCAs != pool {
		t.Error("devtlsConfig.RootCAs not updated from sender")
	}
	if sender.dns == nil {
		t.Error("sender.SetDeviceNetworkStatus not called")
	}
}

func TestHandleDNSCreateAndModify_DelegateToImpl(t *testing.T) {
	ctx := newHandlerCtx(&fakeControllerSender{})
	handleDNSCreate(ctx, "global", dnsStatusWithAddrs(types.DPCStateSuccess, "10.0.0.1"))
	if ctx.networkState != types.DPCStateSuccess {
		t.Errorf("after Create networkState = %v, want Success", ctx.networkState)
	}
	handleDNSModify(ctx, "global", dnsStatusWithAddrs(types.DPCStateFailWithIPAndDNS, "10.0.0.1"), nil)
	if ctx.networkState != types.DPCStateFailWithIPAndDNS {
		t.Errorf("after Modify networkState = %v, want FailWithIPAndDNS", ctx.networkState)
	}
}
