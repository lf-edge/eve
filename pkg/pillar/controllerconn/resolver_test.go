// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"go.uber.org/goleak"
)

func createNetmonitorMockInterface() []netmonitor.MockInterface {
	mockInterface := []netmonitor.MockInterface{
		{
			Attrs: netmonitor.IfAttrs{
				IfIndex: 0,
				IfName:  "if0",
			},
			IPAddrs: []*net.IPNet{
				{
					IP:   []byte{192, 168, 0, 1},
					Mask: []byte{255, 255, 255, 0},
				},
				{
					IP:   []byte{192, 168, 0, 2},
					Mask: []byte{255, 255, 255, 0},
				},
			},
			HwAddr: []byte{},
			DNS: netmonitor.DNSInfo{
				ResolvConfPath: "/etc/resolv.conf",
				Domains:        []string{},
				DNSServers: []net.IP{
					{208, 67, 220, 220},
					{208, 67, 222, 222},
					{141, 1, 1, 1},
					{1, 1, 1, 1},
					{9, 9, 9, 9},
				},
			},
		},
		{
			Attrs: netmonitor.IfAttrs{
				IfIndex: 1,
				IfName:  "if1",
			},
			IPAddrs: []*net.IPNet{
				{
					IP:   []byte{192, 168, 1, 1},
					Mask: []byte{255, 255, 255, 0},
				},
				{
					IP:   []byte{192, 168, 1, 2},
					Mask: []byte{255, 255, 255, 0},
				},
			},
			HwAddr: []byte{},
			DNS: netmonitor.DNSInfo{
				ResolvConfPath: "/etc/resolv.conf",
				Domains:        []string{},
				DNSServers: []net.IP{
					{1, 0, 0, 1},
					{8, 8, 8, 8},
				},
			},
		},
		{
			Attrs: netmonitor.IfAttrs{
				IfIndex: 2,
				IfName:  "ExpensiveIf",
			},
			IPAddrs: []*net.IPNet{{
				IP:   []byte{6, 6, 6, 6},
				Mask: []byte{255, 255, 255, 0},
			}},
			HwAddr: []byte{},
			DNS: netmonitor.DNSInfo{
				ResolvConfPath: "/etc/resolv.conf",
				Domains:        []string{},
				DNSServers: []net.IP{
					{0, 6, 6, 6},
					{0, 7, 7, 7},
				},
			},
		},
	}
	return mockInterface
}

func createDeviceNetworkStatus() types.DeviceNetworkStatus {
	mockInterface := createNetmonitorMockInterface()
	deviceNetworkStatusPorts := make([]types.NetworkPortStatus, len(mockInterface))
	for i := range deviceNetworkStatusPorts {
		deviceNetworkStatusPorts[i].IfName = mockInterface[i].Attrs.IfName
		deviceNetworkStatusPorts[i].IsL3Port = true
		deviceNetworkStatusPorts[i].DNSServers = mockInterface[i].DNS.DNSServers
		addrInfos := make([]types.AddrInfo, len(mockInterface[i].IPAddrs))
		for j := range mockInterface[i].IPAddrs {
			addrInfos[j] = types.AddrInfo{
				Addr: mockInterface[i].IPAddrs[j].IP,
			}
		}

		deviceNetworkStatusPorts[i].AddrInfoList = addrInfos
	}

	deviceNetworkStatus := types.DeviceNetworkStatus{
		CurrentIndex: 0,
		Ports:        deviceNetworkStatusPorts,
	}
	return deviceNetworkStatus
}

func TestDnsResolve(t *testing.T) {
	t.Parallel()

	testHost := "255.255.255.255.nip.io"
	expectedIP := net.IP{255, 255, 255, 255}
	if testing.Short() {
		t.Skipf(
			"Skipping as connecting to the internet would take too much time and short tests are enabled",
		)
	}

	res, errs := controllerconn.ResolveWithSrcIP(testHost, net.IP{1, 1, 1, 1}, net.IP{0, 0, 0, 0})
	if errs != nil {
		panic(errs)
	}
	if res == nil {
		t.Skipf(
			"could not resolve, skipping as probably the tests don't have internet connection of %s is down",
			testHost,
		)
	}
	if !res[0].IP.Equal(expectedIP) {
		t.Fatalf(
			"resolving returned wrong IP address %+v, but should have been %+v",
			res,
			expectedIP,
		)
	}
}

func TestDnsResolveTimeout(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skipf("Skipping as timing out would take too much time and short tests are enabled")
	}
	exampleCom := net.IP{93, 184, 216, 34} // example.com, they drop packets on 53/udp
	res, _ := controllerconn.ResolveWithSrcIP("www.google.com", exampleCom, net.IP{0, 0, 0, 0})
	if res != nil {
		t.Fatalf("resolving with dns server %+v should fail, but succeeded: %+v", exampleCom, res)
	}
}

func TestResolveWithPortsLambda(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreAnyFunction("go.opencensus.io/stats/view.(*worker).start"), goleak.IgnoreCurrent())

	expectedIP := net.IP{1, 2, 3, 4}

	var first atomic.Bool
	first.Store(true)
	var countCalls atomic.Int32
	resolverFunc := func(domain string, dnsServer net.IP, srcIP net.IP) ([]controllerconn.DNSResponse, error) {
		countCalls.Add(1)
		if !first.Swap(false) {
			time.Sleep(1 * time.Second)
			return []controllerconn.DNSResponse{}, nil
		}
		return []controllerconn.DNSResponse{
			{
				IP:  expectedIP,
				TTL: 3600,
			},
		}, nil
	}

	deviceNetworkStatus := createDeviceNetworkStatus()
	res, err := controllerconn.ResolveWithPortsLambda(
		"example.com",
		deviceNetworkStatus,
		resolverFunc,
	)
	if err != nil {
		panic(err)
	}
	if !res[0].IP.Equal(expectedIP) {
		t.Errorf("wrong result, expected IP 1.2.3.4, but got: %+v", res)
	}
	if countCalls.Load() > controllerconn.DNSMaxParallelRequests+1 {
		// checking for +1 as the first call immediately returns
		t.Errorf(
			"more calls to resolverFunc than dnsMaxParallelRequests+1, but first call should already succeed",
		)
	}
}

func TestResolveWithPortsLambdaWithErrors(t *testing.T) {
	t.Parallel()

	expectedIP := net.IP{1, 2, 3, 4}
	resolverFunc := func(domain string, dnsServer net.IP, srcIP net.IP) ([]controllerconn.DNSResponse, error) {
		if srcIP.Equal(net.IP{192, 168, 0, 1}) && domain == "example.com" {
			return []controllerconn.DNSResponse{
				{
					IP:  expectedIP,
					TTL: 3600,
				},
			}, nil
		}
		return nil, errors.New("resolver failed")
	}

	deviceNetworkStatus := createDeviceNetworkStatus()
	res, err := controllerconn.ResolveWithPortsLambda(
		"example.com",
		deviceNetworkStatus,
		resolverFunc,
	)
	if err != nil {
		t.Errorf("expected no error, but got: %+v", err)
	}
	if !res[0].IP.Equal(expectedIP) {
		t.Errorf("expected IP 1.2.3.4, but got: %+v", res)
	}

	res, err = controllerconn.ResolveWithPortsLambda(
		"resolver-should-fail.com",
		deviceNetworkStatus,
		resolverFunc,
	)
	if err == nil {
		t.Error("expected error, but got nil")
	}
	if len(res) > 0 {
		t.Errorf("expected empty response, but got: %+v", res)
	}
}

func TestResolveCacheWrap(t *testing.T) {
	t.Parallel()
	called := 0

	cw := controllerconn.ResolveCacheWrap(func(domain string, dnsServerIP, srcIP net.IP) ([]controllerconn.DNSResponse, error) {
		called++
		return []controllerconn.DNSResponse{
			{
				IP:  []byte{127, 0, 0, 1},
				TTL: 2,
			},
		}, nil
	})

	cw("localhost", net.IP{8, 8, 8, 8}, net.IP{0, 0, 0, 0})

	if called != 1 {
		t.Fatalf("resolver func should have been called once, but called=%d", called)
	}

	cw("localhost", net.IP{8, 8, 8, 8}, net.IP{0, 0, 0, 0})

	if called != 1 {
		t.Fatalf("resolver func should have been called once, but called=%d", called)
	}

	time.Sleep(5 * time.Second)
	cw("localhost", net.IP{8, 8, 8, 8}, net.IP{0, 0, 0, 0})
	if called != 2 {
		t.Fatalf("resolver func should have been called twice, but called=%d", called)
	}

	// Check different srcIPs
	called = 0
	cw("localhost1", net.IP{8, 8, 8, 8}, net.IP{0, 0, 0, 0})
	cw("localhost1", net.IP{8, 8, 8, 8}, net.IP{1, 2, 3, 4})
	if called != 2 {
		t.Fatalf("resolver func should have been called twice because different src IPs, but called=%d", called)
	}
}

func FuzzResolveWithSrcIP(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		domain string,
		dnsServer string,
		src string,
	) {
		dnsServerIP := net.ParseIP(dnsServer)
		srcIP := net.ParseIP(src)
		controllerconn.ResolveWithSrcIPWithTimeout(domain, dnsServerIP, srcIP, 3*time.Second)
	})
}
