// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var logger *logrus.Logger
var logObj *base.LogObject

func makeControllerClient(t *testing.T, dns *types.DeviceNetworkStatus,
	metrics *controllerconn.AgentMetrics) *controllerconn.Client {
	logger = logrus.StandardLogger()
	logger.SetLevel(logrus.TraceLevel)
	logObj = base.NewSourceLogObject(logger, "unittest", 1234)
	devUUID, err := uuid.NewV4()
	if err != nil {
		t.Errorf("uuid.NewV4 failed: %v", err)
	}

	return controllerconn.NewClient(logObj, controllerconn.ClientOptions{
		AgentName:           "unittest",
		NetworkMonitor:      &netmonitor.LinuxNetworkMonitor{Log: logObj, DisableWatcher: true},
		DeviceNetworkStatus: dns,
		AgentMetrics:        metrics,
		NetworkSendTimeout:  10 * time.Second,
		NetworkDialTimeout:  5 * time.Second,
		DevUUID:             devUUID,
		DevSerial:           "device-serial",
		DevSoftSerial:       "device-soft-serial",
		NetTraceOpts: []nettrace.TraceOpt{
			&nettrace.WithLogging{
				CustomLogger: &base.LogrusWrapper{Log: logObj},
			},
			&nettrace.WithSockTrace{},
			&nettrace.WithDNSQueryTrace{},
			&nettrace.WithHTTPReqTrace{
				HeaderFields: nettrace.HdrFieldsOptWithValues,
			},
		},
		NoLedManager: true,
	})
}

// getDeviceNetworkStatus identifies the default interface, gathers its attributes,
// and returns a populated DeviceNetworkStatus.
// If no default route or no DNS servers, it skips the test.
func getDeviceNetworkStatus(t *testing.T) types.DeviceNetworkStatus {
	var dns types.DeviceNetworkStatus

	err := checkInternetConnectivity()
	if err != nil {
		t.Skipf("Skipping test: no Internet connectivity "+
			"(GET https://www.google.com failed: %v)", err)
	}

	ifName, link, gw, err := getLinkForDefaultRoute()
	if err != nil {
		t.Skipf("Skipping test: no default route found (%v)", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Skipf("Skipping test: failed to list addresses for %s: %v", ifName, err)
	}

	addrInfoList := []types.AddrInfo{}
	var subnet net.IPNet
	for _, addr := range addrs {
		if addr.IP == nil || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		addrInfoList = append(addrInfoList, types.AddrInfo{
			Addr: addr.IP,
		})
		if subnet.IP == nil {
			subnet = *addr.IPNet
		}
	}

	if len(addrs) == 0 {
		t.Skip("Skipping test: no suitable IP address available")
	}

	dnsServers, err := getDNSServers()
	if err != nil || len(dnsServers) == 0 {
		t.Skipf("Skipping test: no DNS servers found or error: %v", err)
	}

	portStatus := types.NetworkPortStatus{
		IfName:         ifName,
		Phylabel:       ifName,
		Logicallabel:   ifName,
		IsMgmt:         true,
		IsL3Port:       true,
		Cost:           0,
		Subnet:         subnet,
		DNSServers:     dnsServers,
		AddrInfoList:   addrInfoList,
		Up:             link.Attrs().Flags&net.FlagUp != 0,
		MacAddr:        link.Attrs().HardwareAddr,
		DefaultRouters: []net.IP{gw},
		MTU:            uint16(link.Attrs().MTU),
	}

	dns.Ports = append(dns.Ports, portStatus)
	return dns
}

// checkInternetConnectivity does a quick GET to https://www.google.com.
func checkInternetConnectivity() error {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://www.google.com")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// getLinkForDefaultRoute returns: interface name, link, and GW IP for default route.
func getLinkForDefaultRoute() (string, netlink.Link, net.IP, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return "", nil, nil, err
	}
	for _, r := range routes {
		if (r.Dst == nil || r.Dst.IP.IsUnspecified()) && r.Gw != nil {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				return "", nil, nil, err
			}
			return link.Attrs().Name, link, r.Gw, nil
		}
	}
	return "", nil, nil, os.ErrNotExist
}

// getDNSServers parses /etc/resolv.conf and returns DNS server IPs.
func getDNSServers() ([]net.IP, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var servers []net.IP
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := net.ParseIP(fields[1])
				if ip != nil {
					servers = append(servers, ip)
				}
			}
		}
	}
	return servers, nil
}

func getUnusedInterfaceName() string {
	ifaces, err := net.Interfaces()
	existingNames := make(map[string]struct{})
	if err == nil {
		for _, iface := range ifaces {
			existingNames[iface.Name] = struct{}{}
		}
	}
	// Try fake0, fake1, ..., until unused
	for i := 0; ; i++ {
		name := fmt.Sprintf("fake%d", i)
		if _, exists := existingNames[name]; !exists {
			return name
		}
	}
}

func TestSendOnIntf(test *testing.T) {
	dns := getDeviceNetworkStatus(test)
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rv, err := client.SendOnIntf(ctx, "https://google.com", dns.Ports[0].IfName, nil,
		controllerconn.RequestOptions{
			AllowProxy:       false,
			UseOnboard:       false,
			SuppressLogs:     false,
			WithNetTracing:   false,
			DryRun:           false,
			BailOnHTTPErr:    false,
			Accept4xxErrors:  true,
			Iteration:        0,
			AllowLoopbackDNS: true,
		})

	t := NewGomegaWithT(test)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.RespContents).ToNot(BeEmpty())
	t.Expect(rv.Status).To(Equal(types.SenderStatusNone))

	metrics := types.MetricsMap{}
	agentMetrics.AddInto(nil, metrics)
	t.Expect(metrics).To(HaveKey(dns.Ports[0].IfName))
	intfMetrics := metrics[dns.Ports[0].IfName]
	t.Expect(intfMetrics.SuccessCount).To(BeEquivalentTo(1))
	t.Expect(intfMetrics.FailureCount).To(BeZero())
	t.Expect(intfMetrics.LastSuccess.IsZero()).To(BeFalse())
	t.Expect(intfMetrics.LastFailure.IsZero()).To(BeTrue())
	t.Expect(intfMetrics.AuthFailCount).To(BeZero())
	urlCounters := intfMetrics.URLCounters
	t.Expect(urlCounters).To(HaveKey("https://google.com"))
	counters := urlCounters["https://google.com"]
	t.Expect(counters.SentMsgCount).To(BeEquivalentTo(1))
	t.Expect(counters.RecvMsgCount).To(BeEquivalentTo(1))
	t.Expect(counters.TryMsgCount).To(BeZero())
}

func TestSendOnIntf_NoUsablePorts(test *testing.T) {
	// Create DeviceNetworkStatus with only fake, unusable ports
	var dns types.DeviceNetworkStatus
	for i := 0; i < 2; i++ {
		unusedName := getUnusedInterfaceName()
		fakePort := types.NetworkPortStatus{
			IfName:         unusedName,
			Phylabel:       unusedName,
			Logicallabel:   unusedName,
			IsMgmt:         true,
			IsL3Port:       true,
			Up:             false,
			AddrInfoList:   []types.AddrInfo{},
			DefaultRouters: []net.IP{},
		}
		dns.Ports = append(dns.Ports, fakePort)
	}
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rv, err := client.SendOnIntf(ctx, "https://google.com", dns.Ports[0].IfName, nil,
		controllerconn.RequestOptions{
			AllowProxy:       false,
			UseOnboard:       false,
			SuppressLogs:     false,
			WithNetTracing:   false,
			DryRun:           false,
			BailOnHTTPErr:    false,
			Accept4xxErrors:  true,
			Iteration:        0,
			AllowLoopbackDNS: true,
		})

	t := NewGomegaWithT(test)
	t.Expect(err).To(HaveOccurred())
	t.Expect(err.Error()).To(
		Equal("link not found for interface " + dns.Ports[0].IfName))
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.RespContents).To(BeEmpty())
	t.Expect(rv.Status).To(Equal(types.SenderStatusNone))

	metrics := types.MetricsMap{}
	agentMetrics.AddInto(nil, metrics)
	t.Expect(metrics).To(HaveKey(dns.Ports[0].IfName))
	intfMetrics := metrics[dns.Ports[0].IfName]
	t.Expect(intfMetrics.SuccessCount).To(BeZero())
	t.Expect(intfMetrics.FailureCount).To(BeEquivalentTo(1))
	t.Expect(intfMetrics.LastSuccess.IsZero()).To(BeTrue())
	t.Expect(intfMetrics.LastFailure.IsZero()).To(BeFalse())
	t.Expect(intfMetrics.AuthFailCount).To(BeZero())
	urlCounters := intfMetrics.URLCounters
	t.Expect(urlCounters).To(HaveKey("https://google.com"))
	counters := urlCounters["https://google.com"]
	t.Expect(counters.SentMsgCount).To(BeZero())
	t.Expect(counters.RecvMsgCount).To(BeZero())
	t.Expect(counters.TryMsgCount).To(BeEquivalentTo(1))
}

func TestSendOnIntf_WithNetTrace(test *testing.T) {
	dns := getDeviceNetworkStatus(test)
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rv, err := client.SendOnIntf(ctx, "https://google.com", dns.Ports[0].IfName, nil,
		controllerconn.RequestOptions{
			AllowProxy:       false,
			UseOnboard:       false,
			SuppressLogs:     false,
			WithNetTracing:   true,
			DryRun:           false,
			BailOnHTTPErr:    false,
			Accept4xxErrors:  true,
			Iteration:        0,
			AllowLoopbackDNS: true,
		})

	t := NewGomegaWithT(test)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(rv.TracedReqs).ToNot(BeEmpty())
	t.Expect(rv.TracedReqs[0].PacketCaptures).To(BeEmpty())
	t.Expect(rv.RespContents).ToNot(BeEmpty())
	t.Expect(rv.Status).To(Equal(types.SenderStatusNone))
}

func TestSendOnAllIntf(test *testing.T) {
	dns := getDeviceNetworkStatus(test)

	// Add a fake port with no IPs (should be skipped by SendOnAllIntf)
	unusedName := getUnusedInterfaceName()
	fakePort := types.NetworkPortStatus{
		IfName:         unusedName,
		Phylabel:       unusedName,
		Logicallabel:   unusedName,
		IsMgmt:         true,
		IsL3Port:       true,
		Up:             false,
		AddrInfoList:   []types.AddrInfo{},
		DefaultRouters: []net.IP{},
	}
	dns.Ports = append(dns.Ports, fakePort)
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rv, err := client.SendOnAllIntf(ctx, "https://google.com", nil,
		controllerconn.RequestOptions{
			AllowProxy:      false,
			UseOnboard:      false,
			SuppressLogs:    false,
			WithNetTracing:  false,
			DryRun:          false,
			BailOnHTTPErr:   false,
			Accept4xxErrors: true,
			// Let's try the fake port first - should be skipped.
			Iteration:        1,
			AllowLoopbackDNS: true,
		})

	t := NewGomegaWithT(test)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.RespContents).ToNot(BeEmpty())
	t.Expect(rv.Status).To(Equal(types.SenderStatusNone))
}

func TestSendOnAllIntf_NoUsablePorts(test *testing.T) {
	// Create DeviceNetworkStatus with only fake, unusable ports
	var dns types.DeviceNetworkStatus
	for i := 0; i < 2; i++ {
		unusedName := getUnusedInterfaceName()
		fakePort := types.NetworkPortStatus{
			IfName:         unusedName,
			Phylabel:       unusedName,
			Logicallabel:   unusedName,
			IsMgmt:         true,
			IsL3Port:       true,
			Up:             false,
			AddrInfoList:   []types.AddrInfo{},
			DefaultRouters: []net.IP{},
		}
		dns.Ports = append(dns.Ports, fakePort)
	}
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rv, err := client.SendOnAllIntf(ctx, "https://google.com", nil,
		controllerconn.RequestOptions{
			AllowProxy:       false,
			UseOnboard:       false,
			SuppressLogs:     false,
			WithNetTracing:   false,
			DryRun:           false,
			BailOnHTTPErr:    false,
			Accept4xxErrors:  true,
			Iteration:        0,
			AllowLoopbackDNS: true,
		})

	// We expect an error because no usable ports are present
	t := NewGomegaWithT(test)
	t.Expect(err).To(HaveOccurred())
	sendErr, isSendErr := err.(*controllerconn.SendError)
	t.Expect(isSendErr).To(BeTrue())
	t.Expect(sendErr.Err).ToNot(BeNil())
	t.Expect(sendErr.Attempts).To(HaveLen(2))
	t.Expect(sendErr.Attempts[0].IfName).To(Equal(dns.Ports[0].IfName))
	t.Expect(sendErr.Attempts[0].SourceAddr).To(BeNil())
	t.Expect(sendErr.Attempts[0].Err.Error()).To(
		Equal("link not found for interface " + dns.Ports[0].IfName))
	t.Expect(sendErr.Attempts[1].IfName).To(Equal(dns.Ports[1].IfName))
	t.Expect(sendErr.Attempts[1].SourceAddr).To(BeNil())
	t.Expect(sendErr.Attempts[1].Err.Error()).To(
		Equal("link not found for interface " + dns.Ports[1].IfName))
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.RespContents).To(BeEmpty())
}

func TestVerifyAllIntf(test *testing.T) {
	dns := getDeviceNetworkStatus(test)

	// Add a fake port with no IPs. This will fail the verification but VerifyAllIntf
	// should continue with the real working interface and confirm that connectivity
	// is working.
	unusedName := getUnusedInterfaceName()
	fakePort := types.NetworkPortStatus{
		IfName:         unusedName,
		Phylabel:       unusedName,
		Logicallabel:   unusedName,
		IsMgmt:         true,
		IsL3Port:       true,
		Up:             false,
		AddrInfoList:   []types.AddrInfo{},
		DefaultRouters: []net.IP{},
	}
	dns.Ports = append(dns.Ports, fakePort)
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rv, err := client.VerifyAllIntf(ctx, "https://google.com", 1,
		controllerconn.RequestOptions{
			AllowProxy:     false,
			UseOnboard:     false,
			SuppressLogs:   false,
			WithNetTracing: false,
			DryRun:         false,
			BailOnHTTPErr:  false,
			// In this test we require HTTP success.
			// Accepted 4XX errors are covered by TestVerifyAllIntf_Accept4xx.
			Accept4xxErrors: false,
			// Let's try the fake port first, then continue verification with the proper
			// port next.
			Iteration:        1,
			AllowLoopbackDNS: true,
		})

	t := NewGomegaWithT(test)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.ControllerReachable).To(BeTrue()) // Cloud in this case is google.com
	t.Expect(rv.RemoteTempFailure).To(BeFalse())
}

func TestVerifyAllIntf_NoUsablePorts(test *testing.T) {
	// Create DeviceNetworkStatus with only fake, unusable ports
	var dns types.DeviceNetworkStatus
	for i := 0; i < 2; i++ {
		unusedName := getUnusedInterfaceName()
		fakePort := types.NetworkPortStatus{
			IfName:         unusedName,
			Phylabel:       unusedName,
			Logicallabel:   unusedName,
			IsMgmt:         true,
			IsL3Port:       true,
			Up:             false,
			AddrInfoList:   []types.AddrInfo{},
			DefaultRouters: []net.IP{},
		}
		dns.Ports = append(dns.Ports, fakePort)
	}
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rv, err := client.VerifyAllIntf(ctx, "https://google.com", 1,
		controllerconn.RequestOptions{
			AllowProxy:       false,
			UseOnboard:       false,
			SuppressLogs:     false,
			WithNetTracing:   false,
			DryRun:           false,
			BailOnHTTPErr:    false,
			Accept4xxErrors:  false,
			Iteration:        0,
			AllowLoopbackDNS: true,
		})

	// We expect an error because no usable ports are present
	t := NewGomegaWithT(test)
	t.Expect(err).To(HaveOccurred())
	sendErr, isSendErr := err.(*controllerconn.SendError)
	t.Expect(isSendErr).To(BeTrue())
	t.Expect(sendErr.Err).ToNot(BeNil())
	t.Expect(sendErr.Attempts).To(HaveLen(2))
	t.Expect(sendErr.Attempts[0].IfName).To(Equal(dns.Ports[0].IfName))
	t.Expect(sendErr.Attempts[0].SourceAddr).To(BeNil())
	t.Expect(sendErr.Attempts[0].Err.Error()).To(
		Equal("link not found for interface " + dns.Ports[0].IfName))
	t.Expect(sendErr.Attempts[1].IfName).To(Equal(dns.Ports[1].IfName))
	t.Expect(sendErr.Attempts[1].SourceAddr).To(BeNil())
	t.Expect(sendErr.Attempts[1].Err.Error()).To(
		Equal("link not found for interface " + dns.Ports[1].IfName))
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.ControllerReachable).To(BeFalse()) // Cloud in this case is google.com
	t.Expect(rv.RemoteTempFailure).To(BeFalse())
}

func TestVerifyAllIntf_Accept4xxErrors(test *testing.T) {
	dns := getDeviceNetworkStatus(test)

	// Add a fake port with no IPs. This will fail the verification but VerifyAllIntf
	// should continue with the real working interface and confirm that connectivity
	// is working (even though the remote endpoint returns 404).
	unusedName := getUnusedInterfaceName()
	fakePort := types.NetworkPortStatus{
		IfName:         unusedName,
		Phylabel:       unusedName,
		Logicallabel:   unusedName,
		IsMgmt:         true,
		IsL3Port:       true,
		Up:             false,
		AddrInfoList:   []types.AddrInfo{},
		DefaultRouters: []net.IP{},
	}
	dns.Ports = append(dns.Ports, fakePort)
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rv, err := client.VerifyAllIntf(ctx, "https://google.com/nonexistenturl", 1,
		controllerconn.RequestOptions{
			AllowProxy:     false,
			UseOnboard:     false,
			SuppressLogs:   false,
			WithNetTracing: false,
			DryRun:         false,
			BailOnHTTPErr:  false,
			// Consider connectivity successful even if the remote endpoint returns 404.
			Accept4xxErrors: true,
			// Let's try the fake port first, then continue verification with the proper
			// port next.
			Iteration:        1,
			AllowLoopbackDNS: true,
		})

	t := NewGomegaWithT(test)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(rv.TracedReqs).To(BeEmpty())
	t.Expect(rv.ControllerReachable).To(BeTrue()) // Cloud in this case is google.com
	t.Expect(rv.RemoteTempFailure).To(BeFalse())
}
