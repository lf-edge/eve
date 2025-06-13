// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntester

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cloudconn"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Hard-coded at 1 for now; at least one interface needs to work.
const requiredSuccessCount uint = 1

var nilUUID = uuid.UUID{} // used as a constant

// CloudConnectivityTester implements external connectivity testing using
// the "/api/v2/edgeDevice/ping" endpoint provided by the cloud controller.
type CloudConnectivityTester struct {
	// Exported attributes below should be injected.
	Log            *base.LogObject
	AgentName      string
	TestTimeout    time.Duration // can be changed in run-time
	Metrics        *cloudconn.AgentMetrics
	NetworkMonitor netmonitor.NetworkMonitor

	iteration     int
	prevTLSConfig *tls.Config
}

// TestConnectivity uses VerifyAllIntf from the cloudconn package, which
// tries to call the "ping" API of the controller.
func (t *CloudConnectivityTester) TestConnectivity(dns types.DeviceNetworkStatus,
	withNetTrace bool) (types.IntfStatusMap, []netdump.TracedNetRequest, error) {

	t.iteration++
	intfStatusMap := *types.NewIntfStatusMap()
	t.Log.Tracef("TestConnectivity() requiredSuccessCount %d, iteration %d",
		requiredSuccessCount, t.iteration)

	server, err := os.ReadFile(types.ServerFileName)
	if err != nil {
		t.Log.Error(err)
		// XXX should we return an indicating that the intf is unknown
		// and not failed?
		return intfStatusMap, nil, err
	}
	serverNameAndPort := strings.TrimSpace(string(server))

	cloudClient := cloudconn.NewClient(t.Log, cloudconn.ClientOptions{
		AgentName:           t.AgentName,
		NetworkMonitor:      t.NetworkMonitor,
		DeviceNetworkStatus: &dns,
		TLSConfig:           nil,
		AgentMetrics:        t.Metrics,
		NetworkSendTimeout:  t.TestTimeout,
		NetworkDialTimeout:  0,
		DevUUID:             uuid.UUID{},
		DevSerial:           hardware.GetProductSerial(t.Log),
		DevSoftSerial:       hardware.GetSoftSerial(t.Log),
		NetTraceOpts:        t.netTraceOpts(dns),
		ResolverCacheFunc:   nil,
		NoLedManager:        false,
	})

	t.Log.Functionf("TestConnectivity: Use V2 API %v\n", cloudClient.UsingV2API())
	testURL := cloudconn.URLPathString(
		serverNameAndPort, cloudClient.UsingV2API(), nilUUID, "ping")

	err = cloudClient.UpdateTLSConfig(nil)
	if err != nil {
		t.Log.Functionf("TestConnectivity: " +
			"Device certificate not found, looking for Onboarding certificate")
		onboardingCert, err := tls.LoadX509KeyPair(types.OnboardCertName,
			types.OnboardKeyName)
		if err != nil {
			err = fmt.Errorf("onboarding certificate cannot be loaded: %v", err)
			t.Log.Functionf("TestConnectivity: %v\n", err)
			return intfStatusMap, nil, err
		}
		clientCert := &onboardingCert
		err = cloudClient.UpdateTLSConfig(clientCert)
		if err != nil {
			err = fmt.Errorf("failed to load TLS config for talking to controller: %v", err)
			t.Log.Functionf("TestConnectivity: %v", err)
			return intfStatusMap, nil, err
		}
	}

	if t.prevTLSConfig != nil {
		cloudClient.TLSConfig.ClientSessionCache = t.prevTLSConfig.ClientSessionCache
	}
	for ix := range dns.Ports {
		if dns.Ports[ix].InvalidConfig {
			continue
		}
		ifName := dns.Ports[ix].IfName
		err = cloudconn.CheckAndGetNetworkProxy(t.Log, &dns, ifName, t.Metrics)
		if err != nil {
			err = fmt.Errorf("failed to get network proxy for interface %s: %v",
				ifName, err)
			t.Log.Errorf("TestConnectivity: %v", err)
			intfStatusMap.RecordFailure(ifName, err.Error())
			return intfStatusMap, nil, err
		}
	}
	ctx, cancel := cloudClient.GetContextForAllIntfFunctions()
	defer cancel()
	rv, err := cloudClient.VerifyAllIntf(ctx, testURL, requiredSuccessCount,
		cloudconn.RequestOptions{
			WithNetTracing: withNetTrace,
			Iteration:      t.iteration,
		})
	intfStatusMap.SetOrUpdateFromMap(rv.IntfStatusMap)
	t.Log.Tracef("TestConnectivity: intfStatusMap = %+v", intfStatusMap)
	for i := range rv.TracedReqs {
		// Differentiate ping tests from google tests.
		reqName := rv.TracedReqs[i].RequestName
		rv.TracedReqs[i].RequestName = "ping-" + reqName
	}
	if withNetTrace {
		if (!rv.CloudReachable || err != nil) && !rv.RemoteTempFailure {
			rv.TracedReqs = append(rv.TracedReqs, t.tryGoogleWithTracing(dns)...)
		}
	}
	if err != nil {
		if rv.RemoteTempFailure {
			err = &RemoteTemporaryFailure{
				Endpoint:   serverNameAndPort,
				WrappedErr: err,
			}
		} else if portsNotReady := t.getPortsNotReady(err, dns); len(portsNotReady) > 0 {
			// At least one of the uplink ports is not ready in terms of L3 connectivity.
			// Signal to the caller that it might make sense to wait and repeat test later.
			err = &PortsNotReady{
				WrappedErr: err,
				Ports:      portsNotReady,
			}
		}
		t.Log.Errorf("TestConnectivity: %v", err)
		return intfStatusMap, rv.TracedReqs, err
	}

	t.prevTLSConfig = cloudClient.TLSConfig
	if rv.CloudReachable {
		t.Log.Functionf("TestConnectivity: uplink test SUCCEEDED for URL: %s", testURL)
		return intfStatusMap, rv.TracedReqs, nil
	}
	err = fmt.Errorf("uplink test FAILED for URL: %s", testURL)
	t.Log.Errorf("TestConnectivity: %v, intfStatusMap: %+v", err, intfStatusMap)
	return intfStatusMap, rv.TracedReqs, err
}

func (t *CloudConnectivityTester) getPortsNotReady(
	verifyErr error, dns types.DeviceNetworkStatus) (ports []string) {
	if sendErr, isSendErr := verifyErr.(*cloudconn.SendError); isSendErr {
		portMap := make(map[string]struct{}) // Avoid duplicate entries.
		for _, attempt := range sendErr.Attempts {
			var dnsErr *types.DNSNotAvailError
			if errors.As(attempt.Err, &dnsErr) {
				if port := dns.LookupPortByIfName(dnsErr.IfName); port != nil {
					portMap[port.Logicallabel] = struct{}{}
				}
			}
			var ipErr *types.IPAddrNotAvailError
			if errors.As(attempt.Err, &ipErr) {
				if port := dns.LookupPortByIfName(ipErr.IfName); port != nil {
					portMap[port.Logicallabel] = struct{}{}
				}
			}
		}
		for port := range portMap {
			ports = append(ports, port)
		}
	}
	return ports
}

// Enable all net traces, including packet capture - ping and google.com requests
// are quite small.
func (t *CloudConnectivityTester) netTraceOpts(
	dns types.DeviceNetworkStatus) []nettrace.TraceOpt {
	return []nettrace.TraceOpt{
		&nettrace.WithLogging{
			CustomLogger: &base.LogrusWrapper{Log: t.Log},
		},
		&nettrace.WithConntrack{},
		&nettrace.WithSockTrace{},
		&nettrace.WithDNSQueryTrace{},
		&nettrace.WithHTTPReqTrace{
			// Hide secrets stored inside values of header fields.
			HeaderFields: nettrace.HdrFieldsOptValueLenOnly,
		},
		&nettrace.WithPacketCapture{
			Interfaces:  types.GetMgmtPortsAny(dns, 0),
			IncludeICMP: true,
			IncludeARP:  true,
		},
	}
}

// If net tracing is enabled and the controller connectivity test fails, we try to access
// google.com over HTTP and HTTPS and include collected traces in the output.
// This can help to determine if the issue is with the Internet access or with
// something specific to the controller.
func (t *CloudConnectivityTester) tryGoogleWithTracing(
	dns types.DeviceNetworkStatus) (tracedReqs []netdump.TracedNetRequest) {
	client := cloudconn.NewClient(t.Log, cloudconn.ClientOptions{
		AgentName:           t.AgentName,
		DeviceNetworkStatus: &dns,
		TLSConfig:           nil,
		AgentMetrics:        nil,
		NetworkSendTimeout:  t.TestTimeout,
		NetworkDialTimeout:  0,
		DevUUID:             uuid.UUID{},
		DevSerial:           "",
		DevSoftSerial:       "",
		NetTraceOpts:        t.netTraceOpts(dns),
		ResolverCacheFunc:   nil,
		NoLedManager:        false,
	})
	ctx, cancel := client.GetContextForAllIntfFunctions()
	defer cancel()
	tests := []struct {
		url  string
		name string
	}{
		{url: "http://www.google.com", name: "google.com-over-http"},
		{url: "https://www.google.com", name: "google.com-over-https"},
	}
	for _, test := range tests {
		rv, _ := client.SendOnAllIntf(ctx, test.url, nil,
			cloudconn.RequestOptions{
				WithNetTracing: true,
				BailOnHTTPErr:  true,
				Iteration:      t.iteration,
			})
		for i := range rv.TracedReqs {
			reqName := rv.TracedReqs[i].RequestName
			rv.TracedReqs[i].RequestName = test.name + "-" + reqName
		}
		tracedReqs = append(tracedReqs, rv.TracedReqs...)
	}
	return tracedReqs
}
