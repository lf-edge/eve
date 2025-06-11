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
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Hard-coded at 1 for now; at least one interface needs to work.
const requiredSuccessCount uint = 1

var nilUUID = uuid.UUID{} // used as a constant

// ControllerConnectivityTester implements external connectivity testing using
// the "/api/v2/edgeDevice/ping" endpoint provided by the controller.
type ControllerConnectivityTester struct {
	// Exported attributes below should be injected.
	Log            *base.LogObject
	AgentName      string
	TestTimeout    time.Duration // can be changed in run-time
	Metrics        *controllerconn.AgentMetrics
	NetworkMonitor netmonitor.NetworkMonitor

	iteration          int
	prevTLSConfig      *tls.Config
	controllerHostname string
}

// TestConnectivity uses VerifyAllIntf from the controllerconn package, which
// tries to call the "ping" API of the controller.
func (t *ControllerConnectivityTester) TestConnectivity(
	dns types.DeviceNetworkStatus, airGapMode AirGapMode,
	withNetTrace bool) (types.IntfStatusMap, []netdump.TracedNetRequest, error) {

	t.iteration++
	intfStatusMap := *types.NewIntfStatusMap()
	t.Log.Tracef("TestConnectivity() requiredSuccessCount %d, iteration %d",
		requiredSuccessCount, t.iteration)

	ctrlClient := controllerconn.NewClient(t.Log, controllerconn.ClientOptions{
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

	err := ctrlClient.UpdateTLSConfig(nil)
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
		err = ctrlClient.UpdateTLSConfig(clientCert)
		if err != nil {
			err = fmt.Errorf("failed to load TLS config for talking to controller: %v", err)
			t.Log.Functionf("TestConnectivity: %v", err)
			return intfStatusMap, nil, err
		}
	}

	if t.prevTLSConfig != nil {
		ctrlClient.TLSConfig.ClientSessionCache = t.prevTLSConfig.ClientSessionCache
	}
	t.prevTLSConfig = ctrlClient.TLSConfig

	for ix := range dns.Ports {
		if dns.Ports[ix].InvalidConfig {
			continue
		}
		ifName := dns.Ports[ix].IfName
		err = controllerconn.CheckAndGetNetworkProxy(t.Log, &dns, ifName, t.Metrics)
		if err != nil {
			err = fmt.Errorf("failed to get network proxy for interface %s: %v",
				ifName, err)
			t.Log.Errorf("TestConnectivity: %v", err)
			intfStatusMap.RecordFailure(ifName, err.Error())
			return intfStatusMap, nil, err
		}
	}

	connTest := connTestSetup{
		ctrlClient:   ctrlClient,
		dns:          dns,
		withNetTrace: withNetTrace,
		airGapMode:   airGapMode,
	}
	var tracedReqs []netdump.TracedNetRequest
	if airGapMode.Enabled && airGapMode.LocURL != "" {
		locTestRV := t.testLOCConnectivity(connTest)
		intfStatusMap.SetOrUpdateFromMap(locTestRV.intfStatusMap)
		tracedReqs = locTestRV.tracedReqs
		if locTestRV.testErr == nil {
			return intfStatusMap, tracedReqs, nil
		}
		// If LOC connectivity is not working, we continue with the standard controller
		// connectivity test.
	}

	controllerTestRV := t.testControllerConnectivity(connTest)
	intfStatusMap.SetOrUpdateFromMap(controllerTestRV.intfStatusMap)
	tracedReqs = append(tracedReqs, controllerTestRV.tracedReqs...)

	if !airGapMode.Enabled && withNetTrace && controllerTestRV.testErr != nil {
		if _, isRTF := controllerTestRV.testErr.(*RemoteTemporaryFailure); !isRTF {
			// When network tracing is enabled and controller connectivity is not working,
			// we additionally perform google.com connectivity tests and include network
			// traces from them in the netdump for troubleshooting purposes.
			tracedReqs = append(tracedReqs, t.tryGoogleWithTracing(dns)...)
		}
	}

	return intfStatusMap, tracedReqs, controllerTestRV.testErr
}

type connTestSetup struct {
	ctrlClient   *controllerconn.Client
	dns          types.DeviceNetworkStatus
	withNetTrace bool
	airGapMode   AirGapMode
}

type connectivityTestRV struct {
	intfStatusMap types.IntfStatusMap
	tracedReqs    []netdump.TracedNetRequest
	testErr       error
}

func (t *ControllerConnectivityTester) testControllerConnectivity(
	connTest connTestSetup) (rv connectivityTestRV) {
	if t.controllerHostname == "" {
		server, err := os.ReadFile(types.ServerFileName)
		if err != nil {
			rv.testErr = fmt.Errorf("controller hostname is not available: %w", err)
			t.Log.Error(rv.testErr)
			return rv
		}
		t.controllerHostname = strings.TrimSpace(string(server))
	}
	testURL := controllerconn.URLPathString(
		t.controllerHostname, connTest.ctrlClient.UsingV2API(), nilUUID, "ping")
	ctx, cancel := connTest.ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()

	suppressLogs := connTest.airGapMode.Enabled
	verifyRV, verifyErr := connTest.ctrlClient.VerifyAllIntf(ctx, testURL,
		requiredSuccessCount, controllerconn.RequestOptions{
			WithNetTracing: connTest.withNetTrace,
			Iteration:      t.iteration,
			SuppressLogs:   suppressLogs,
		})

	rv.intfStatusMap = verifyRV.IntfStatusMap
	rv.tracedReqs = verifyRV.TracedReqs
	for i := range rv.tracedReqs {
		reqName := rv.tracedReqs[i].RequestName
		rv.tracedReqs[i].RequestName = "ping-controller-" + reqName
	}
	rv.testErr = t.processReturnValue(
		connTest.dns, t.controllerHostname, verifyRV, verifyErr, suppressLogs)
	return rv
}

func (t *ControllerConnectivityTester) testLOCConnectivity(
	connTest connTestSetup) (rv connectivityTestRV) {
	testURL := controllerconn.URLPathString(
		connTest.airGapMode.LocURL, connTest.ctrlClient.UsingV2API(), nilUUID, "ping")
	ctx, cancel := connTest.ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()

	verifyRV, verifyErr := connTest.ctrlClient.VerifyAllIntf(ctx, testURL,
		requiredSuccessCount, controllerconn.RequestOptions{
			WithNetTracing: connTest.withNetTrace,
			// Older versions of LOC do not implement the ping endpoint.
			// To maintain compatibility, we treat HTTP status code 404 as a successful
			// connectivity response (at least for now).
			Accept4xxErrors: true,
			Iteration:       t.iteration,
		})

	rv.intfStatusMap = verifyRV.IntfStatusMap
	rv.tracedReqs = verifyRV.TracedReqs
	for i := range rv.tracedReqs {
		reqName := rv.tracedReqs[i].RequestName
		rv.tracedReqs[i].RequestName = "ping-loc-" + reqName
	}
	rv.testErr = t.processReturnValue(
		connTest.dns, connTest.airGapMode.LocURL, verifyRV, verifyErr, false)
	return rv
}

func (t *ControllerConnectivityTester) processReturnValue(
	dns types.DeviceNetworkStatus, endpoint string, rv controllerconn.VerifyRetval,
	rvErr error, suppressLogs bool) (processedErr error) {
	if rvErr != nil {
		if rv.RemoteTempFailure {
			processedErr = &RemoteTemporaryFailure{
				Endpoint:   endpoint,
				WrappedErr: rvErr,
			}
		} else if portsNotReady := t.getPortsNotReady(rvErr, dns); len(portsNotReady) > 0 {
			// At least one of the uplink ports is not ready in terms of L3 connectivity.
			// Signal to the caller that it might make sense to wait and repeat test later.
			processedErr = &PortsNotReady{
				WrappedErr: rvErr,
				Ports:      portsNotReady,
			}
		} else {
			processedErr = rvErr
		}
		return processedErr
	}
	if !rv.ControllerReachable {
		processedErr = fmt.Errorf("%s is not reachable", endpoint)
	}
	if processedErr == nil {
		t.Log.Functionf("TestConnectivity: connectivity test SUCCEEDED for URL: %s",
			endpoint)
	} else {
		logFunc := t.Log.Errorf
		if suppressLogs {
			logFunc = t.Log.Functionf
		}
		logFunc("TestConnectivity: connectivity test FAILED for URL: %s, err: %v",
			endpoint, processedErr)
	}
	return processedErr
}

func (t *ControllerConnectivityTester) getPortsNotReady(
	verifyErr error, dns types.DeviceNetworkStatus) (ports []string) {
	if sendErr, isSendErr := verifyErr.(*controllerconn.SendError); isSendErr {
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
func (t *ControllerConnectivityTester) netTraceOpts(
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
func (t *ControllerConnectivityTester) tryGoogleWithTracing(
	dns types.DeviceNetworkStatus) (tracedReqs []netdump.TracedNetRequest) {
	client := controllerconn.NewClient(t.Log, controllerconn.ClientOptions{
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
			controllerconn.RequestOptions{
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
