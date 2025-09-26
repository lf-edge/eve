// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntester

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
)

// Hard-coded at 1 for now; at least one interface needs to work.
const requiredSuccessCount uint = 1

var nilUUID = uuid.UUID{} // used as a constant

// ZedcloudConnectivityTester implements external connectivity testing using
// the "/api/v2/edgeDevice/ping" endpoint provided by the zedcloud.
type ZedcloudConnectivityTester struct {
	// Exported attributes below should be injected.
	Log         *base.LogObject
	AgentName   string
	TestTimeout time.Duration // can be changed in run-time
	Metrics     *zedcloud.AgentMetrics

	// Configurable remote endpoints used to query and collect nettrace when
	// the controller is not accessible, to provide information about
	// network connectivity for troubleshooting purposes.
	// This list is injected and potentially updated at runtime by NIM.
	DiagRemoteEndpoints []*url.URL

	iteration     int
	prevTLSConfig *tls.Config
}

// TestConnectivity uses VerifyAllIntf from the zedcloud package, which
// tries to call the "ping" API of the controller.
func (t *ZedcloudConnectivityTester) TestConnectivity(dns types.DeviceNetworkStatus,
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

	zedcloudCtx := zedcloud.NewContext(t.Log, zedcloud.ContextOptions{
		DevNetworkStatus: &dns,
		SendTimeout:      uint32(t.TestTimeout.Seconds()),
		AgentMetrics:     t.Metrics,
		Serial:           hardware.GetProductSerial(t.Log),
		SoftSerial:       hardware.GetSoftSerial(t.Log),
		AgentName:        t.AgentName,
		NetTraceOpts:     t.netTraceOpts(dns),
	})
	t.Log.Functionf("TestConnectivity: Use V2 API %v\n", zedcloud.UseV2API())
	testURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, nilUUID, "ping")

	tlsConfig, err := zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus,
		nil, &zedcloudCtx)
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
		tlsConfig, err = zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus,
			clientCert, &zedcloudCtx)
		if err != nil {
			err = fmt.Errorf("failed to load TLS config for talking to Zedcloud: %v", err)
			t.Log.Functionf("TestConnectivity: %v", err)
			return intfStatusMap, nil, err
		}
	}

	if t.prevTLSConfig != nil {
		tlsConfig.ClientSessionCache = t.prevTLSConfig.ClientSessionCache
	}
	zedcloudCtx.TlsConfig = tlsConfig
	for ix := range dns.Ports {
		if dns.Ports[ix].InvalidConfig {
			continue
		}
		ifName := dns.Ports[ix].IfName
		err = devicenetwork.CheckAndGetNetworkProxy(t.Log, &dns, ifName, t.Metrics)
		if err != nil {
			err = fmt.Errorf("failed to get network proxy for interface %s: %v",
				ifName, err)
			t.Log.Errorf("TestConnectivity: %v", err)
			intfStatusMap.RecordFailure(ifName, err.Error())
			return intfStatusMap, nil, err
		}
	}
	rv, err := zedcloud.VerifyAllIntf(&zedcloudCtx, testURL, requiredSuccessCount,
		t.iteration, withNetTrace)
	intfStatusMap.SetOrUpdateFromMap(rv.IntfStatusMap)
	t.Log.Tracef("TestConnectivity: intfStatusMap = %+v", intfStatusMap)
	for i := range rv.TracedReqs {
		// Differentiate ping tests from google tests.
		reqName := rv.TracedReqs[i].RequestName
		rv.TracedReqs[i].RequestName = "ping-" + reqName
	}
	if withNetTrace {
		if (!rv.CloudReachable || err != nil) && !rv.RemoteTempFailure {
			// When network tracing is enabled and controller connectivity is not working,
			// we additionally perform connectivity tests towards configurable remote
			// endpoints and include network traces from them in the netdump for
			// troubleshooting purposes.
			rv.TracedReqs = append(rv.TracedReqs, t.tryRemoteEndpointsWithTracing(dns)...)
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

	t.prevTLSConfig = zedcloudCtx.TlsConfig
	if rv.CloudReachable {
		t.Log.Functionf("TestConnectivity: uplink test SUCCEEDED for URL: %s", testURL)
		return intfStatusMap, rv.TracedReqs, nil
	}
	err = fmt.Errorf("uplink test FAILED for URL: %s", testURL)
	t.Log.Errorf("TestConnectivity: %v, intfStatusMap: %+v", err, intfStatusMap)
	return intfStatusMap, rv.TracedReqs, err
}

func (t *ZedcloudConnectivityTester) getPortsNotReady(
	verifyErr error, dns types.DeviceNetworkStatus) (ports []string) {
	if sendErr, isSendErr := verifyErr.(*zedcloud.SendError); isSendErr {
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

// Enable all net traces, including packet capture - ping and diag requests
// are quite small.
func (t *ZedcloudConnectivityTester) netTraceOpts(
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
// configured remote HTTP and HTTPS endpoints and include collected traces in the output.
// This can help to determine if the issue is with the network connectivity or with
// something specific to the controller.
func (t *ZedcloudConnectivityTester) tryRemoteEndpointsWithTracing(
	dns types.DeviceNetworkStatus) (tracedReqs []netdump.TracedNetRequest) {
	const bailOnHTTPErr = true
	const withNetTracing = true
	zedcloudCtx := zedcloud.NewContext(t.Log, zedcloud.ContextOptions{
		DevNetworkStatus: &dns,
		SendTimeout:      uint32(t.TestTimeout.Seconds()),
		AgentName:        t.AgentName,
		NetTraceOpts:     t.netTraceOpts(dns),
	})
	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(&zedcloudCtx)
	defer cancel()
	for _, url := range t.DiagRemoteEndpoints {
		if url == nil {
			continue
		}
		rv, _ := zedcloud.SendOnAllIntf(ctxWork, &zedcloudCtx, url.String(), 0, nil,
			t.iteration, bailOnHTTPErr, withNetTracing)
		for i := range rv.TracedReqs {
			reqName := rv.TracedReqs[i].RequestName
			rv.TracedReqs[i].RequestName = strings.Join(
				[]string{url.Scheme, url.Hostname(), reqName}, "-")
		}
		tracedReqs = append(tracedReqs, rv.TracedReqs...)
	}
	return tracedReqs
}
