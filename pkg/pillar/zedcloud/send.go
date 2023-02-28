// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common code to communicate to zedcloud

package zedcloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
	"google.golang.org/protobuf/proto"
)

// ContentTypeProto : binary-encoded Protobuf content type
const ContentTypeProto = "application/x-proto-binary"

// MaxWaitForRequests : upper limit of time to send requests
// independent of how many management interfaces and source IP addresses we try
const MaxWaitForRequests = 4 * time.Minute

// ZedCloudContext is set up by NewContext() below
// revive:disable-next-line Needs to be fixed in other files as well, which then lets new yetus warnings arise
type ZedCloudContext struct {
	DeviceNetworkStatus *types.DeviceNetworkStatus
	// revive:disable-next-line
	TlsConfig          *tls.Config
	FailureFunc        func(log *base.LogObject, intf string, url string, reqLen int64, respLen int64, authFail bool)
	SuccessFunc        func(log *base.LogObject, intf string, url string, reqLen int64, respLen int64, timeSpent int64, resume bool)
	NoLedManager       bool // Don't call UpdateLedManagerConfig
	DevUUID            uuid.UUID
	DevSerial          string
	DevSoftSerial      string
	NetworkSendTimeout uint32 // In seconds
	V2API              bool   // XXX Needed?
	AgentName          string // the agent process name
	NetTraceOpts       []nettrace.TraceOpt
	// V2 related items
	PrevCertPEM           [][]byte // cached proxy certs for later comparison
	onBoardCert           *tls.Certificate
	deviceCert            *tls.Certificate
	serverSigningCert     *x509.Certificate
	deviceCertHash        []byte
	onBoardCertHash       []byte
	serverSigningCertHash []byte
	onBoardCertBytes      []byte
	log                   *base.LogObject
	DeferredEventCtx      *DeferredContext
	DeferredPeriodicCtx   *DeferredContext
}

// ContextOptions - options to be passed at NewContext
type ContextOptions struct {
	DevNetworkStatus *types.DeviceNetworkStatus
	TLSConfig        *tls.Config
	AgentMetrics     *AgentMetrics
	Timeout          uint32
	Serial           string
	SoftSerial       string
	AgentName        string // XXX replace by NoLogFailures?
	NetTraceOpts     []nettrace.TraceOpt
}

// SendAttempt - single attempt to send data made by SendOnIntf function.
type SendAttempt struct {
	// Non-nil if the attempt failed.
	Err error
	// Name of the interface through which the data were send.
	IfName string
	// Source IP address used by the send operation.
	SourceAddr net.IP
}

// String describes single Send* attempt.
func (sa SendAttempt) String() string {
	var withSrc string
	if sa.SourceAddr != nil && !sa.SourceAddr.IsUnspecified() {
		withSrc = " with src IP " + sa.SourceAddr.String()
	}
	return fmt.Sprintf("send via %s%s: %v", sa.IfName, withSrc, sa.Err)
}

// SendError - error that may be returned by VerifyAllIntf and SendOn* functions below,
// summarizing all errors from all the attempts.
type SendError struct {
	// A summary error for the failed Send operation.
	Err error
	// Information about individual Send attempts.
	Attempts []SendAttempt
}

// Error message.
func (e *SendError) Error() string {
	return e.Err.Error()
}

// Unwrap - return wrapped error.
func (e *SendError) Unwrap() error {
	return e.Err
}

// SendRetval is returned from non-local variants of Send* functions.
// (from SendOnAllIntf and SendOnIntf).
type SendRetval struct {
	ReqURL       string // Used by e.g. RemoveAndVerifyAuthContainer().
	Status       types.SenderStatus
	HTTPResp     *http.Response
	RespContents []byte
	TracedReqs   []netdump.TracedNetRequest
}

// VerifyRetval is returned from connectivity verification (VerifyAllIntf).
type VerifyRetval struct {
	CloudReachable    bool
	RemoteTempFailure bool
	IntfStatusMap     types.IntfStatusMap
	TracedReqs        []netdump.TracedNetRequest
}

var nilUUID = uuid.UUID{}

// GetContextForAllIntfFunctions returns context with timeout to use with AllIntf functions
// it uses 3 times of defined NetworkSendTimeout
// and limits max wait up to MaxWaitForRequests
func GetContextForAllIntfFunctions(ctx *ZedCloudContext) (context.Context, context.CancelFunc) {
	maxWaitDuration := time.Duration(ctx.NetworkSendTimeout) * time.Second * 3
	if maxWaitDuration == 0 {
		maxWaitDuration = MaxWaitForRequests
		ctx.log.Warnf("GetContextForAllIntfFunctions: provided maxWaitDuration equals 0, will use %d",
			MaxWaitForRequests)
	}
	if maxWaitDuration > MaxWaitForRequests {
		ctx.log.Functionf("GetContextForAllIntfFunctions: maxWaitDuration %d is more than limit, will use %d",
			maxWaitDuration, MaxWaitForRequests)
		maxWaitDuration = MaxWaitForRequests
	}
	return context.WithTimeout(context.Background(), maxWaitDuration)
}

// SendOnAllIntf tries all interfaces (free first) until one succeeds. iteration arg
// ensure load spreading across multiple interfaces.
// Returns response for first success. Caller can not use SendRetval.HTTPResp.Body but can
// use SendRetval.RespContents byte slice.
// If bailOnHTTPErr is set we immediately return when we get a 4xx or 5xx error without
// trying the other interfaces.
// XXX also 1010 from CloudFlare?
// http.StatusForbidden is a special case i.e. even if bailOnHTTPErr is not set
// we bail out, since caller needs to be notified immediately for triggering any
// reaction based on this.
// We return a SendRetval.Status enum for various error cases.
// The caller is responsible to handle any required AuthContainer by calling
// RemoveAndVerifyAuthContainer
func SendOnAllIntf(ctxWork context.Context, ctx *ZedCloudContext, url string, reqlen int64,
	b *bytes.Buffer, iteration int, bailOnHTTPErr, withNetTracing bool) (SendRetval, error) {

	log := ctx.log
	// If failed then try the non-free
	const allowProxy = true
	var attempts []SendAttempt
	combinedRV := SendRetval{ReqURL: url}

	intfs := types.GetMgmtPortsSortedCostWithoutFailed(*ctx.DeviceNetworkStatus, iteration)
	if len(intfs) == 0 {
		// This can happen during onboarding etc and the failed status
		// might be updated infrequently by nim
		log.Warnf("All management ports are marked failed; trying all")
		intfs = types.GetMgmtPortsSortedCost(*ctx.DeviceNetworkStatus, iteration)
	}
	if len(intfs) == 0 {
		err := fmt.Errorf("Can not connect to %s: No management interfaces",
			url)
		log.Error(err.Error())
		return combinedRV, err
	}

	for _, intf := range intfs {
		const useOnboard = false
		rv, err := SendOnIntf(ctxWork, ctx, url, intf, reqlen, b,
			allowProxy, useOnboard, withNetTracing, false)
		combinedRV.TracedReqs = append(combinedRV.TracedReqs, rv.TracedReqs...)
		// this changes original boolean logic a little in V2 API, basically the last status non-zero enum would
		// overwrite the previous one in the loop if they are differ
		if rv.Status != types.SenderStatusNone {
			combinedRV.Status = rv.Status
		}
		if rv.HTTPResp != nil {
			switch rv.HTTPResp.StatusCode {
			case http.StatusServiceUnavailable:
				combinedRV.Status = types.SenderStatusUpgrade
			case http.StatusNotFound, http.StatusBadRequest:
				combinedRV.Status = types.SenderStatusNotFound
			case http.StatusForbidden:
				combinedRV.Status = types.SenderStatusForbidden
			}
		}

		if bailOnHTTPErr && rv.HTTPResp != nil &&
			rv.HTTPResp.StatusCode >= 400 && rv.HTTPResp.StatusCode < 600 {
			log.Functionf("sendOnAllIntf: for %s reqlen %d ignore code %d\n",
				url, reqlen, rv.HTTPResp.StatusCode)
			combinedRV.HTTPResp = rv.HTTPResp
			return combinedRV, err
		}
		if rv.HTTPResp != nil && rv.HTTPResp.StatusCode == http.StatusForbidden {
			combinedRV.HTTPResp = rv.HTTPResp
			return combinedRV, err
		}
		if err != nil {
			if sendErr, ok := err.(*SendError); ok && len(sendErr.Attempts) > 0 {
				// Merge errors from all attempts.
				attempts = append(attempts, sendErr.Attempts...)
			} else {
				attempts = append(attempts, SendAttempt{
					Err:    err,
					IfName: intf,
				})
			}
			continue
		}
		combinedRV.HTTPResp = rv.HTTPResp
		combinedRV.RespContents = rv.RespContents
		return combinedRV, nil
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %v",
		url, attempts)
	log.Errorln(errStr)
	err := &SendError{
		Err:      errors.New(errStr),
		Attempts: attempts,
	}
	return combinedRV, err
}

// VerifyAllIntf : verify the state of connectivity for *all* uplink interfaces.
// The interfaces are tested in the order of decreasing priority (i.e. increasing
// cost). Until we find enough working management interfaces (the limit is currently
// hard-coded to 1 working mgmt interface), every iterated management interface
// undergoes full end-to-end testing. First we run local checks:
//   - Does interface (i.e. link) exist in the kernel?
//   - Does interface have a routable IP address?
//   - Is there any DNS server associated with the interface?
//   - If there is a proxy config, is it valid?
//   - If this is a wwan interface, is the modem connected and are there any errors
//     reported by the wwan microservice?
//   - etc.
//
// Additionally, for the full interface testing we run an HTTP GET request for the provided
// URL to test connectivity with a remote endpoint (typically controller).
// Once we find enough working management interfaces, the remaining interfaces (of lower
// priority, higher cost) are only verified using the aforementioned local checks.
// Non-management interfaces (i.e. app-shared) are always tested using local checks only,
// we never run HTTP requests for these types of interfaces.
// The idea is to limit the amount or completely avoid generating traffic for interfaces
// (of potentially higher cost) which are currently not going to be used by EVE for
// connectivity with the controller. At the same time we want to provide at least some
// status for all interfaces and avoid publishing old and potentially obsolete interface
// state data.
//
// We return a bool VerifyRetval.RemoteTempFailure for the cases when we reached
// the controller but it is overloaded, or has certificate issues.
// Return Values: VerifyRetval, error
//   - If Failure,
//     VerifyRetval.RemoteTempFailure - indicates if it is a remote failure
//     error  - indicates details of Errors
//   - VerifyRetval.IntfStatusMap - Status for each verified interface.
//     Includes entries for all interfaces that were tested.
//     If an intf is success, Error == "", else - Set to appropriate Error
//     ErrorTime will always be set for the interface.
func VerifyAllIntf(ctx *ZedCloudContext, url string, requiredSuccessCount uint,
	iteration int, withNetTracing bool) (VerifyRetval, error) {

	log := ctx.log
	const allowProxy = true
	var (
		verifyRV         VerifyRetval
		intfSuccessCount uint
		attempts         []SendAttempt
	)

	// Map of per-interface errors
	verifyRV.IntfStatusMap = *types.NewIntfStatusMap()

	// This will be set to the cost of the most expensive mgmt interface
	// that was needed to achieve requiredSuccessCount.
	var workingMgmtCost uint8

	intfs := types.GetAllPortsSortedCost(*ctx.DeviceNetworkStatus, iteration)
	ctxWork, cancel := GetContextForAllIntfFunctions(ctx)
	defer cancel()

	// Always iterate through *all* uplink interfaces, never break out of the loop.
	// However, some of the interfaces might be verified only using local checks
	// (aka dry-run).
	for _, intf := range intfs {
		portStatus := types.GetPort(*ctx.DeviceNetworkStatus, intf)
		// If we have enough uplinks with cloud connectivity, then the remaining
		// interfaces (some of which might not be free) are verified using
		// only local checks, without generating any traffic.
		// Local-only checks are also always applied for non-management interfaces
		// (i.e. app-shared).
		dryRun := !portStatus.IsMgmt || intfSuccessCount >= requiredSuccessCount
		// For LTE connectivity start by checking locally available state information
		// as provided by the wwan microservice. If an error is detected, report
		// it immediately rather than trying to access the URL and generating
		// traffic.
		if portStatus.WirelessStatus.WType == types.WirelessTypeCellular {
			wwanStatus := portStatus.WirelessStatus.Cellular
			if wwanStatus.ConfigError != "" {
				verifyRV.IntfStatusMap.RecordFailure(intf, wwanStatus.ConfigError)
				continue
			}
			if wwanStatus.Module.OpMode != types.WwanOpModeConnected {
				verifyRV.IntfStatusMap.RecordFailure(intf,
					fmt.Sprintf("modem %s is not connected, current state: %s",
						wwanStatus.Module.Name, wwanStatus.Module.OpMode))
				continue
			}
			if wwanStatus.ProbeError != "" {
				verifyRV.IntfStatusMap.RecordFailure(intf, wwanStatus.ProbeError)
				continue
			}
		}
		// This VerifyAllIntf() is called for "ping" url only, it does
		// not have return envelope verifying check after the call nor
		// does it check other values of status.
		const useOnboard = false
		rv, err := SendOnIntf(ctxWork, ctx, url, intf, 0, nil,
			allowProxy, useOnboard, withNetTracing, dryRun)
		verifyRV.TracedReqs = append(verifyRV.TracedReqs, rv.TracedReqs...)
		switch rv.Status {
		case types.SenderStatusRefused, types.SenderStatusCertInvalid:
			verifyRV.RemoteTempFailure = true
		}
		if rv.HTTPResp != nil &&
			(rv.HTTPResp.StatusCode >= http.StatusInternalServerError &&
				rv.HTTPResp.StatusCode <= http.StatusNetworkAuthenticationRequired) {
			verifyRV.RemoteTempFailure = true
		}
		if err != nil {
			log.Errorf("Zedcloud un-reachable via interface %s: %s",
				intf, err)
			if sendErr, ok := err.(*SendError); ok && len(sendErr.Attempts) > 0 {
				// Merge errors from all attempts.
				attempts = append(attempts, sendErr.Attempts...)
			} else {
				attempts = append(attempts, SendAttempt{
					Err:    err,
					IfName: intf,
				})
			}
			verifyRV.IntfStatusMap.RecordFailure(intf, err.Error())
			continue
		}
		if dryRun {
			// If this is a management interface with the same cost as the last
			// needed working mgmt interface, then do not overshadow results
			// of the last full end-to-end test (test that included sending a request
			// to the remote URL) with a (successful) dry-run test (only local checks).
			// Instead, we let the next iterations of VerifyAllIntf to eventually
			// get to this interface through rotations and re-test it fully
			// (or cheaper interface(s) will start working and this interface will be
			// relegated to dry-run testing only).
			if !portStatus.IsMgmt || portStatus.Cost > workingMgmtCost {
				verifyRV.IntfStatusMap.RecordSuccess(intf)
			}
			if portStatus.IsMgmt {
				intfSuccessCount++
			}
			continue
		}
		switch rv.HTTPResp.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusNotModified, http.StatusNoContent:
			log.Tracef("VerifyAllIntf: Zedcloud reachable via interface %s", intf)
			verifyRV.IntfStatusMap.RecordSuccess(intf)
			if intfSuccessCount < requiredSuccessCount {
				workingMgmtCost = portStatus.Cost
			}
			intfSuccessCount++
		default:
			err = fmt.Errorf("controller with URL %s returned status code %d (%s)",
				url, rv.HTTPResp.StatusCode, http.StatusText(rv.HTTPResp.StatusCode))
			log.Errorf("Uplink test FAILED via %s: %v", intf, err)
			attempts = append(attempts, SendAttempt{
				Err:    err,
				IfName: intf,
			})
			verifyRV.IntfStatusMap.RecordFailure(intf, err.Error())
			continue
		}
	}
	if requiredSuccessCount <= 0 {
		// No need for working mgmt interface. Just return true.
		verifyRV.CloudReachable = true
		return verifyRV, nil
	}
	if len(types.GetMgmtPortsAny(*ctx.DeviceNetworkStatus, 0)) == 0 {
		err := fmt.Errorf("Can not connect to %s: No management interfaces", url)
		log.Error(err.Error())
		return verifyRV, err
	}
	if intfSuccessCount == 0 {
		errStr := fmt.Sprintf("All attempts to connect to %s failed: %v",
			url, attempts)
		log.Errorln(errStr)
		err := &SendError{
			Err:      errors.New(errStr),
			Attempts: attempts,
		}
		return verifyRV, err
	}
	if intfSuccessCount < requiredSuccessCount {
		errStr := fmt.Sprintf("Not enough Ports (%d) against required count %d"+
			" to reach %s; last failed with: %v",
			intfSuccessCount, requiredSuccessCount, url, attempts)
		log.Errorln(errStr)
		err := &SendError{
			Err:      errors.New(errStr),
			Attempts: attempts,
		}
		return verifyRV, err
	}
	verifyRV.CloudReachable = true
	log.Tracef("VerifyAllIntf: Verify done. intfStatusMap: %+v",
		verifyRV.IntfStatusMap)
	return verifyRV, nil
}

// SendOnIntf : Tries all source addresses on interface until one succeeds.
// Returns response for first success. Caller can not use SendRetval.HTTPResp.Body but can
// use SendRetval.RespContents contents return.
// If we get a http response, we return that even if it was an error to allow the caller
// to look at StatusCode.
// We return a SendRetval.Status enum for the caller to differentiate various error cases.
// For example, the controller might be accessible but is overloaded, or has certificate
// issues.
// The caller is responsible to handle any required AuthContainer by calling
// RemoveAndVerifyAuthContainer
// Enable dryRun to just perform all pre-send interface checks without actually
// sending any data.
func SendOnIntf(workContext context.Context, ctx *ZedCloudContext, destURL string,
	intf string, reqlen int64, b *bytes.Buffer, allowProxy, useOnboard, withNetTracing,
	dryRun bool) (SendRetval, error) {

	log := ctx.log
	var rv SendRetval
	var reqURL string
	var useTLS, isEdgenode, isGet bool

	if strings.HasPrefix(destURL, "http:") {
		reqURL = destURL
		useTLS = false
	} else {
		if strings.HasPrefix(destURL, "https:") {
			reqURL = destURL
		} else {
			reqURL = "https://" + destURL
		}
		useTLS = true
	}
	rv.ReqURL = reqURL

	if strings.Contains(destURL, "/edgedevice/") {
		isEdgenode = true
		if strings.Contains(destURL, "/register") {
			useOnboard = true
		}
	}
	if b == nil {
		isGet = true
	}

	addrCount, err := types.CountLocalAddrAnyNoLinkLocalIf(*ctx.DeviceNetworkStatus, intf)
	if err != nil {
		return rv, err
	}
	log.Tracef("Connecting to %s using intf %s #sources %d reqlen %d\n",
		reqURL, intf, addrCount, reqlen)

	if addrCount == 0 {
		if ctx.FailureFunc != nil && !dryRun {
			ctx.FailureFunc(log, intf, reqURL, 0, 0, false)
		}
		// Determine a specific failure for intf
		link, err := netlink.LinkByName(intf)
		if err != nil {
			errStr := fmt.Sprintf("Link not found to connect to %s using intf %s: %s",
				reqURL, intf, err)
			log.Traceln(errStr)
			return rv, errors.New(errStr)
		}
		attrs := link.Attrs()
		if attrs.OperState != netlink.OperUp {
			errStr := fmt.Sprintf("Link not up to connect to %s using intf %s: %s",
				reqURL, intf, attrs.OperState.String())
			log.Traceln(errStr)
			return rv, errors.New(errStr)
		}
		err = &types.IPAddrNotAvail{IfName: intf}
		log.Trace(err)
		return rv, err
	}

	// Prepare config for the HTTP client.
	clientConfig := nettrace.HTTPClientCfg{
		// Since we recreate the transport on each call there is no benefit
		// to keeping the connections open.
		DisableKeepAlive: true,
	}
	if ctx.NetworkSendTimeout != 0 {
		clientConfig.ReqTimeout = time.Duration(ctx.NetworkSendTimeout) * time.Second
	}

	// Get the transport header with proxy information filled
	proxyURL, err := LookupProxy(ctx.log, ctx.DeviceNetworkStatus, intf, reqURL)
	var usedProxy, usedProxyWithIP bool
	if err == nil && proxyURL != nil && allowProxy {
		log.Tracef("sendOnIntf: For input URL %s, proxy found is %s",
			reqURL, proxyURL.String())
		usedProxy = true
		host := strings.Split(proxyURL.Host, ":")[0]
		usedProxyWithIP = net.ParseIP(host) != nil
		clientConfig.TLSClientConfig = ctx.TlsConfig
		clientConfig.Proxy = http.ProxyURL(proxyURL)
	} else {
		clientConfig.TLSClientConfig = ctx.TlsConfig
	}

	// Note that if an explicit HTTPS proxy addressed by an IP address is used,
	// EVE does not need to perform any domain name resolution.
	// The resolution of the controller's domain name is performed by the proxy,
	// not by EVE.
	dnsServers := types.GetDNSServers(*ctx.DeviceNetworkStatus, intf)
	if len(dnsServers) == 0 && !usedProxyWithIP {
		if ctx.FailureFunc != nil && !dryRun {
			ctx.FailureFunc(log, intf, reqURL, 0, 0, false)
		}
		err = &types.DNSNotAvail{
			IfName: intf,
		}
		log.Trace(err)
		return rv, err
	}
	// Make sure that the HTTP client will not try to use DNS server configured
	// for another interface.
	skipNs := func(ipAddr net.IP, port uint16) (skip bool, reason string) {
		for _, dnsServer := range dnsServers {
			if dnsServer != nil && dnsServer.Equal(ipAddr) {
				return false, ""
			}
		}
		return true, "DNS server is from a different network"
	}
	clientConfig.SkipNameserver = skipNs

	if dryRun {
		// Do not actually send the request.
		// Return nil response and nil error back to the caller.
		return rv, nil
	}

	var (
		transport     *http.Transport
		attempts      []SendAttempt
		sessionResume bool
	)
	if !withNetTracing {
		transport = &http.Transport{
			TLSClientConfig:   clientConfig.TLSClientConfig,
			Proxy:             clientConfig.Proxy,
			DisableKeepAlives: clientConfig.DisableKeepAlive,
		}
	}

	// If the HTTP requests are being traced and PCAP is enabled, the function
	// will wait just a little bit at the end of each request to capture all the packets.
	// This overhead is introduced only when requests are traced, which
	// is not very often (e.g. once per day).
	const pcapDelay = 250 * time.Millisecond
	var withPCAP bool
	if withNetTracing {
		for _, traceOpt := range ctx.NetTraceOpts {
			if _, ok := traceOpt.(*nettrace.WithPacketCapture); ok {
				withPCAP = true
				break
			}
		}
	}

	// Try all addresses
	for retryCount := 0; retryCount < addrCount; retryCount++ {
		localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Error(err)
			return rv, err
		}
		clientConfig.SourceIP = localAddr
		attempt := SendAttempt{
			IfName:     intf,
			SourceAddr: localAddr,
		}

		// Prepare the HTTP request.
		var req *http.Request
		var b2 *bytes.Buffer
		if ctx.V2API && isEdgenode && !isGet {
			b2, err = AddAuthentication(ctx, b, useOnboard)
			if err != nil {
				log.Errorf("SendOnIntf: auth error %v\n", err)
				return rv, err
			}
			reqlen = int64(b2.Len())
			log.Tracef("SendOnIntf: add auth for %s\n", reqURL)
		} else {
			b2 = b
		}

		if b2 != nil {
			req, err = http.NewRequest("POST", reqURL, b2)
		} else {
			req, err = http.NewRequest("GET", reqURL, nil)
		}
		if err != nil {
			log.Errorf("NewRequest failed %s\n", err)
			attempt.Err = err
			attempts = append(attempts, attempt)
			continue
		}

		if b2 != nil {
			req.Header.Add("Content-Type", ContentTypeProto)
		}
		// Add a per-request UUID to the HTTP Header
		// for traceability in the controller
		id, err := uuid.NewV4()
		if err != nil {
			log.Errorf("NewV4 failed: %v", err)
			attempt.Err = err
			attempts = append(attempts, attempt)
			continue
		}
		req.Header.Add("X-Request-Id", id.String())
		if ctx.DevUUID == nilUUID {
			// Also add Device Serial Number to the HTTP Header for initial tracability
			devSerialNum := ctx.DevSerial
			if devSerialNum != "" {
				req.Header.Add("X-Serial-Number", devSerialNum)
			}
			// Add Software Serial Number to the HTTP Header for initial tracability
			devSoftSerial := ctx.DevSoftSerial
			if devSoftSerial != "" {
				req.Header.Add("X-Soft-Serial", devSoftSerial)
			}
			log.Tracef("Serial-Numbers, serial: %s, soft-serial %s",
				devSerialNum, devSoftSerial)
		}

		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				log.Tracef("Got RemoteAddr: %+v, LocalAddr: %+v\n",
					connInfo.Conn.RemoteAddr(),
					connInfo.Conn.LocalAddr())
			},
			DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
				log.Tracef("DNS Info: %+v\n", dnsInfo)
			},
			DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
				log.Tracef("DNS start: %+v\n", dnsInfo)
			},
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				sessionResume = state.DidResume
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(workContext, trace))
		log.Tracef("SendOnIntf: req method %s, isget %v, url %s",
			req.Method, isGet, reqURL)
		apiCallStartTime := time.Now()

		// Prepare the HTTP client.
		var (
			client         *http.Client
			tracedClient   *nettrace.HTTPClient
			tracedReqName  string
			tracedReqDescr string
			dnsIsAvail     bool
			// Did the domain name resolution used IP address cached in /etc/hosts
			// (see pillar/cmd/nim/controllerdns.go)
			fromDNSCache bool
		)
		if withNetTracing {
			tracedClient, err = nettrace.NewHTTPClient(clientConfig, ctx.NetTraceOpts...)
			if err != nil {
				log.Errorf("SendOnIntf: nettrace.NewHTTPClient failed: %v\n", err)
				attempt.Err = err
				attempts = append(attempts, attempt)
				continue
			}
			client = tracedClient.Client
			var reqMethod string
			if isGet {
				reqMethod = "GET"
			} else {
				reqMethod = "POST"
			}
			tracedReqName = fmt.Sprintf("%s-%d", intf, retryCount)
			tracedReqDescr = fmt.Sprintf("%s %s via %s src IP %v",
				reqMethod, reqURL, intf, localAddr)
		} else {
			fromDNSCache = true // set to false by resolverDial below
			localTCPAddr := net.TCPAddr{IP: localAddr}
			localUDPAddr := net.UDPAddr{IP: localAddr}
			log.Tracef("Connecting to %s using intf %s source %v\n",
				reqURL, intf, localTCPAddr)
			resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
				log.Tracef("resolverDial %v %v", network, address)
				fromDNSCache = false
				dnsIP := net.ParseIP(strings.Split(address, ":")[0])
				// Note that port number is not looked at by skipNs.
				skip, reason := skipNs(dnsIP, 0)
				if skip {
					return nil, fmt.Errorf("skipped nameserver %v: %s", dnsIP, reason)
				}
				dnsIsAvail = true
				// XXX can we fallback to TCP? Would get a mismatched address if we do
				d := net.Dialer{LocalAddr: &localUDPAddr}
				return d.Dial(network, address)
			}
			r := net.Resolver{Dial: resolverDial, PreferGo: true, StrictErrors: false}
			d := net.Dialer{Resolver: &r, LocalAddr: &localTCPAddr}
			transport.DialContext = d.DialContext
			client = &http.Client{Transport: transport, Timeout: clientConfig.ReqTimeout}
		}

		// Execute the HTTP request.
		resp, err := client.Do(req)

		// Handle failed HTTP request (have not received HTTP response).
		if err != nil {
			if withNetTracing {
				if withPCAP {
					time.Sleep(pcapDelay)
				}
				netTrace, pcaps, err := tracedClient.GetTrace(tracedReqDescr)
				if err != nil {
					log.Error(err)
				} else {
					rv.TracedReqs = append(rv.TracedReqs, netdump.TracedNetRequest{
						RequestName:    tracedReqName,
						NetTrace:       netTrace,
						PacketCaptures: pcaps,
					})
					// Determine dnsIsAvail and fromDNSCache using Dial traces.
					fromDNSCache = true
					for _, dialTrace := range netTrace.Dials {
						if len(dialTrace.ResolverDials) > 0 {
							dnsIsAvail = true
							fromDNSCache = false
						}
						if len(dialTrace.SkippedNameservers) > 0 {
							fromDNSCache = false
						}
					}
				}
				if err = tracedClient.Close(); err != nil {
					log.Error(err)
				}
			}
			if !fromDNSCache && !dnsIsAvail {
				attempt.Err = &types.DNSNotAvail{IfName: intf}
			} else if cf, cert := isCertFailure(err); cf {
				// XXX can we ever get this from a proxy?
				// We assume we reached the controller here
				log.Errorf("client.Do fail: certFailure")
				rv.Status = types.SenderStatusCertInvalid
				if cert != nil {
					errStr := fmt.Sprintf("cert failure for Subject %s NotBefore %v NotAfter %v",
						cert.Subject, cert.NotBefore,
						cert.NotAfter)
					log.Error(errStr)
					cerr := errors.New(errStr)
					attempt.Err = cerr
				} else {
					attempt.Err = err
				}
			} else if isCertUnknownAuthority(err) {
				if usedProxy {
					log.Errorf("client.Do fail: CertUnknownAuthority with proxy")
					rv.Status = types.SenderStatusCertUnknownAuthorityProxy
				} else {
					log.Errorf("client.Do fail: CertUnknownAuthority") // could be transparent proxy
					rv.Status = types.SenderStatusCertUnknownAuthority
				}
				attempt.Err = err
			} else if isECONNREFUSED(err) {
				if usedProxy {
					// Must try other interfaces and configs
					// since the proxy might be broken.
					log.Errorf("client.Do fail: ECONNREFUSED with proxy")
				} else {
					log.Errorf("client.Do fail: ECONNREFUSED")
					rv.Status = types.SenderStatusRefused
				}
				attempt.Err = err
			} else if logutils.IsNoSuitableAddrErr(err) {
				// We get lots of these due to IPv6 link-local
				// only address on some interfaces.
				// Do not return as errors
				log.Warn("client.Do fail: No suitable address")
			} else if _, deadlineSet := workContext.Deadline(); deadlineSet {
				log.Errorf("client.Do global deadline: %v", err)
				attempt.Err = err
			} else {
				log.Errorf("client.Do (timeout %d) fail: %v",
					ctx.NetworkSendTimeout, err)
				attempt.Err = err
			}
			if attempt.Err != nil {
				attempts = append(attempts, attempt)
			}
			continue
		}

		// Read body (continue receiving body content over the network).
		contents, readErr := io.ReadAll(resp.Body)
		if err = resp.Body.Close(); err != nil {
			log.Error(err)
		}
		resp.Body = nil

		// Obtain traces and packet captured after the response body has been read.
		if withNetTracing {
			if withPCAP {
				time.Sleep(pcapDelay)
			}
			netTrace, pcaps, err := tracedClient.GetTrace(tracedReqDescr)
			if err != nil {
				log.Error(err)
			} else {
				rv.TracedReqs = append(rv.TracedReqs, netdump.TracedNetRequest{
					RequestName:    tracedReqName,
					NetTrace:       netTrace,
					PacketCaptures: pcaps,
				})
			}
			if err = tracedClient.Close(); err != nil {
				log.Error(err)
			}
		}

		// Handle failure to read HTTP response body.
		if readErr != nil {
			log.Errorf("ReadAll (timeout %d) failed: %s",
				ctx.NetworkSendTimeout, err)
			attempt.Err = err
			attempts = append(attempts, attempt)
			continue
		}
		resplen := int64(len(contents))

		if useTLS {
			connState := resp.TLS
			if connState == nil {
				errStr := "no TLS connection state"
				log.Errorln(errStr)
				attempt.Err = errors.New(errStr)
				attempts = append(attempts, attempt)
				// Inform ledmanager about broken cloud connectivity
				if !ctx.NoLedManager {
					utils.UpdateLedManagerConfig(log, types.LedBlinkRespWithoutTLS)
				}
				if ctx.FailureFunc != nil {
					ctx.FailureFunc(log, intf, reqURL, reqlen,
						resplen, false)
				}
				continue
			}

			if connState.OCSPResponse == nil ||
				!stapledCheck(log, connState) {

				if connState.OCSPResponse == nil {
					// XXX remove debug check
					log.Tracef("no OCSP response for %s\n",
						reqURL)
				}
				errStr := fmt.Sprintf("OCSP stapled check failed for %s",
					reqURL)

				//XXX OSCP is not implemented in cloud side so
				// commenting out it for now.
				if false {
					log.Errorln(errStr)
					// Inform ledmanager about broken cloud connectivity
					if !ctx.NoLedManager {
						utils.UpdateLedManagerConfig(log, types.LedBlinkRespWithoutOSCP)
					}
					if ctx.FailureFunc != nil {
						ctx.FailureFunc(log, intf, reqURL,
							reqlen, resplen, false)
					}
					attempt.Err = errors.New(errStr)
					attempts = append(attempts, attempt)
					continue
				}
				log.Traceln(errStr)
			}
		}
		// Even if we got e.g., a 404 we consider the connection a
		// success since we care about the connectivity to the cloud.
		totalTimeMillis := int64(time.Since(apiCallStartTime) / time.Millisecond)
		if ctx.SuccessFunc != nil {
			ctx.SuccessFunc(log, intf, reqURL, reqlen, resplen, totalTimeMillis, sessionResume)
		}

		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusNotModified, http.StatusNoContent:
			log.Tracef("SendOnIntf to %s, response %s\n", reqURL, resp.Status)
			rv.HTTPResp = resp
			rv.RespContents = contents
			return rv, nil
		default:
			maxlen := 256
			if maxlen > len(contents) {
				maxlen = len(contents)
			}

			hexdump := hex.Dump(bytes.TrimSpace(contents[:maxlen]))
			// remove trailing newline from hex.Dump
			hexdump = strings.TrimSuffix(hexdump, "\n")

			errStr := fmt.Sprintf("SendOnIntf to %s reqlen %d statuscode %d %s body:\n%s",
				reqURL, reqlen, resp.StatusCode,
				http.StatusText(resp.StatusCode), hexdump)
			// zedrouter probing sends 'http' to zedcloud server, expect to get status of 404, not an error
			if resp.StatusCode != http.StatusNotFound || ctx.AgentName != "zedrouter" {
				log.Errorln(errStr)
				log.Errorf("Got payload for status %s: %s",
					http.StatusText(resp.StatusCode), contents)
			}
			// Get caller to schedule a retry based on StatusCode
			rv.Status = types.SenderStatusNone
			rv.HTTPResp = resp
			return rv, errors.New(errStr)
		}
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(log, intf, reqURL, 0, 0, false)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %v",
		reqURL, attempts)
	log.Errorln(errStr)
	err = &SendError{
		Err:      errors.New(errStr),
		Attempts: attempts,
	}
	return rv, err
}

// SendLocal uses local routes to request the data
func SendLocal(ctx *ZedCloudContext, destURL string, intf string, ipSrc net.IP,
	reqlen int64, b *bytes.Buffer, reqContentType string) (*http.Response, []byte, error) {

	log := ctx.log
	var reqURL string
	var isGet bool

	if strings.HasPrefix(destURL, "http:") {
		reqURL = destURL
	} else {
		if strings.HasPrefix(destURL, "https:") {
			reqURL = destURL
		} else {
			reqURL = "https://" + destURL
		}
	}

	if b == nil {
		isGet = true
	}

	transport := &http.Transport{
		TLSClientConfig: ctx.TlsConfig,
	}
	// Since we recreate the transport on each call there is no benefit
	// to keeping the connections open.
	defer transport.CloseIdleConnections()

	// Try all addresses
	localTCPAddr := net.TCPAddr{IP: ipSrc}
	localUDPAddr := net.UDPAddr{IP: ipSrc}
	resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		log.Tracef("resolverDial %v %v", network, address)
		switch network {
		case "udp", "udp4", "udp6":
			d := net.Dialer{LocalAddr: &localUDPAddr}
			return d.Dial(network, address)
		case "tcp", "tcp4", "tcp6":
			d := net.Dialer{LocalAddr: &localTCPAddr}
			return d.Dial(network, address)
		default:
			return nil, fmt.Errorf("unsupported address type: %v", network)
		}
	}
	r := net.Resolver{Dial: resolverDial, PreferGo: true,
		StrictErrors: false}
	d := net.Dialer{Resolver: &r, LocalAddr: &localTCPAddr}
	transport.Dial = d.Dial

	client := &http.Client{Transport: transport}
	if ctx.NetworkSendTimeout != 0 {
		client.Timeout = time.Duration(ctx.NetworkSendTimeout) * time.Second
	}

	var req *http.Request
	var err error

	if b != nil {
		req, err = http.NewRequest("POST", reqURL, b)
	} else {
		req, err = http.NewRequest("GET", reqURL, nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("NewRequest failed %s", err)
	}

	// Add a per-request UUID to the HTTP Header
	// for traceability in the receiver
	id, err := uuid.NewV4()
	if err != nil {
		return nil, nil, fmt.Errorf("NewRequest NewV4 failed %s", err)
	}
	req.Header.Add("X-Request-Id", id.String())

	if reqContentType != "" {
		req.Header.Add("Content-Type", reqContentType)
	}

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			log.Tracef("Got RemoteAddr: %+v, LocalAddr: %+v\n",
				connInfo.Conn.RemoteAddr(),
				connInfo.Conn.LocalAddr())
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			log.Tracef("DNS Info: %+v\n", dnsInfo)
		},
		DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
			log.Tracef("DNS start: %+v\n", dnsInfo)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(),
		trace))
	log.Tracef("SendLocal: req method %s, isget %v, url %s",
		req.Method, isGet, reqURL)
	callStartTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		errStr := fmt.Sprintf("client.Do (timeout %d) fail: %v", ctx.NetworkSendTimeout, err)
		log.Errorln(errStr)
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(log, intf, reqURL, reqlen, 0, false)
		}
		return nil, nil, errors.New(errStr)
	}

	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		resp.Body = nil
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(log, intf, reqURL, reqlen, 0, false)
		}
		return nil, nil, fmt.Errorf("ReadAll failed: %v", err)
	}
	resp.Body.Close()
	resplen := int64(len(contents))
	resp.Body = nil

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNotModified, http.StatusNoContent:
		totalTimeMillis := int64(time.Since(callStartTime) / time.Millisecond)
		if ctx.SuccessFunc != nil {
			ctx.SuccessFunc(log, intf, reqURL, reqlen, resplen, totalTimeMillis, false)
		}
		log.Tracef("SendLocal to %s, response %s", reqURL, resp.Status)
		return resp, contents, nil
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(log, intf, reqURL, reqlen, resplen, false)
	}
	return resp, nil, fmt.Errorf("SendLocal to %s reqlen %d statuscode %d %s",
		reqURL, reqlen, resp.StatusCode,
		http.StatusText(resp.StatusCode))
}

// SendLocalProto is a variant of SendLocal which sends and receives proto messages.
func SendLocalProto(ctx *ZedCloudContext, destURL string, intf string, ipSrc net.IP,
	req proto.Message, resp proto.Message) (*http.Response, error) {
	var (
		reqBuf      *bytes.Buffer
		reqLen      int64
		contentType string
	)
	if req != nil {
		reqBytes, err := proto.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request message: %v", err)
		}
		reqBuf = bytes.NewBuffer(reqBytes)
		reqLen = int64(len(reqBytes))
		contentType = ContentTypeProto
	}
	httpResp, respBytes, err := SendLocal(ctx, destURL, intf, ipSrc, reqLen, reqBuf, contentType)
	if err != nil {
		return httpResp, err
	}
	if resp != nil && httpResp.StatusCode != http.StatusNoContent {
		if err := ValidateProtoContentType(destURL, httpResp); err != nil {
			return nil, fmt.Errorf("response header error: %s", err)
		}
		err := proto.Unmarshal(respBytes, resp)
		if err != nil {
			return nil, fmt.Errorf("response message unmarshalling failed: %v", err)
		}
	}
	return httpResp, nil
}

// ValidateProtoContentType checks content-type of what is supposed to be binary encoded proto message.
func ValidateProtoContentType(url string, r *http.Response) error {
	// No check Content-Type for empty response
	if r.ContentLength == 0 {
		return nil
	}
	var ctTypeStr = "Content-Type"

	ct := r.Header.Get(ctTypeStr)
	if ct == "" {
		return fmt.Errorf("no content-type")
	}
	mimeType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("get Content-type error")
	}
	switch mimeType {
	case ContentTypeProto:
		return nil
	default:
		return fmt.Errorf("content-type %s not supported",
			mimeType)
	}
}

func isCertFailure(err error) (bool, *x509.Certificate) {
	e0, ok := err.(*url.Error)
	if !ok {
		return false, nil
	}
	e1, ok := e0.Err.(x509.CertificateInvalidError)
	if !ok {
		return false, nil
	}
	return true, e1.Cert
}

func isCertUnknownAuthority(err error) bool {
	e0, ok := err.(*url.Error)
	if !ok {
		return false
	}
	_, ok = e0.Err.(x509.UnknownAuthorityError)
	if !ok {
		return false
	}
	return true
}

func isECONNREFUSED(err error) bool {
	e0, ok := err.(*url.Error)
	if !ok {
		return false
	}
	e1, ok := e0.Err.(*net.OpError)
	if !ok {
		return false
	}
	e2, ok := e1.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errno, ok := e2.Err.(syscall.Errno)
	if !ok {
		return false
	}
	return errno == syscall.ECONNREFUSED
}

// NewContext - return initialized cloud context
func NewContext(log *base.LogObject, opt ContextOptions) ZedCloudContext {
	ctx := ZedCloudContext{
		DeviceNetworkStatus: opt.DevNetworkStatus,
		NetworkSendTimeout:  opt.Timeout,
		TlsConfig:           opt.TLSConfig,
		V2API:               UseV2API(),
		DevSerial:           opt.Serial,
		DevSoftSerial:       opt.SoftSerial,
		AgentName:           opt.AgentName,
		NetTraceOpts:        opt.NetTraceOpts,
		log:                 log,
	}
	if opt.AgentMetrics != nil {
		ctx.FailureFunc = opt.AgentMetrics.RecordFailure
		ctx.SuccessFunc = opt.AgentMetrics.RecordSuccess
	}
	return ctx
}
