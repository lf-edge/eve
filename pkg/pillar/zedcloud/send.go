// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common code to communicate to zedcloud

package zedcloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
)

// ContentTypeProto : binary-encoded Protobuf content type
const ContentTypeProto = "application/x-proto-binary"

// ZedCloudContent is set up by NewContext() below
type ZedCloudContext struct {
	DeviceNetworkStatus *types.DeviceNetworkStatus
	TlsConfig           *tls.Config
	FailureFunc         func(log *base.LogObject, intf string, url string, reqLen int64, respLen int64, authFail bool)
	SuccessFunc         func(log *base.LogObject, intf string, url string, reqLen int64, respLen int64, timeSpent int64, resume bool)
	NoLedManager        bool // Don't call UpdateLedManagerConfig
	DevUUID             uuid.UUID
	DevSerial           string
	DevSoftSerial       string
	NetworkSendTimeout  uint32 // In seconds
	V2API               bool   // XXX Needed?
	AgentName           string // the agent process name
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
	deferredCtx           DeferredContext
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
}

var nilUUID = uuid.UUID{}

// Tries all interfaces (free first) until one succeeds. interation arg
// ensure load spreading across multiple interfaces.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// If bailOnHTTPErr is set we immediately return when we get a 4xx or 5xx error without trying the other interfaces.
// XXX also 1010 from CloudFlare?
// http.StatusForbidden is a special case i.e. even if bailOnHTTPErr is not set
// we bail out, since caller needs to be notified immediately for triggering any
// reaction based on this.
// We return a SenderResult enum for various error cases.
func SendOnAllIntf(ctx *ZedCloudContext, url string, reqlen int64, b *bytes.Buffer, iteration int, bailOnHTTPErr bool) (*http.Response, []byte, types.SenderResult, error) {

	log := ctx.log
	// If failed then try the non-free
	const allowProxy = true
	var errorList []error
	senderStatus := types.SenderStatusNone

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
		return nil, nil, senderStatus, err
	}
	for _, intf := range intfs {
		const useOnboard = false
		resp, contents, status, err := SendOnIntf(ctx, url, intf, reqlen, b, allowProxy, useOnboard)
		// this changes original boolean logic a little in V2 API, basically the last status non-zero enum would
		// overwrite the previous one in the loop if they are differ
		if status != types.SenderStatusNone {
			senderStatus = status
		}
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusServiceUnavailable:
				senderStatus = types.SenderStatusUpgrade
			case http.StatusNotFound:
				senderStatus = types.SenderStatusNotFound
			}
		}

		if bailOnHTTPErr && resp != nil &&
			resp.StatusCode >= 400 && resp.StatusCode < 600 {
			log.Functionf("sendOnAllIntf: for %s reqlen %d ignore code %d\n",
				url, reqlen, resp.StatusCode)
			return resp, nil, senderStatus, err
		}
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			return resp, nil, senderStatus, err
		}
		if err != nil {
			errorList = append(errorList, err)
			continue
		}
		return resp, contents, senderStatus, nil
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %v",
		url, errorList)
	log.Errorln(errStr)
	return nil, nil, senderStatus, errors.New(errStr)
}

// VerifyAllIntf
// We try with free interfaces in first iteration.
//      We test interfaces in sequence and as soon as we find the first working
//      interface, we stop. Other interfaces are not tested.
// If we find enough free interfaces through
// which cloud connectivity can be achieved, we won't test non-free interfaces.
// Otherwise we test non-free interfaces also.
// We return a bool remoteTemporaryFailure for the cases when we reached
// the controller but it is overloaded, or has certificate issues.
// Return Values:
//    success/Failure, remoteTemporaryFailure, error, intfStatusMap
//    If Failure,
//       remoteTemporaryFailure - indicates if it is a remote failure
//       error  - indicates details of Errors
//    IntfStatusMap - This status for each interface verified.
//      Includes entries for all interfaces that were tested.
//      If an intf is success, Error == "" Else - Set to appropriate Error
//      ErrorTime will always be set for the interface.
func VerifyAllIntf(ctx *ZedCloudContext,
	url string, successCount uint,
	iteration int) (bool, bool, types.IntfStatusMap, error) {

	log := ctx.log
	var intfSuccessCount uint
	const allowProxy = true
	var errorList []error

	remoteTemporaryFailure := false
	// Map of per-interface errors
	intfStatusMap := *types.NewIntfStatusMap()

	if successCount <= 0 {
		// No need to test. Just return true.
		return true, remoteTemporaryFailure, intfStatusMap, nil
	}

	// For non-mgmt (i.e. app-shared) ports, the presence of a valid IP address
	// along with DNS server and gateway is good enough for us to deem them as Success.
	// We do not test non-mgmt ports periodically, which makes it not possible to clear
	// any old errors on them. Here we check for presence of valid IP/DNS on non-mgmt
	// ports and accordingly mark their status.
	for _, port := range ctx.DeviceNetworkStatus.Ports {
		if port.IsMgmt {
			continue
		}

		if port.HasIPAndDNS() {
			intfStatusMap.RecordSuccess(port.IfName)
		}
	}

	intfs := types.GetMgmtPortsSortedCost(*ctx.DeviceNetworkStatus, iteration)
	if len(intfs) == 0 {
		err := fmt.Errorf("Can not connect to %s: No management interfaces",
			url)
		log.Error(err.Error())
		return false, remoteTemporaryFailure, intfStatusMap, err
	}
	for _, intf := range intfs {
		if intfSuccessCount >= successCount {
			// We have enough uplinks with cloud connectivity working.
			break
		}
		// This VerifyAllIntf() is called for "ping" url only, it does not have
		// return envelope verifying check. Thus below does not check other values of status.
		const useOnboard = false
		resp, _, status, err := SendOnIntf(ctx, url, intf, 0, nil, allowProxy, useOnboard)
		switch status {
		case types.SenderStatusRefused, types.SenderStatusCertInvalid:
			remoteTemporaryFailure = true
		}
		if resp != nil &&
			(resp.StatusCode >= http.StatusInternalServerError &&
				resp.StatusCode <= http.StatusNetworkAuthenticationRequired) {
			remoteTemporaryFailure = true
		}
		if err != nil {
			log.Errorf("Zedcloud un-reachable via interface %s: %s",
				intf, err)
			errorList = append(errorList, err)
			intfStatusMap.RecordFailure(intf, err.Error())
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated:
			log.Tracef("VerifyAllIntf: Zedcloud reachable via interface %s", intf)
			intfStatusMap.RecordSuccess(intf)
			intfSuccessCount++
		default:
			errStr := fmt.Sprintf("Uplink test FAILED via %s to URL %s with "+
				"status code %d and status %s",
				intf, url, resp.StatusCode, http.StatusText(resp.StatusCode))
			log.Errorln(errStr)
			err = errors.New(errStr)
			errorList = append(errorList, err)
			intfStatusMap.RecordFailure(intf, err.Error())
			continue
		}
	}
	if intfSuccessCount == 0 {
		err := fmt.Errorf("All test attempts to connect to %s failed: %v",
			url, errorList)
		log.Error(err.Error())
		return false, remoteTemporaryFailure, intfStatusMap, err
	}
	if intfSuccessCount < successCount {
		err := fmt.Errorf("Not enough Ports (%d) against required count %d"+
			" to reach %s; last failed with %v",
			intfSuccessCount, successCount, url, errorList)
		log.Error(err.Error())
		return false, remoteTemporaryFailure, intfStatusMap, err
	}
	log.Tracef("VerifyAllIntf: Verify done. intfStatusMap: %+v", intfStatusMap)
	return true, remoteTemporaryFailure, intfStatusMap, nil
}

// Tries all source addresses on interface until one succeeds.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// If we get a http response, we return that even if it was an error
// to allow the caller to look at StatusCode
// We return a SenderResult enum for various error cases.
// the controller but it is overloaded, or has certificate issues.
func SendOnIntf(ctx *ZedCloudContext, destURL string, intf string, reqlen int64, b *bytes.Buffer, allowProxy bool, useOnboard bool) (*http.Response, []byte, types.SenderResult, error) {

	log := ctx.log
	var reqUrl string
	var useTLS, isEdgenode, isGet, isCerts bool

	senderStatus := types.SenderStatusNone
	if strings.HasPrefix(destURL, "http:") {
		reqUrl = destURL
		useTLS = false
	} else {
		if strings.HasPrefix(destURL, "https:") {
			reqUrl = destURL
		} else {
			reqUrl = "https://" + destURL
		}
		useTLS = true
	}

	if strings.Contains(destURL, "/edgedevice/") {
		isEdgenode = true
		if strings.Contains(destURL, "/certs") {
			isCerts = true
		} else if strings.Contains(destURL, "/register") {
			useOnboard = true
		}
	}
	if b == nil {
		isGet = true
	}

	addrCount, err := types.CountLocalAddrAnyNoLinkLocalIf(*ctx.DeviceNetworkStatus, intf)
	if err != nil {
		return nil, nil, senderStatus, err
	}
	log.Tracef("Connecting to %s using intf %s #sources %d reqlen %d\n",
		reqUrl, intf, addrCount, reqlen)

	if addrCount == 0 {
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(log, intf, reqUrl, 0, 0, false)
		}
		// Determine a specific failure for intf
		link, err := netlink.LinkByName(intf)
		if err != nil {
			errStr := fmt.Sprintf("Link not found to connect to %s using intf %s: %s",
				reqUrl, intf, err)
			log.Traceln(errStr)
			return nil, nil, senderStatus, errors.New(errStr)
		}
		attrs := link.Attrs()
		if attrs.OperState != netlink.OperUp {
			errStr := fmt.Sprintf("Link not up to connect to %s using intf %s: %s",
				reqUrl, intf, attrs.OperState.String())
			log.Traceln(errStr)
			return nil, nil, senderStatus, errors.New(errStr)
		}
		errStr := fmt.Sprintf("No IP addresses to connect to %s using intf %s",
			reqUrl, intf)
		log.Traceln(errStr)
		return nil, nil, senderStatus, errors.New(errStr)
	}
	dnsServers := types.GetDNSServers(*ctx.DeviceNetworkStatus, intf)
	if len(dnsServers) == 0 {
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(log, intf, reqUrl, 0, 0, false)
		}
		errStr := fmt.Sprintf("No DNS servers to connect to %s using intf %s",
			reqUrl, intf)
		log.Traceln(errStr)
		return nil, nil, senderStatus, errors.New(errStr)
	}

	// Get the transport header with proxy information filled
	proxyUrl, err := LookupProxy(ctx.log, ctx.DeviceNetworkStatus, intf, reqUrl)
	var transport *http.Transport
	var usedProxy bool
	if err == nil && proxyUrl != nil && allowProxy {
		log.Tracef("sendOnIntf: For input URL %s, proxy found is %s",
			reqUrl, proxyUrl.String())
		usedProxy = true
		transport = &http.Transport{
			TLSClientConfig: ctx.TlsConfig,
			Proxy:           http.ProxyURL(proxyUrl),
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig: ctx.TlsConfig,
		}
	}
	// Since we recreate the transport on each call there is no benefit
	// to keeping the connections open.
	defer transport.CloseIdleConnections()

	var errorList []error
	var sessionResume bool

	// Try all addresses
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Error(err)
			return nil, nil, senderStatus, err
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		localUDPAddr := net.UDPAddr{IP: localAddr}
		log.Tracef("Connecting to %s using intf %s source %v\n",
			reqUrl, intf, localTCPAddr)
		resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Tracef("resolverDial %v %v", network, address)
			ip := net.ParseIP(strings.Split(address, ":")[0])
			for _, dnsServer := range dnsServers {
				if dnsServer != nil && dnsServer.Equal(ip) {
					// XXX can we fallback to TCP? Would get a mismatched address if we do
					d := net.Dialer{LocalAddr: &localUDPAddr}
					return d.Dial(network, address)
				}
			}
			return nil, fmt.Errorf("DNS server %s is from a different network, skipping",
				ip.String())
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
		var b2 *bytes.Buffer
		if ctx.V2API && isEdgenode && !isGet {
			b2, err = addAuthentication(ctx, b, useOnboard)
			if err != nil {
				log.Errorf("SendOnIntf: auth error %v\n", err)
				return nil, nil, senderStatus, err
			}
			reqlen = int64(b2.Len())
			log.Tracef("SendOnIntf: add auth for %s\n", reqUrl)
		} else {
			b2 = b
		}

		if b2 != nil {
			req, err = http.NewRequest("POST", reqUrl, b2)
		} else {
			req, err = http.NewRequest("GET", reqUrl, nil)
		}
		if err != nil {
			log.Errorf("NewRequest failed %s\n", err)
			errorList = append(errorList, err)
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
			errorList = append(errorList, err)
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
		req = req.WithContext(httptrace.WithClientTrace(req.Context(),
			trace))
		log.Tracef("SendOnIntf: req method %s, isget %v, url %s",
			req.Method, isGet, reqUrl)
		apiCallStartTime := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			if cf, cert := isCertFailure(err); cf {
				// XXX can we ever get this from a proxy?
				// We assume we reached the controller here
				log.Errorf("client.Do fail: certFailure")
				senderStatus = types.SenderStatusCertInvalid
				if cert != nil {
					errStr := fmt.Sprintf("cert failure for Subject %s NotBefore %v NotAfter %v",
						cert.Subject, cert.NotBefore,
						cert.NotAfter)
					log.Error(errStr)
					cerr := errors.New(errStr)
					errorList = append(errorList, cerr)
				} else {
					errorList = append(errorList, err)
				}
			} else if isCertUnknownAuthority(err) {
				if usedProxy {
					log.Errorf("client.Do fail: CertUnknownAuthority with proxy")
					senderStatus = types.SenderStatusCertUnknownAuthorityProxy
				} else {
					log.Errorf("client.Do fail: CertUnknownAuthority") // could be transparent proxy
					senderStatus = types.SenderStatusCertUnknownAuthority
				}
				errorList = append(errorList, err)
			} else if isECONNREFUSED(err) {
				if usedProxy {
					// Must try other interfaces and configs
					// since the proxy might be broken.
					log.Errorf("client.Do fail: ECONNREFUSED with proxy")
				} else {
					log.Errorf("client.Do fail: ECONNREFUSED")
					senderStatus = types.SenderStatusRefused
				}
				errorList = append(errorList, err)
			} else if logutils.IsNoSuitableAddrErr(err) {
				// We get lots of these due to IPv6 link-local
				// only address on some interfaces.
				// Do not return as errors
				log.Warn("client.Do fail: No suitable address")
			} else {
				log.Errorf("client.Do (timeout %d) fail: %v",
					ctx.NetworkSendTimeout, err)
				errorList = append(errorList, err)
			}
			continue
		}

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("ReadAll (timeout %d) failed: %s",
				ctx.NetworkSendTimeout, err)
			resp.Body.Close()
			resp.Body = nil
			errorList = append(errorList, err)
			continue
		}
		resp.Body.Close()
		resp.Body = nil
		resplen := int64(len(contents))

		if useTLS {
			connState := resp.TLS
			if connState == nil {
				errStr := "no TLS connection state"
				log.Errorln(errStr)
				err = errors.New(errStr)
				errorList = append(errorList, err)
				// Inform ledmanager about broken cloud connectivity
				if !ctx.NoLedManager {
					utils.UpdateLedManagerConfig(log, types.LedBlinkRespWithoutTLS)
				}
				if ctx.FailureFunc != nil {
					ctx.FailureFunc(log, intf, reqUrl, reqlen,
						resplen, false)
				}
				continue
			}

			if connState.OCSPResponse == nil ||
				!stapledCheck(log, connState) {

				if connState.OCSPResponse == nil {
					// XXX remove debug check
					log.Tracef("no OCSP response for %s\n",
						reqUrl)
				}
				errStr := fmt.Sprintf("OCSP stapled check failed for %s",
					reqUrl)

				//XXX OSCP is not implemented in cloud side so
				// commenting out it for now.
				if false {
					log.Errorln(errStr)
					// Inform ledmanager about broken cloud connectivity
					if !ctx.NoLedManager {
						utils.UpdateLedManagerConfig(log, types.LedBlinkRespWithoutOSCP)
					}
					if ctx.FailureFunc != nil {
						ctx.FailureFunc(log, intf, reqUrl,
							reqlen, resplen, false)
					}
					err = errors.New(errStr)
					errorList = append(errorList, err)
					continue
				}
				log.Traceln(errStr)
			}
		}
		// Even if we got e.g., a 404 we consider the connection a
		// success since we care about the connectivity to the cloud.
		totalTimeMillis := int64(time.Since(apiCallStartTime) / time.Millisecond)
		if ctx.SuccessFunc != nil {
			ctx.SuccessFunc(log, intf, reqUrl, reqlen, resplen, totalTimeMillis, sessionResume)
		}

		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusNotModified:
			log.Tracef("SendOnIntf to %s, response %s\n", reqUrl, resp.Status)

			var contents2 []byte
			var err error
			status := types.SenderStatusNone
			if ctx.V2API || isCerts { // /certs may not have set the V2API yet
				if resplen > 0 && checkMimeProtoType(resp) {
					contents2, status, err = verifyAuthentication(ctx, contents, isCerts)
					if err != nil {
						var envelopeErr bool
						if status == types.SenderStatusHashSizeError || status == types.SenderStatusAlgoFail {
							// server may not support V2 envelope
							envelopeErr = true
						}
						log.Errorf("SendOnIntf verify auth error %v, V2 %v, content len %d, url %s, extraStatus %v\n",
							err, !envelopeErr, len(contents), reqUrl, status) // XXX change to debug later
						if ctx.FailureFunc != nil {
							ctx.FailureFunc(log, intf, reqUrl, 0, 0, true)
						}
						return nil, nil, status, err
					}
					log.Tracef("SendOnIntf verify auth ok, len content/content2 %d/%d, url %s",
						len(contents), len(contents2), reqUrl)
				} else {
					contents2 = contents
				}
			} else {
				contents2 = contents
			}
			return resp, contents2, status, nil
		default:
			errStr := fmt.Sprintf("SendOnIntf to %s reqlen %d statuscode %d %s",
				reqUrl, reqlen, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			// zedrouter probing sends 'http' to zedcloud server, expect to get status of 404, not an error
			if resp.StatusCode != http.StatusNotFound || ctx.AgentName != "zedrouter" {
				log.Errorln(errStr)
			}
			log.Tracef("received response %v\n", resp)
			// Get caller to schedule a retry based on StatusCode
			return resp, nil, types.SenderStatusNone, errors.New(errStr)
		}
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(log, intf, reqUrl, 0, 0, false)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s using intf %s failed: %v",
		reqUrl, intf, errorList)
	log.Errorln(errStr)
	return nil, nil, senderStatus, errors.New(errStr)
}

//SendLocal uses local routes to request the data
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
		// XXX can we fallback to TCP? Would get a mismatched address if we do
		d := net.Dialer{LocalAddr: &localUDPAddr}
		return d.Dial(network, address)
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

	contents, err := ioutil.ReadAll(resp.Body)
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
		log:                 log,
	}
	if opt.AgentMetrics != nil {
		ctx.FailureFunc = opt.AgentMetrics.RecordFailure
		ctx.SuccessFunc = opt.AgentMetrics.RecordSuccess
	}
	return ctx
}
