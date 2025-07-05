// Copyright (c) 2017-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This package is used to establish connection to the controller/LOC/LPS
// and perform some HTTP(S) request or just check if connectivity is working.

package controllerconn

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

	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

// ContentTypeProto : binary-encoded Protobuf content type
const ContentTypeProto = "application/x-proto-binary"

// MaxWaitForRequests : upper limit of time to send requests
// independent of how many management interfaces and source IP addresses we try
const MaxWaitForRequests = 4 * time.Minute

// If the HTTP requests are being traced and PCAP is enabled, the function
// will wait just a little bit at the end of each request to capture all the packets.
// This overhead is introduced only when requests are traced, which
// is not very often (e.g. once per day).
const pcapDelay = 250 * time.Millisecond

// Client allows to establish connection to the controller/LOC/LPS
// and perform some HTTP(S) request or just check if connectivity is working.
// It takes care of proxy handling, TLS configuration, and network interface
// (source IP) selection. It provides methods to send requests over one or more
// interfaces while applying user-provided request options, such as desired
// HTTP response code handling, dry-running or network tracing.
type Client struct {
	// ClientOptions are exposed and can be changed (while Client is not being used)
	// even after the Client is created.
	ClientOptions
	log   *base.LogObject
	v2API bool

	prevCertPEM           [][]byte // cached proxy certs for later comparison
	onBoardCert           *tls.Certificate
	deviceCert            *tls.Certificate
	serverSigningCert     *x509.Certificate
	deviceCertHash        []byte
	onBoardCertHash       []byte
	serverSigningCertHash []byte
	onBoardCertBytes      []byte
}

// ClientOptions - options to be passed at NewClient.
type ClientOptions struct {
	// AgentName is the identifier for the agent using the client (used in logs and metrics).
	AgentName string
	// NetworkMonitor provides interface status details.
	// If provided, the client can determine more precise reasons why a particular
	// interface is not in a ready state for sending operations.
	NetworkMonitor netmonitor.NetworkMonitor
	// DeviceNetworkStatus supplies the current network configuration
	// (interfaces, addresses, etc.).
	// This is a mandatory argument for Send operations.
	DeviceNetworkStatus *types.DeviceNetworkStatus
	// TLSConfig defines TLS settings to use for HTTPS requests (e.g., certificates, ciphers).
	// Optional argument.
	TLSConfig *tls.Config
	// AgentMetrics is used to record send attempt metrics (successes, failures, etc.).
	AgentMetrics *AgentMetrics
	// NetworkSendTimeout is the timeout duration for sending HTTP requests.
	// Optional argument.
	NetworkSendTimeout time.Duration
	// NetworkDialTimeout is the timeout duration for establishing TCP connections.
	// Optional argument.
	NetworkDialTimeout time.Duration
	// DevUUID is the unique identifier of the device (used for authentication and traceability).
	DevUUID uuid.UUID
	// DevSerial is the hardware serial number of the device
	// (sent in HTTP headers for traceability).
	DevSerial string
	// DevSoftSerial is the software serial number of the device
	// (sent in HTTP headers for traceability).
	DevSoftSerial string
	// NetTraceOpts defines options for network tracing
	// (i.e. what to include in captured network traces).
	NetTraceOpts []nettrace.TraceOpt
	// ResolverCacheFunc is an optional function that can be used by Client to access
	// cached hostname resolutions and thus avoid calling lookups for already known IPs.
	ResolverCacheFunc ResolverCacheFunc
	// NoLedManager, if true, disables calls to UpdateLedManagerConfig.
	NoLedManager bool
}

// NewClient creates and returns a new Client instance configured with the provided
// ClientOptions. The returned Client manages connections to the controller,
// including proxy handling, TLS settings, and network interface selection.
func NewClient(log *base.LogObject, opts ClientOptions) *Client {
	return &Client{
		ClientOptions: opts,
		log:           log,
		v2API:         UseV2API(),
	}
}

// RequestOptions defines per-request configuration flags for controllerconn Client methods.
// These options control request behavior such as proxy usage, network tracing,
// log suppression, HTTP error handling, and dry-run mode.
type RequestOptions struct {
	// AllowProxy enables or disables the use of HTTP proxy when sending requests.
	AllowProxy bool
	// UseOnboard indicates that the request should be signed using the device's
	// onboarding certificate (as opposed to device certificate).
	UseOnboard bool
	// SuppressLogs lowers the log severity to Trace for all Send-related methods,
	// suppressing higher-severity log output.
	SuppressLogs bool
	// WithNetTracing enables network tracing for post-mortem troubleshooting purposes.
	WithNetTracing bool
	// DryRun performs all pre-send checks to verify interface readiness, but skips
	// actually sending the data.
	DryRun bool
	// BailOnHTTPErr causes SendOnAllIntf to stop trying other interfaces if a 4xx or 5xx
	// HTTP error is received from the server.
	BailOnHTTPErr bool
	// Accept4xxErrors allows VerifyAllIntf to treat 4xx HTTP status codes as a valid
	// indication of port connectivity.
	Accept4xxErrors bool
	// Iteration indicates the current round-robin position used by SendOnAllIntf
	// to spread load across multiple ports.
	Iteration int
	// Allow DNS server proxy listening on a loopback IP address.
	// This is currently used only for unit testing purposes to support host operating
	// systems with DNS proxy (such as systemd with systemd-resolved).
	AllowLoopbackDNS bool
}

// ResolverCacheFunc is a callback that the caller may provide to give access
// to cached resolved IP addresses. SendOnIntf will try to use the cached IPs
// to avoid unnecessary DNS lookups.
type ResolverCacheFunc func(hostname string) []types.CachedIP

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
	ControllerReachable bool // Main controller or LOC (in air-gap mode) is reachable
	RemoteTempFailure   bool
	IntfStatusMap       types.IntfStatusMap
	TracedReqs          []netdump.TracedNetRequest
}

var nilUUID = uuid.UUID{}

// UseV2API - check the controller cert file and use V2 api if it exist
// by default it is running V2, unless /config/Force-API-V1 file exists.
// Note: with controllerconn.Client created, it is more efficient to call Client.UseV2API().
func UseV2API() bool {
	_, err := os.Stat(types.APIV1FileName)
	if err == nil {
		return false
	}
	return true
}

// URLPathString - generate url for either v1 or v1 API path
func URLPathString(server string, isV2api bool, devUUID uuid.UUID, action string) string {
	var urlstr string
	if !isV2api {
		urlstr = server + "/api/v1/edgedevice/" + action
	} else {
		urlstr = server + "/api/v2/edgedevice/"
		if devUUID != nilUUID {
			urlstr = urlstr + "id/" + devUUID.String() + "/"
		}
		urlstr = urlstr + action
	}
	return urlstr
}

// ValidateProtoContentType checks content-type of what is supposed to be binary
// encoded proto message.
func ValidateProtoContentType(r *http.Response) error {
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

// GetContextForAllIntfFunctions returns context with timeout to use with AllIntf functions
// it uses 3 times of defined NetworkSendTimeout
// and limits max wait up to MaxWaitForRequests
func (c *Client) GetContextForAllIntfFunctions() (context.Context, context.CancelFunc) {
	maxWaitDuration := c.NetworkSendTimeout * 3
	if maxWaitDuration == 0 {
		maxWaitDuration = MaxWaitForRequests
		c.log.Warnf("GetContextForAllIntfFunctions: provided maxWaitDuration equals 0, "+
			"will use %d", MaxWaitForRequests)
	}
	if maxWaitDuration > MaxWaitForRequests {
		c.log.Functionf("GetContextForAllIntfFunctions: maxWaitDuration %d is more "+
			"than limit, will use %d", maxWaitDuration, MaxWaitForRequests)
		maxWaitDuration = MaxWaitForRequests
	}
	return context.WithTimeout(context.Background(), maxWaitDuration)
}

// UsingV2API returns true if the client is set to use EVE API version 2.
func (c *Client) UsingV2API() bool {
	return c.v2API
}

// SendOnAllIntf tries all interfaces (free first) until one succeeds.
// RequestOptions.Iteration argument ensure load spreading across multiple interfaces.
// Returns response for first success. Caller can not use SendRetval.HTTPResp.Body but can
// use SendRetval.RespContents byte slice.
// If RequestOptions.BailOnHTTPErr is set we immediately return when we get a 4xx or 5xx
// error without trying the other interfaces.
// XXX also 1010 from CloudFlare?
// http.StatusForbidden is a special case, i.e. even if RequestOptions.BailOnHTTPErr
// is not set we bail out, since caller needs to be notified immediately for triggering
// any reaction based on this.
// We return a SendRetval.Status enum for various error cases.
// The caller is responsible to handle any required AuthContainer by calling
// RemoveAndVerifyAuthContainer.
func (c *Client) SendOnAllIntf(ctx context.Context, url string, b *bytes.Buffer,
	opts RequestOptions) (SendRetval, error) {

	var attempts []SendAttempt
	combinedRV := SendRetval{ReqURL: url}

	errorLog := c.log.Errorf
	warnLog := c.log.Warnf
	if opts.SuppressLogs {
		errorLog = c.log.Tracef
		warnLog = c.log.Tracef
	}

	// reqlen is used only for logging purposes.
	var reqlen int
	if b != nil {
		reqlen = b.Len()
	}

	intfs := types.GetMgmtPortsSortedCostWithoutFailed(
		*c.DeviceNetworkStatus, opts.Iteration)
	if len(intfs) == 0 {
		// This can happen during onboarding etc. and the failed status
		// might be updated infrequently by nim
		warnLog("All management ports are marked failed; trying all")
		intfs = types.GetMgmtPortsSortedCost(*c.DeviceNetworkStatus, opts.Iteration)
	}
	if len(intfs) == 0 {
		err := fmt.Errorf("cannot connect to %s: No management interfaces", url)
		errorLog(err.Error())
		return combinedRV, err
	}

	for _, intf := range intfs {
		sendOnIntfOpts := opts
		sendOnIntfOpts.AllowProxy = true
		sendOnIntfOpts.UseOnboard = false
		rv, err := c.SendOnIntf(ctx, url, intf, b, sendOnIntfOpts)
		combinedRV.TracedReqs = append(combinedRV.TracedReqs, rv.TracedReqs...)
		// This changes original boolean logic a little in V2 API.
		// Basically the last status non-zero enum would overwrite the previous one
		// in the loop if they differ.
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

		if opts.BailOnHTTPErr && rv.HTTPResp != nil &&
			rv.HTTPResp.StatusCode >= 400 && rv.HTTPResp.StatusCode < 600 {
			c.log.Tracef("SendOnAllIntf: for %s reqlen %d ignore code %d",
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
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %s",
		url, c.describeSendAttempts(attempts))
	errorLog(errStr)
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
// the controller, but it is overloaded or has certificate issues.
// Return Values: VerifyRetval, error
//   - If Failure,
//     VerifyRetval.RemoteTempFailure: indicates if it is a remote failure
//     error: indicates details of Errors
//   - VerifyRetval.IntfStatusMap - Status for each verified interface.
//     Includes entries for all interfaces that were tested.
//     If an intf is success, Error == "", else it contains error message
//     ErrorTime will always be set for the interface.
func (c *Client) VerifyAllIntf(ctx context.Context,
	url string, requiredSuccessCount uint, opts RequestOptions) (VerifyRetval, error) {

	var (
		verifyRV         VerifyRetval
		intfSuccessCount uint
		attempts         []SendAttempt
	)

	errorLog := c.log.Errorf
	if opts.SuppressLogs {
		errorLog = c.log.Tracef
	}

	// Map of per-interface errors
	verifyRV.IntfStatusMap = *types.NewIntfStatusMap()

	// This will be set to the cost of the most expensive mgmt interface
	// that was needed to achieve requiredSuccessCount.
	var workingMgmtCost uint8

	// A small set of verification checks is run even for L2-only interfaces
	// (link presence, admin status, etc.)
	intfs := types.GetAllPortsSortedCost(*c.DeviceNetworkStatus, false, opts.Iteration)

	// Always iterate through *all* uplink interfaces, never break out of the loop.
	// However, some of the interfaces might be verified only using local checks
	// (aka dry-run).
	for _, intf := range intfs {
		portStatus := types.GetPort(*c.DeviceNetworkStatus, intf)
		if portStatus.InvalidConfig {
			// Do not try to test port with invalid config.
			// Otherwise, the test would fail and the parsing error would get overwritten.
			continue
		}
		// If we have enough uplinks with controller connectivity, then the remaining
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
		sendOnIntfOpts := opts
		sendOnIntfOpts.DryRun = dryRun
		sendOnIntfOpts.AllowProxy = true
		// This VerifyAllIntf() is called for "ping" url only, it does
		// not have return envelope verifying check after the call nor
		// does it check other values of status.
		sendOnIntfOpts.UseOnboard = false
		rv, err := c.SendOnIntf(ctx, url, intf, nil, sendOnIntfOpts)
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
			var noAddrErr *types.IPAddrNotAvailError
			if errors.As(err, &noAddrErr) {
				// Interface link exists and is UP but does not have any IP address assigned.
				// This is expected for L2-only interfaces and also for app-shared interfaces
				// configured with DhcpTypeNone.
				if !portStatus.IsL3Port ||
					(!portStatus.IsMgmt && portStatus.Dhcp == types.DhcpTypeNone) {
					verifyRV.IntfStatusMap.RecordSuccess(intf)
					continue
				}
			}
			var noDNSErr *types.DNSNotAvailError
			if errors.As(err, &noDNSErr) {
				// The interface link is up and an IP address is assigned, but no DNS
				// server is configured. This is not necessarily a failure for an app-shared
				// interface. Some applications might not require DNS for external hostnames
				// and may only use internal DNS servers to resolve the names of other apps
				// running on the same device. However, we should still issue a warning about
				// this potential issue.
				if !portStatus.IsMgmt {
					verifyRV.IntfStatusMap.RecordSuccessWithWarning(intf, err.Error())
					continue
				}
			}
			errorLog("Controller un-reachable via interface %s: %s", intf, err)
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
			// Continue below the switch to record success.
			break
		default:
			if opts.Accept4xxErrors &&
				rv.HTTPResp.StatusCode >= 400 && rv.HTTPResp.StatusCode < 500 {
				// Continue below the switch to record success.
				break
			} else {
				err = fmt.Errorf("controller with URL %s returned status code %d (%s)",
					url, rv.HTTPResp.StatusCode, http.StatusText(rv.HTTPResp.StatusCode))
				errorLog("Uplink test FAILED via %s: %v", intf, err)
				attempts = append(attempts, SendAttempt{
					Err:    err,
					IfName: intf,
				})
				verifyRV.IntfStatusMap.RecordFailure(intf, err.Error())
				continue
			}
		}

		c.log.Tracef("VerifyAllIntf: Controller reachable via interface %s", intf)
		verifyRV.IntfStatusMap.RecordSuccess(intf)
		if intfSuccessCount < requiredSuccessCount {
			workingMgmtCost = portStatus.Cost
		}
		intfSuccessCount++
	}
	if requiredSuccessCount <= 0 {
		// No need for working mgmt interface. Just return true.
		verifyRV.ControllerReachable = true
		return verifyRV, nil
	}
	if len(types.GetMgmtPortsAny(*c.DeviceNetworkStatus, 0)) == 0 {
		err := fmt.Errorf("cannot connect to %s: No management interfaces", url)
		errorLog(err.Error())
		return verifyRV, err
	}
	if intfSuccessCount == 0 {
		errStr := fmt.Sprintf("All attempts to connect to %s failed: %s",
			url, c.describeSendAttempts(attempts))
		errorLog(errStr)
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
		errorLog(errStr)
		err := &SendError{
			Err:      errors.New(errStr),
			Attempts: attempts,
		}
		return verifyRV, err
	}
	verifyRV.ControllerReachable = true
	c.log.Tracef("VerifyAllIntf: Verify done. intfStatusMap: %+v",
		verifyRV.IntfStatusMap)
	return verifyRV, nil
}

type tracedReq struct {
	client         *nettrace.HTTPClient
	reqName        string
	reqDescription string
}

// SendOnIntf tries all source addresses on the given interface until one succeeds.
// Returns the first successful response. The caller should not use SendRetval.HTTPResp.Body,
// but can safely use SendRetval.RespContents.
// If an HTTP response is received (even with an error status), it is returned to allow
// the caller to inspect StatusCode.
// SendRetval.Status helps the caller distinguish between different failure types,
// e.g., controller accessible but overloaded, or certificate issues.
// The caller must handle any AuthContainer (e.g., via RemoveAndVerifyAuthContainer).
// Set RequestOptions.DryRun to perform pre-send checks without actually sending data.
func (c *Client) SendOnIntf(ctx context.Context, destURL string, intf string,
	b *bytes.Buffer, opts RequestOptions) (SendRetval, error) {

	errorLog := c.log.Errorf
	warnLog := c.log.Warnf
	if opts.SuppressLogs {
		errorLog = c.log.Tracef
		warnLog = c.log.Tracef
	}

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

	useOnboard := opts.UseOnboard
	if strings.Contains(destURL, "/edgedevice/") {
		isEdgenode = true
		if strings.Contains(destURL, "/register") {
			useOnboard = true
		}
	}
	if b == nil {
		isGet = true
	}

	if err := c.verifyIntfState(intf, reqURL, opts); err != nil {
		return rv, err
	}

	clientConfig, proxyUsed, err := c.prepareHTTPClientConfig(intf, reqURL, opts)
	if err != nil {
		errorLog(err.Error())
		return rv, err
	}

	if opts.DryRun {
		// Do not actually send the request.
		// Return nil response and nil error back to the caller.
		return rv, nil
	}

	var attempts []SendAttempt
	var sessionResume bool
	transport := &http.Transport{
		TLSClientConfig:   clientConfig.TLSClientConfig,
		Proxy:             clientConfig.Proxy,
		DisableKeepAlives: clientConfig.DisableKeepAlive,
	}
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			c.log.Tracef("Got RemoteAddr: %+v, LocalAddr: %+v\n",
				connInfo.Conn.RemoteAddr(),
				connInfo.Conn.LocalAddr())
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			c.log.Tracef("DNS Info: %+v\n", dnsInfo)
		},
		DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
			c.log.Tracef("DNS start: %+v\n", dnsInfo)
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			sessionResume = state.DidResume
		},
	}

	// Try all IP addresses.
	// verifyIntfState already checked that portStatus is not nil.
	portStatus := c.DeviceNetworkStatus.LookupPortByIfName(intf)
	for i, addr := range portStatus.AddrInfoList {
		srcIP := addr.Addr
		if srcIP.IsLinkLocalUnicast() {
			continue
		}
		clientConfig.SourceIP = srcIP
		attempt := SendAttempt{
			IfName:     intf,
			SourceAddr: srcIP,
		}

		// Prepare the HTTP request.
		req, reqlen, err := c.prepareHTTPRequest(reqURL, b, isEdgenode, isGet, useOnboard)
		if err != nil {
			errorLog(err.Error())
			attempt.Err = err
			attempts = append(attempts, attempt)
			continue
		}
		req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

		// Prepare the HTTP client.
		var client *http.Client
		var tracing tracedReq
		if opts.WithNetTracing {
			// Note that resolver cache is not supported when network tracing is enabled.
			// This is actually intentional - when tracing, we want to run normal hostname
			// IP resolution and collect traces of DNS queries.
			tracing.client, err = nettrace.NewHTTPClient(clientConfig, c.NetTraceOpts...)
			if err != nil {
				// Log error and revert to running send operation without tracing.
				errorLog("SendOnIntf: nettrace.NewHTTPClient failed: %v", err)
				opts.WithNetTracing = false
				warnLog("Running SendOnIntf (req: %s) without network tracing", reqURL)
			} else {
				client = tracing.client.Client
				var reqMethod string
				if isGet {
					reqMethod = "GET"
				} else {
					reqMethod = "POST"
				}
				tracing.reqName = fmt.Sprintf("%s-%d", intf, i)
				tracing.reqDescription = fmt.Sprintf("%s %s via %s src IP %v",
					reqMethod, reqURL, intf, srcIP)
			}
		}
		if !opts.WithNetTracing {
			dialer := &DialerWithResolverCache{
				log:              c.log,
				ifName:           intf,
				localIP:          srcIP,
				skipNs:           clientConfig.SkipNameserver,
				timeout:          clientConfig.TCPHandshakeTimeout,
				resolverCache:    c.ResolverCacheFunc,
				allowLoopbackDNS: opts.AllowLoopbackDNS,
			}
			transport.DialContext = dialer.DialContext
			client = &http.Client{Transport: transport, Timeout: clientConfig.ReqTimeout}
		}

		// Execute the HTTP request.
		apiCallStartTime := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			processedErr := c.handleHTTPReqFailure(
				err, opts, intf, proxyUsed, &rv, &tracing)
			if processedErr != nil {
				attempt.Err = processedErr
				attempts = append(attempts, attempt)
			}
			continue
		}

		// Read body (continue receiving body content over the network).
		contents, readErr := io.ReadAll(resp.Body)
		if err = resp.Body.Close(); err != nil {
			errorLog(err.Error())
		}
		resp.Body = nil

		// Obtain traces and packet captured after the response body has been read.
		if opts.WithNetTracing {
			if c.nettraceWithPCAP() {
				time.Sleep(pcapDelay)
			}
			netTrace, pcaps, err := tracing.client.GetTrace(tracing.reqDescription)
			if err != nil {
				errorLog(err.Error())
			} else {
				rv.TracedReqs = append(rv.TracedReqs, netdump.TracedNetRequest{
					RequestName:    tracing.reqName,
					NetTrace:       netTrace,
					PacketCaptures: pcaps,
				})
			}
			if err = tracing.client.Close(); err != nil {
				errorLog(err.Error())
			}
		}

		// Handle failure to read HTTP response body.
		if readErr != nil {
			errorLog("ReadAll (timeout %d) failed: %s", c.NetworkSendTimeout, readErr)
			attempt.Err = readErr
			attempts = append(attempts, attempt)
			continue
		}
		resplen := int64(len(contents))

		// Check TLS-related errors.
		if useTLS {
			connState := resp.TLS
			if connState == nil {
				errStr := "no TLS connection state"
				errorLog(errStr)
				attempt.Err = errors.New(errStr)
				attempts = append(attempts, attempt)
				// Inform ledmanager about broken controller connectivity
				if !c.NoLedManager {
					utils.UpdateLedManagerConfig(c.log, types.LedBlinkRespWithoutTLS)
				}
				if c.AgentMetrics != nil {
					c.AgentMetrics.RecordFailure(c.log, intf, reqURL, reqlen,
						resplen, false)
				}
				continue
			}

			if ok, err := c.stapledCheck(connState); !ok {
				// OCSP is not implemented in the controller; log this error at the lowest
				// severity level for now.
				c.log.Tracef("OCSP stapled check failed for %s: %s", reqURL, err)
			}
		}

		// Even if we got e.g., a 404 we consider the connection a
		// success since we care about the connectivity to the controller.
		totalTimeMillis := int64(time.Since(apiCallStartTime) / time.Millisecond)
		if c.AgentMetrics != nil {
			c.AgentMetrics.RecordSuccess(
				c.log, intf, reqURL, reqlen, resplen, totalTimeMillis, sessionResume)
		}

		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusNotModified, http.StatusNoContent:
			c.log.Tracef("SendOnIntf to %s, response %s\n", reqURL, resp.Status)
			rv.HTTPResp = resp
			rv.RespContents = contents
			return rv, nil
		default:
			// Get caller to schedule a retry based on StatusCode
			rv.Status = types.SenderStatusNone
			rv.HTTPResp = resp

			if opts.Accept4xxErrors && (resp.StatusCode >= 400 && resp.StatusCode < 500) {
				return rv, nil
			}

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

			errorLog(errStr)
			errorLog("Got payload for status %s: %s",
				http.StatusText(resp.StatusCode), contents)
			return rv, errors.New(errStr)
		}
	}

	if c.AgentMetrics != nil {
		c.AgentMetrics.RecordFailure(c.log, intf, reqURL, 0, 0, false)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %s",
		reqURL, c.describeSendAttempts(attempts))
	errorLog(errStr)
	err = &SendError{
		Err:      errors.New(errStr),
		Attempts: attempts,
	}
	return rv, err
}

func (c *Client) nettraceWithPCAP() bool {
	for _, traceOpt := range c.NetTraceOpts {
		if _, ok := traceOpt.(*nettrace.WithPacketCapture); ok {
			return true
		}
	}
	return false
}

// verifyIntfState verifies that the specified interface has usable addresses
// and is in an operational state (e.g., link is up). Returns an error describing
// the specific failure, if any. Records failures in AgentMetrics unless in dryRun mode.
func (c *Client) verifyIntfState(intf, reqURL string, opts RequestOptions) error {
	addrCount, err := types.CountLocalAddrAnyNoLinkLocalIf(*c.DeviceNetworkStatus, intf)
	if err == nil && addrCount > 0 {
		return nil
	}

	if c.AgentMetrics != nil && !opts.DryRun {
		c.AgentMetrics.RecordFailure(c.log, intf, reqURL, 0, 0, false)
	}

	// Determine a specific failure for the interface:

	if intf == "" {
		return errors.New("missing interface name")
	}
	portStatus := c.DeviceNetworkStatus.LookupPortByIfName(intf)
	if portStatus == nil {
		return fmt.Errorf("missing port status for interface %s", intf)
	}
	if c.NetworkMonitor == nil {
		if addrCount == 0 {
			return &types.IPAddrNotAvailError{IfName: intf}
		}
		return err
	}
	ifIndex, exists, err2 := c.NetworkMonitor.GetInterfaceIndex(intf)
	if err2 != nil {
		return fmt.Errorf("failed to get link for interface %s: %w", intf, err2)
	}
	if !exists {
		return fmt.Errorf("link not found for interface %s", intf)
	}
	ifAttrs, err2 := c.NetworkMonitor.GetInterfaceAttrs(ifIndex)
	if err2 != nil {
		return fmt.Errorf("failed to get interface %s attributes: %w", intf, err2)
	}
	if !ifAttrs.LowerUp {
		return fmt.Errorf("link not up for interface %s", intf)
	}
	if addrCount == 0 {
		return &types.IPAddrNotAvailError{IfName: intf}
	}
	return err
}

// prepareHTTPClientConfig builds an HTTP client configuration for sending a request
// on the specified interface, including proxy settings and DNS server filter.
// Returns the client config, whether a proxy is being used, and any error.
func (c *Client) prepareHTTPClientConfig(intf, reqURL string,
	opts RequestOptions) (clientCfg nettrace.HTTPClientCfg, proxyUsed bool, err error) {
	clientCfg = nettrace.HTTPClientCfg{
		// Since we recreate the transport on each call there is no benefit
		// to keeping the connections open.
		DisableKeepAlive:    true,
		ReqTimeout:          c.NetworkSendTimeout,
		TCPHandshakeTimeout: c.NetworkDialTimeout,
		TLSClientConfig:     c.TLSConfig,
	}

	// Get the transport header with proxy information filled
	proxyURL, err := LookupProxy(c.log, c.DeviceNetworkStatus, intf, reqURL)
	var proxyWithIP bool
	if err == nil && proxyURL != nil && opts.AllowProxy {
		proxyUsed = true
		host := strings.Split(proxyURL.Host, ":")[0]
		proxyWithIP = net.ParseIP(host) != nil
		clientCfg.Proxy = http.ProxyURL(proxyURL)
	}

	// Note that if an explicit HTTPS proxy addressed by an IP address is used,
	// EVE does not need to perform any domain name resolution.
	// The resolution of the controller's domain name is performed by the proxy,
	// not by EVE.
	dnsServers := types.GetDNSServers(*c.DeviceNetworkStatus, intf)
	if len(dnsServers) == 0 && !proxyWithIP {
		if c.AgentMetrics != nil && !opts.DryRun {
			c.AgentMetrics.RecordFailure(c.log, intf, reqURL, 0, 0, false)
		}
		err = &types.DNSNotAvailError{
			IfName: intf,
		}
		return clientCfg, proxyUsed, err
	}

	clientCfg.SkipNameserver = func(ip net.IP, _ uint16) (bool, string) {
		for _, dnsServer := range dnsServers {
			if dnsServer != nil && dnsServer.Equal(ip) {
				return false, ""
			}
		}
		return true, "DNS server is from a different network"
	}
	return clientCfg, proxyUsed, nil
}

// prepareHTTPRequest creates an HTTP request (GET or POST) with appropriate headers,
// including authentication, content type, and tracing IDs. Returns the request,
// its length, and any error.
func (c *Client) prepareHTTPRequest(reqURL string, b *bytes.Buffer,
	isEdgenode, isGet, useOnboard bool) (req *http.Request, reqlen int64, err error) {
	var b2 *bytes.Buffer
	if c.v2API && isEdgenode && !isGet {
		b2, err = c.AddAuthentication(b, useOnboard)
		if err != nil {
			return nil, 0, err
		}
	} else {
		b2 = b
	}
	if b2 != nil {
		reqlen = int64(b2.Len())
	}

	if b2 != nil {
		req, err = http.NewRequest("POST", reqURL, b2)
	} else {
		req, err = http.NewRequest("GET", reqURL, nil)
	}
	if err != nil {
		return nil, 0, err
	}

	if b2 != nil {
		req.Header.Add("Content-Type", ContentTypeProto)
	}
	// Add a per-request UUID to the HTTP Header
	// for traceability in the controller
	id, err := uuid.NewV4()
	if err != nil {
		return nil, 0, err
	}
	req.Header.Add("X-Request-Id", id.String())
	if c.DevUUID == nilUUID {
		// Also add Device Serial Number to the HTTP Header for initial traceability
		devSerialNum := c.DevSerial
		if devSerialNum != "" {
			req.Header.Add("X-Serial-Number", devSerialNum)
		}
		// Add Software Serial Number to the HTTP Header for initial traceability
		devSoftSerial := c.DevSoftSerial
		if devSoftSerial != "" {
			req.Header.Add("X-Soft-Serial", devSoftSerial)
		}
		c.log.Tracef("Serial-Numbers, serial: %s, soft-serial %s",
			devSerialNum, devSoftSerial)
	}

	return req, reqlen, nil
}

// handleHTTPReqFailure analyzes and logs HTTP request failures, updates the SendRetval
// status based on the type of error (e.g., cert failure, connection refused),
// and appends any network tracing information. Returns a processed error.
func (c *Client) handleHTTPReqFailure(reqErr error, reqOpts RequestOptions,
	intf string, proxyUsed bool, rv *SendRetval, tracing *tracedReq) (processedErr error) {

	errorLog := c.log.Errorf
	warnLog := c.log.Warnf
	if reqOpts.SuppressLogs {
		errorLog = c.log.Tracef
		warnLog = c.log.Tracef
	}

	if reqOpts.WithNetTracing {
		if c.nettraceWithPCAP() {
			time.Sleep(pcapDelay)
		}
		netTrace, pcaps, err := tracing.client.GetTrace(tracing.reqDescription)
		if err != nil {
			errorLog(err.Error())
		} else {
			rv.TracedReqs = append(rv.TracedReqs, netdump.TracedNetRequest{
				RequestName:    tracing.reqName,
				NetTrace:       netTrace,
				PacketCaptures: pcaps,
			})
			// Find out if dial failed because there was no DNS server available.
			var calledResolver, dnsWasAvail bool
			for _, dialTrace := range netTrace.Dials {
				if len(dialTrace.ResolverDials) > 0 {
					dnsWasAvail = true
					calledResolver = true
				}
				if len(dialTrace.SkippedNameservers) > 0 {
					calledResolver = true
				}
			}
			if calledResolver && !dnsWasAvail {
				reqErr = &types.DNSNotAvailError{IfName: intf}
			}
		}
		if err = tracing.client.Close(); err != nil {
			errorLog(err.Error())
		}
	}

	if cf, cert := c.isCertFailure(reqErr); cf {
		// XXX can we ever get this from a proxy?
		// We assume we reached the controller here
		errorLog("client.Do fail: certFailure")
		rv.Status = types.SenderStatusCertInvalid
		if cert != nil {
			errStr := fmt.Sprintf("cert failure for Subject %s NotBefore %v NotAfter %v",
				cert.Subject, cert.NotBefore,
				cert.NotAfter)
			errorLog(errStr)
			return errors.New(errStr)
		}
		return reqErr
	}
	if c.isCertUnknownAuthority(reqErr) {
		if proxyUsed {
			errorLog("client.Do fail: CertUnknownAuthority with proxy")
			rv.Status = types.SenderStatusCertUnknownAuthorityProxy
		} else {
			// could be transparent proxy
			errorLog("client.Do fail: CertUnknownAuthority")
			rv.Status = types.SenderStatusCertUnknownAuthority
		}
		return reqErr
	}
	if c.isECONNREFUSED(reqErr) {
		if proxyUsed {
			// Must try other interfaces and configs
			// since the proxy might be broken.
			errorLog("client.Do fail: ECONNREFUSED with proxy")
		} else {
			errorLog("client.Do fail: ECONNREFUSED")
			rv.Status = types.SenderStatusRefused
		}
		return reqErr
	}
	if logutils.IsNoSuitableAddrErr(reqErr) {
		// We get lots of these due to IPv6 link-local
		// only address on some interfaces.
		// Do not return as errors
		warnLog("client.Do fail: No suitable address")
		return nil
	}
	errorLog("client.Do (timeout %d) fail: %v", c.NetworkSendTimeout, reqErr)
	return reqErr
}

// SendLocal performs HTTP request towards an application deployed on the edge device.
func (c *Client) SendLocal(destURL string, intf string, ipSrc net.IP,
	b *bytes.Buffer, reqContentType string) (*http.Response, []byte, error) {

	var reqURL string
	var isGet bool
	var reqlen int64

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
	} else {
		reqlen = int64(b.Len())
	}

	transport := &http.Transport{
		TLSClientConfig: c.TLSConfig,
	}
	// Since we recreate the transport on each call there is no benefit
	// to keeping the connections open.
	defer transport.CloseIdleConnections()
	dialer := &DialerWithResolverCache{
		log:           c.log,
		ifName:        intf,
		localIP:       ipSrc,
		timeout:       c.NetworkDialTimeout,
		resolverCache: c.ResolverCacheFunc,
	}
	transport.DialContext = dialer.DialContext

	client := &http.Client{Transport: transport, Timeout: c.NetworkSendTimeout}

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
			c.log.Tracef("Got RemoteAddr: %+v, LocalAddr: %+v\n",
				connInfo.Conn.RemoteAddr(),
				connInfo.Conn.LocalAddr())
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			c.log.Tracef("DNS Info: %+v\n", dnsInfo)
		},
		DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
			c.log.Tracef("DNS start: %+v\n", dnsInfo)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(),
		trace))
	c.log.Tracef("SendLocal: req method %s, isget %v, url %s",
		req.Method, isGet, reqURL)
	callStartTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		errStr := fmt.Sprintf("client.Do (timeout %d) fail: %v", c.NetworkSendTimeout, err)
		c.log.Errorln(errStr)
		if c.AgentMetrics != nil {
			c.AgentMetrics.RecordFailure(c.log, intf, reqURL, reqlen, 0, false)
		}
		return nil, nil, errors.New(errStr)
	}

	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		resp.Body = nil
		if c.AgentMetrics != nil {
			c.AgentMetrics.RecordFailure(c.log, intf, reqURL, reqlen, 0, false)
		}
		return nil, nil, fmt.Errorf("ReadAll failed: %v", err)
	}
	resp.Body.Close()
	resplen := int64(len(contents))
	resp.Body = nil

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNotModified, http.StatusNoContent:
		totalTimeMillis := int64(time.Since(callStartTime) / time.Millisecond)
		if c.AgentMetrics != nil {
			c.AgentMetrics.RecordSuccess(
				c.log, intf, reqURL, reqlen, resplen, totalTimeMillis, false)
		}
		c.log.Tracef("SendLocal to %s, response %s", reqURL, resp.Status)
		return resp, contents, nil
	}
	if c.AgentMetrics != nil {
		c.AgentMetrics.RecordFailure(c.log, intf, reqURL, reqlen, resplen, false)
	}
	return resp, nil, fmt.Errorf("SendLocal to %s reqlen %d statuscode %d %s",
		reqURL, reqlen, resp.StatusCode,
		http.StatusText(resp.StatusCode))
}

// SendLocalProto is a variant of SendLocal which sends and receives proto messages.
func (c *Client) SendLocalProto(destURL string, intf string, ipSrc net.IP,
	req proto.Message, resp proto.Message) (*http.Response, error) {
	var (
		reqBuf      *bytes.Buffer
		contentType string
	)
	if req != nil {
		reqBytes, err := proto.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request message: %v", err)
		}
		reqBuf = bytes.NewBuffer(reqBytes)
		contentType = ContentTypeProto
	}
	httpResp, respBytes, err := c.SendLocal(destURL, intf, ipSrc, reqBuf, contentType)
	if err != nil {
		return httpResp, err
	}
	if resp != nil && httpResp.StatusCode != http.StatusNoContent {
		if err := ValidateProtoContentType(httpResp); err != nil {
			return nil, fmt.Errorf("response header error: %s", err)
		}
		err := proto.Unmarshal(respBytes, resp)
		if err != nil {
			return nil, fmt.Errorf("response message unmarshalling failed: %v", err)
		}
	}
	return httpResp, nil
}

// Describe send attempts in a concise and readable form.
func (c *Client) describeSendAttempts(attempts []SendAttempt) string {
	var attemptDescriptions []string
	for _, attempt := range attempts {
		var description string
		// Unwrap errors defined here in pillar to avoid stutter.
		// Instead of "send via eth1: interface eth1: no DNS server available",
		// we simply return "interface eth1: no DNS server available".
		// Same for IPAddrNotAvailError.
		// Otherwise, the errors are of the form:
		// "send via eth1 [with src IP <IP>]: <error from http client>"
		switch err := attempt.Err.(type) {
		case *types.DNSNotAvailError:
			description = err.Error()
		case *types.IPAddrNotAvailError:
			description = err.Error()
		default:
			description = attempt.String()
		}
		attemptDescriptions = append(attemptDescriptions, description)
	}
	return strings.Join(attemptDescriptions, "; ")
}

func (c *Client) isCertFailure(err error) (bool, *x509.Certificate) {
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

func (c *Client) isCertUnknownAuthority(err error) bool {
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

func (c *Client) isECONNREFUSED(err error) bool {
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
