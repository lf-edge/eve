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
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// XXX should we add some Init() function to create this?
// Currently caller fills it in.
type ZedCloudContext struct {
	DeviceNetworkStatus *types.DeviceNetworkStatus
	TlsConfig           *tls.Config
	FailureFunc         func(intf string, url string, reqLen int64, respLen int64)
	SuccessFunc         func(intf string, url string, reqLen int64, respLen int64)
	NoLedManager        bool // Don't call UpdateLedManagerConfig
	DevUUID             uuid.UUID
	DevSerial           string
	DevSoftSerial       string
	NetworkSendTimeout  uint32 // In seconds
}

var sendCounter uint32
var nilUUID = uuid.UUID{}

// Tries all interfaces (free first) until one succeeds. interation arg
// ensure load spreading across multiple interfaces.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// We return a bool remoteTemporaryFailure for the cases when we reached
// the controller but it is overloaded, or has certificate issues.
func SendOnAllIntf(ctx ZedCloudContext, url string, reqlen int64, b *bytes.Buffer, iteration int, return400 bool) (*http.Response, []byte, bool, error) {
	// If failed then try the non-free
	const allowProxy = true
	var errorList []error
	remoteTemporaryFailure := false

	for try := 0; try < 2; try += 1 {
		var intfs []string
		var numFreeIntf int
		if try == 0 {
			intfs = types.GetMgmtPortsFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("sendOnAllIntf trying free %v\n", intfs)
			numFreeIntf = len(intfs)
			if len(intfs) == 0 {
				err := errors.New("No free management interfaces")
				errorList = append(errorList, err)
			}
		} else {
			intfs = types.GetMgmtPortsNonFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("sendOnAllIntf non-free %v\n", intfs)
			if len(intfs) == 0 {
				if numFreeIntf == 0 {
					err := errors.New("No management interfaces")
					errorList = append(errorList, err)
				} else {
					// Should have an error from
					// trying the free
				}
			}
		}
		for _, intf := range intfs {
			portStatus := ctx.DeviceNetworkStatus.GetPortByIfName(intf)
			if portStatus != nil {
				if portStatus.CloudReachable == false {
					log.Infof("SendOnAllIntf: XXXXX Skipping interface %s, since cloud is not "+
						"reachable via this interface", intf)
					continue
				}
			} else {
				log.Errorf("SendOnAllIntf: Could not find DevicePortConfig for interface %s "+
					"in DeviceNetworkStatus %+v", intf, ctx.DeviceNetworkStatus)
			}
			resp, contents, rtf, err := SendOnIntf(ctx, url, intf, reqlen, b, allowProxy)
			if rtf {
				remoteTemporaryFailure = true
			}
			if return400 && resp != nil &&
				resp.StatusCode == 400 {
				log.Infof("sendOnAllIntf: for %s reqlen %d ignore code %d\n",
					url, reqlen, resp.StatusCode)
				return resp, nil, remoteTemporaryFailure, err
			}
			if err != nil {
				errorList = append(errorList, err)
				continue
			}
			return resp, contents, remoteTemporaryFailure, nil
		}
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %v",
		url, errorList)
	log.Errorln(errStr)
	return nil, nil, remoteTemporaryFailure, errors.New(errStr)
}

// We try with free interfaces first. If we find enough free interfaces through
// which cloud connectivity can be achieved, we won't test non-free interfaces.
// Otherwise we test non-free interfaces also.
// We return a bool remoteTemporaryFailure for the cases when we reached
// the controller but it is overloaded, or has certificate issues.
func VerifyAllIntf(ctx ZedCloudContext,
	url string, successCount int, iteration int) (bool, bool, error) {
	var intfSuccessCount int = 0
	const allowProxy = true
	var errorList []error
	remoteTemporaryFailure := false

	if successCount <= 0 {
		// No need to test. Just return true.
		return true, remoteTemporaryFailure, nil
	}

	for try := 0; try < 2; try += 1 {
		var intfs []string
		if try == 0 {
			intfs = types.GetMgmtPortsFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("VerifyAllIntf: trying free %v\n", intfs)
		} else {
			intfs = types.GetMgmtPortsNonFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("VerifyAllIntf: non-free %v\n", intfs)
		}
		for _, intf := range intfs {
			resp, _, rtf, err := SendOnIntf(ctx, url, intf, 0, nil, allowProxy)
			if rtf {
				remoteTemporaryFailure = true
			}
			if err != nil {
				log.Errorf("Zedcloud un-reachable via interface %s: %s",
					intf, err)
				errorList = append(errorList, err)
				continue
			}
			portStatus := ctx.DeviceNetworkStatus.GetPortByIfName(intf)
			switch resp.StatusCode {
			case http.StatusOK, http.StatusCreated:
				log.Infof("VerifyAllIntf: Zedcloud reachable via interface %s", intf)
				intfSuccessCount += 1
				portStatus.CloudReachable = true
			default:
				errStr := fmt.Sprintf("Uplink test FAILED via %s to URL %s with "+
					"status code %d and status %s",
					intf, url, resp.StatusCode, http.StatusText(resp.StatusCode))
				log.Errorln(errStr)
				err = errors.New(errStr)
				errorList = append(errorList, err)
				portStatus.CloudReachable = false
				continue
			}
		}
	}
	if intfSuccessCount == 0 {
		errStr := fmt.Sprintf("All test attempts to connect to %s failed: %v",
			url, errorList)
		log.Errorln(errStr)
		return false, remoteTemporaryFailure, errors.New(errStr)
	}
	if intfSuccessCount < successCount {
		errStr := fmt.Sprintf("Not enough Ports (%d) against required count %d to reach Zedcloud; last failed with %v",
			intfSuccessCount, successCount, errorList)
		log.Errorln(errStr)
		return false, remoteTemporaryFailure, errors.New(errStr)
	}
	return true, remoteTemporaryFailure, nil
}

// Tries all source addresses on interface until one succeeds.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// If we get a http response, we return that even if it was an error
// to allow the caller to look at StatusCode
// We return a bool remoteTemporaryFailure for the cases when we reached
// the controller but it is overloaded, or has certificate issues.
func SendOnIntf(ctx ZedCloudContext, destUrl string, intf string, reqlen int64, b *bytes.Buffer, allowProxy bool) (*http.Response, []byte, bool, error) {

	var reqUrl string
	var useTLS bool
	if strings.HasPrefix(destUrl, "http:") {
		reqUrl = destUrl
		useTLS = false
	} else {
		if strings.HasPrefix(destUrl, "https:") {
			reqUrl = destUrl
		} else {
			reqUrl = "https://" + destUrl
		}
		useTLS = true
	}

	addrCount := types.CountLocalAddrAnyNoLinkLocalIf(*ctx.DeviceNetworkStatus, intf)
	log.Debugf("Connecting to %s using intf %s #sources %d reqlen %d\n",
		reqUrl, intf, addrCount, reqlen)

	if addrCount == 0 {
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(intf, reqUrl, 0, 0)
		}
		errStr := fmt.Sprintf("No IP addresses to connect to %s using intf %s",
			reqUrl, intf)
		log.Debugln(errStr)
		return nil, nil, false, errors.New(errStr)
	}
	numDNSServers := types.CountDNSServers(*ctx.DeviceNetworkStatus, intf)
	if numDNSServers == 0 {
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(intf, reqUrl, 0, 0)
		}
		errStr := fmt.Sprintf("No DNS servers to connect to %s using intf %s",
			reqUrl, intf)
		log.Debugln(errStr)
		return nil, nil, false, errors.New(errStr)
	}

	// Get the transport header with proxy information filled
	proxyUrl, err := LookupProxy(ctx.DeviceNetworkStatus, intf, reqUrl)
	var transport *http.Transport
	var usedProxy bool
	if err == nil && proxyUrl != nil && allowProxy {
		log.Debugf("sendOnIntf: For input URL %s, proxy found is %s",
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

	// Try all addresses
	remoteTemporaryFailure := false
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Error(err)
			return nil, nil, remoteTemporaryFailure, err
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		localUDPAddr := net.UDPAddr{IP: localAddr}
		log.Debugf("Connecting to %s using intf %s source %v\n",
			reqUrl, intf, localTCPAddr)
		resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Debugf("resolverDial %v %v", network, address)
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
		if b != nil {
			req, err = http.NewRequest("POST", reqUrl, b)
		} else {
			req, err = http.NewRequest("GET", reqUrl, nil)
		}
		if err != nil {
			log.Errorf("NewRequest failed %s\n", err)
			errorList = append(errorList, err)
			continue
		}

		if b != nil {
			req.Header.Add("Content-Type", "application/x-proto-binary")
		}
		// Add Device UUID to the HTTP Header
		// for tracability
		devUuidStr := ctx.DevUUID.String()
		if devUuidStr != "" && devUuidStr != nilUUID.String() {
			req.Header.Add("X-Request-Id", devUuidStr)
		} else {
			// Add Device Serial Number to the HTTP Header for initial tracability
			devSerialNum := ctx.DevSerial
			if devSerialNum != "" {
				req.Header.Add("X-Serial-Number", devSerialNum)
			}
			// Add Software Serial Number to the HTTP Header for initial tracability
			devSoftSerial := ctx.DevSoftSerial
			if devSoftSerial != "" {
				req.Header.Add("X-Soft-Serial", devSoftSerial)
			}
			log.Debugf("Serial-Numbers, count (%d), serial: %s, soft-serial %s",
				sendCounter, devSerialNum, devSoftSerial) // XXX change to debug
			sendCounter++
		}

		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				log.Debugf("Got RemoteAddr: %+v, LocalAddr: %+v\n",
					connInfo.Conn.RemoteAddr(),
					connInfo.Conn.LocalAddr())
			},
			DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
				log.Debugf("DNS Info: %+v\n", dnsInfo)
			},
			DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
				log.Debugf("DNS start: %+v\n", dnsInfo)
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(),
			trace))
		resp, err := client.Do(req)
		if err != nil {
			if cf, cert := isCertFailure(err); cf {
				// XXX can we ever get this from a proxy?
				// We assume we reached the controller here
				log.Errorf("client.Do fail: certFailure")
				remoteTemporaryFailure = true
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
			} else if isECONNREFUSED(err) {
				if usedProxy {
					log.Errorf("client.Do fail: ECONNREFUSED with proxy")
				} else {
					log.Errorf("client.Do fail: ECONNREFUSED")
					remoteTemporaryFailure = true
				}
				errorList = append(errorList, err)
			} else if isNoSuitableAddress(err) {
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
					types.UpdateLedManagerConfig(12)
				}
				if ctx.FailureFunc != nil {
					ctx.FailureFunc(intf, reqUrl, reqlen,
						resplen)
				}
				continue
			}

			if connState.OCSPResponse == nil ||
				!stapledCheck(connState) {

				if connState.OCSPResponse == nil {
					// XXX remove debug check
					log.Debugf("no OCSP response for %s\n",
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
						types.UpdateLedManagerConfig(13)
					}
					if ctx.FailureFunc != nil {
						ctx.FailureFunc(intf, reqUrl,
							reqlen, resplen)
					}
					err = errors.New(errStr)
					errorList = append(errorList, err)
					continue
				}
				log.Debugln(errStr)
			}
		}
		// Even if we got e.g., a 404 we consider the connection a
		// success since we care about the connectivity to the cloud.
		if ctx.SuccessFunc != nil {
			ctx.SuccessFunc(intf, reqUrl, reqlen, resplen)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			log.Debugf("SendOnIntf to %s StatusOK\n", reqUrl)
			return resp, contents, false, nil
		case http.StatusCreated:
			log.Debugf("SendOnIntf to %s StatusCreated\n", reqUrl)
			return resp, contents, false, nil
		default:
			errStr := fmt.Sprintf("sendOnIntf to %s reqlen %d statuscode %d %s",
				reqUrl, reqlen, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Errorln(errStr)
			log.Debugf("received response %v\n", resp)
			// Get caller to schedule a retry based on StatusCode
			return resp, nil, false, errors.New(errStr)
		}
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(intf, reqUrl, 0, 0)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s using intf %s failed: %v",
		reqUrl, intf, errorList)
	log.Errorln(errStr)
	return nil, nil, remoteTemporaryFailure, errors.New(errStr)
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

func isNoSuitableAddress(err error) bool {
	e0, ok := err.(*url.Error)
	if !ok {
		return false
	}
	e1, ok := e0.Err.(*net.OpError)
	if !ok {
		return false
	}
	e2, ok := e1.Err.(*net.AddrError)
	if !ok {
		return false
	}
	return e2.Err == "no suitable address found"
}
