// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Common code to communicate to zedcloud

package zedcloud

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
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
}

// Tries all interfaces (free first) until one succeeds. interation arg
// ensure load spreading across multiple interfaces.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
func SendOnAllIntf(ctx ZedCloudContext, url string, reqlen int64, b *bytes.Buffer, iteration int, return400 bool) (*http.Response, []byte, error) {
	// If failed then try the non-free
	const allowProxy = true
	var lastError error

	for try := 0; try < 2; try += 1 {
		var intfs []string
		var numFreeIntf int
		if try == 0 {
			intfs = types.GetMgmtPortsFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("sendOnAllIntf trying free %v\n", intfs)
			numFreeIntf = len(intfs)
			if len(intfs) == 0 {
				lastError = errors.New("No free management interfaces")
			}
		} else {
			intfs = types.GetMgmtPortsNonFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("sendOnAllIntf non-free %v\n", intfs)
			if len(intfs) == 0 {
				if numFreeIntf == 0 {
					lastError = errors.New("No management interfaces")
				} else {
					// Should have a lastError from
					// trying the free
				}
			}
		}
		for _, intf := range intfs {
			// XXX Hard coded timeout to 15 seconds. Might need some adjusting
			// depending on network conditions down the road.
			resp, contents, err := SendOnIntf(ctx, url, intf, reqlen, b, allowProxy, 15)
			if return400 && resp != nil &&
				resp.StatusCode == 400 {
				log.Infof("sendOnAllIntf: for %s reqlen %d ignore code %d\n",
					url, reqlen, resp.StatusCode)
				return resp, nil, err
			}
			if err != nil {
				lastError = err
				continue
			}
			return resp, contents, nil
		}
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed: %s",
		url, lastError)
	log.Errorln(errStr)
	return nil, nil, errors.New(errStr)
}

// We try with free interfaces first. If we find enough free interfaces through
// which cloud connectivity can be achieved, we won't test non-free interfaces.
// Otherwise we test non-free interfaces also.
func VerifyAllIntf(ctx ZedCloudContext,
	url string, successCount int, iteration int) (bool, error) {
	var intfSuccessCount int = 0
	const allowProxy = true
	var lastError error

	if successCount <= 0 {
		// No need to test. Just return true.
		return true, nil
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
			if intfSuccessCount >= successCount {
				// We have enough uplinks with cloud connectivity working.
				break
			}
			resp, _, err := SendOnIntf(ctx, url, intf, 0, nil, allowProxy, 15)
			if err != nil {
				// XXX Have code to mark this interface as not suitable
				// for cloud/internet connectivity
				log.Errorf("Zedcloud un-reachable via interface %s: %s",
					intf, err)
				lastError = err
				continue
			}
			switch resp.StatusCode {
			case http.StatusOK:
				log.Infof("VerifyAllIntf: Zedcloud reachable via interface %s", intf)
				intfSuccessCount += 1
			default:
				errStr := fmt.Sprintf("Uplink test FAILED via %s to URL %s with "+
					"status code %d and status %s",
					intf, url, resp.StatusCode, http.StatusText(resp.StatusCode))
				log.Errorln(errStr)
				lastError = errors.New(errStr)
				continue
			}
		}
	}
	if intfSuccessCount == 0 {
		errStr := fmt.Sprintf("All test attempts to connect to %s failed: %s",
			url, lastError)
		log.Errorln(errStr)
		return false, errors.New(errStr)
	}
	if intfSuccessCount < successCount {
		errStr := fmt.Sprintf("Not enough Ports (%d) against required count %d to reach Zedcloud; last failed with %s",
			intfSuccessCount, successCount, lastError)
		log.Errorln(errStr)
		return false, errors.New(errStr)
	}
	return true, nil
}

// Tries all source addresses on interface until one succeeds.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// If we get a http response, we return that even if it was an error
// to allow the caller to look at StatusCode
func SendOnIntf(ctx ZedCloudContext, destUrl string, intf string, reqlen int64, b *bytes.Buffer, allowProxy bool, timeout int) (*http.Response, []byte, error) {

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
		return nil, nil, errors.New(errStr)
	}
	// Get the transport header with proxy information filled
	proxyUrl, err := LookupProxy(ctx.DeviceNetworkStatus, intf, reqUrl)
	var transport *http.Transport
	if err == nil && proxyUrl != nil && allowProxy {
		log.Debugf("sendOnIntf: For input URL %s, proxy found is %s",
			reqUrl, proxyUrl.String())
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

	var lastError error

	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		log.Debugf("Connecting to %s using intf %s source %v\n",
			reqUrl, intf, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport.Dial = d.Dial

		client := &http.Client{Transport: transport}
		if timeout != 0 {
			client.Timeout = time.Duration(timeout) * time.Second
		}

		var req *http.Request
		if b != nil {
			req, err = http.NewRequest("POST", reqUrl, b)
		} else {
			req, err = http.NewRequest("GET", reqUrl, nil)
		}
		if err != nil {
			log.Errorf("NewRequest failed %s\n", err)
			lastError = err
			continue
		}

		if b != nil {
			req.Header.Add("Content-Type", "application/x-proto-binary")
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
			log.Errorf("client.Do fail: %v\n", err)
			lastError = err
			continue
		}

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("ReadAll failed %s\n", err)
			resp.Body.Close()
			resp.Body = nil
			lastError = err
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
				lastError = errors.New(errStr)
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
					lastError = errors.New(errStr)
					continue
				}
				log.Infoln(errStr)
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
			return resp, contents, nil
		default:
			errStr := fmt.Sprintf("sendOnIntf to %s reqlen %d statuscode %d %s",
				reqUrl, reqlen, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Errorln(errStr)
			log.Debugf("received response %v\n", resp)
			// Get caller to schedule a retry based on StatusCode
			return resp, nil, errors.New(errStr)
		}
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(intf, reqUrl, 0, 0)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s using intf %s failed: %s",
		reqUrl, intf, lastError)
	log.Errorln(errStr)
	return nil, nil, errors.New(errStr)
}
