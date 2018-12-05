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
)

// XXX should we add some Init() function to create this?
// Currently caller fills it in.
type ZedCloudContext struct {
	DeviceNetworkStatus *types.DeviceNetworkStatus
	TlsConfig           *tls.Config
	FailureFunc         func(intf string, url string, reqLen int64, respLen int64)
	SuccessFunc         func(intf string, url string, reqLen int64, respLen int64)
}

// Tries all interfaces (free first) until one succeeds. interation arg
// ensure load spreading across multiple interfaces.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
func SendOnAllIntf(ctx ZedCloudContext, url string, reqlen int64, b *bytes.Buffer, iteration int, return400 bool) (*http.Response, []byte, error) {
	// If failed then try the non-free
	for try := 0; try < 2; try += 1 {
		var intfs []string
		if try == 0 {
			intfs = types.GetUplinksFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("sendOnAllIntf trying free %v\n", intfs)
		} else {
			intfs = types.GetUplinksNonFree(*ctx.DeviceNetworkStatus,
				iteration)
			log.Debugf("sendOnAllIntf non-free %v\n", intfs)
		}
		for _, intf := range intfs {
			resp, contents, err := SendOnIntf(ctx, url, intf, reqlen, b, true)
			if return400 && resp != nil &&
				resp.StatusCode >= 400 && resp.StatusCode < 500 {
				log.Infof("sendOnAllIntf: for %s reqlen %d ignore code %d\n",
					url, reqlen, resp.StatusCode)
				return resp, nil, err
			}
			if err != nil {
				continue
			}
			return resp, contents, nil
		}
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed",
		url)
	log.Errorln(errStr)
	return nil, nil, errors.New(errStr)
}

// Tries all source addresses on interface until one succeeds.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// If we get a http response, we return that even if it was an error
// to allow the caller to look at StatusCode
func SendOnIntf(ctx ZedCloudContext, destUrl string, intf string, reqlen int64, b *bytes.Buffer, allowProxy bool) (*http.Response, []byte, error) {

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

	addrCount := types.CountLocalAddrAny(*ctx.DeviceNetworkStatus, intf)
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
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		log.Debugf("Connecting to %s using intf %s source %v\n",
			reqUrl, intf, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}

		// Get the transport header with proxy information filled
		proxyUrl, err := LookupProxy(ctx.DeviceNetworkStatus,
			intf, reqUrl)
		var transport *http.Transport
		if err == nil && proxyUrl != nil && allowProxy {
			log.Debugf("sendOnIntf: For input URL %s, proxy found is %s",
				reqUrl, proxyUrl.String())
			transport = &http.Transport{
				TLSClientConfig: ctx.TlsConfig,
				Dial:            d.Dial,
				Proxy:           http.ProxyURL(proxyUrl),
			}
		} else {
			transport = &http.Transport{
				TLSClientConfig: ctx.TlsConfig,
				Dial:            d.Dial,
			}
		}

		client := &http.Client{Transport: transport}

		var req *http.Request
		if b != nil {
			req, err = http.NewRequest("POST", reqUrl, b)
		} else {
			req, err = http.NewRequest("GET", reqUrl, nil)
		}
		if err != nil {
			log.Errorf("NewRequest failed %s\n", err)
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
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(),
			trace))
		resp, err := client.Do(req)
		if err != nil {
			log.Errorf("URL get fail: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("ReadAll failed %s\n", err)
			continue
		}
		resplen := int64(len(contents))

		if useTLS {
			connState := resp.TLS
			if connState == nil {
				log.Errorln("no TLS connection state")
				// Inform ledmanager about broken cloud connectivity
				types.UpdateLedManagerConfig(10)
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
				} else {
					log.Errorf("OCSP stapled check failed for %s\n",
						reqUrl)
				}
				//XXX OSCP is not implemented in cloud side so
				// commenting out it for now.
				if false {
					// Inform ledmanager about broken cloud connectivity
					types.UpdateLedManagerConfig(10)
					if ctx.FailureFunc != nil {
						ctx.FailureFunc(intf, reqUrl,
							reqlen, resplen)
					}
					continue
				}
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
	errStr := fmt.Sprintf("All attempts to connect to %s using intf %s failed",
		reqUrl, intf)
	log.Errorln(errStr)
	return nil, nil, errors.New(errStr)
}
