// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Common code to communicate to zedcloud

package zedcloud

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
)

// XXX should we add some Init() function to create this?
type ZedCloudContext struct {
	DeviceNetworkStatus *types.DeviceNetworkStatus
	TlsConfig           *tls.Config
	FailureFunc         func(intf string, url string, reqLen int64, respLen int64)
	SuccessFunc         func(intf string, url string, reqLen int64, respLen int64)
	Debug               bool
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
			if ctx.Debug {
				log.Printf("sendOnAllIntf trying free %v\n",
					intfs)
			}
		} else {
			intfs = types.GetUplinksNonFree(*ctx.DeviceNetworkStatus,
				iteration)
			if ctx.Debug {
				log.Printf("sendOnAllIntf non-free %v\n",
					intfs)
			}
		}
		for _, intf := range intfs {
			resp, contents, err := sendOnIntf(ctx, url, intf, reqlen, b)
			if return400 && resp != nil &&
				resp.StatusCode >= 400 && resp.StatusCode < 500 {
				log.Printf("sendOnAllIntf: for %s ignore code %\n",
					url, resp.StatusCode)
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
	log.Println(errStr)
	return nil, nil, errors.New(errStr)
}

// Tries all source addresses on interface until one succeeds.
// Returns response for first success. Caller can not use resp.Body but can
// use []byte contents return.
// If we get a http response, we return that even if it was an error
// to allow the caller to look at StatusCode
func sendOnIntf(ctx ZedCloudContext, url string, intf string, reqlen int64, b *bytes.Buffer) (*http.Response, []byte, error) {
	addrCount := types.CountLocalAddrAny(*ctx.DeviceNetworkStatus, intf)
	if ctx.Debug {
		log.Printf("Connecting to %s using intf %s #sources %d\n",
			url, intf, addrCount)
	}
	if addrCount == 0 {
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(intf, url, 0, 0)
		}
		errStr := fmt.Sprintf("No IP addresses to connect to %s using intf %s",
			url, intf)
		if ctx.Debug {
			log.Println(errStr)
		}
		return nil, nil, errors.New(errStr)
	}
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		if ctx.Debug {
			log.Printf("Connecting to %s using intf %s source %v\n",
				url, intf, localTCPAddr)
		}
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: ctx.TlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}
		var req *http.Request
		if b != nil {
			req, err = http.NewRequest("POST", "https://"+url, b)
		} else {
			req, err = http.NewRequest("GET", "https://"+url, nil)
		}
		if err != nil {
			log.Println(err)
			continue
		}
		if b != nil {
			req.Header.Add("Content-Type", "application/x-proto-binary")
		}
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				if ctx.Debug {
					log.Printf("Got RemoteAddr: %+v, LocalAddr: %+v\n",
						connInfo.Conn.RemoteAddr(),
						connInfo.Conn.LocalAddr())
				}
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(),
			trace))
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("URL get fail: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			continue
		}
		resplen := int64(len(contents))

		connState := resp.TLS
		if connState == nil {
			log.Println("no TLS connection state")
			// Inform ledmanager about broken cloud connectivity
			types.UpdateLedManagerConfig(10)
			if ctx.FailureFunc != nil {
				ctx.FailureFunc(intf, url, reqlen, resplen)
			}
			continue
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				// XXX remove debug check
				if ctx.Debug {
					log.Printf("no OCSP response for %s\n",
						url)
				}
			} else {
				log.Printf("OCSP stapled check failed for %s\n",
					url)
			}
			//XXX OSCP is not implemented in cloud side so
			// commenting out it for now.
			if false {
				// Inform ledmanager about broken cloud connectivity
				types.UpdateLedManagerConfig(10)
				if ctx.FailureFunc != nil {
					ctx.FailureFunc(intf, url, reqlen,
						resplen)
				}
				continue
			}
		}
		// Even if we got e.g., a 404 we consider the connection a
		// success since we care about the connectivity to the cloud.
		if ctx.SuccessFunc != nil {
			ctx.SuccessFunc(intf, url, reqlen, resplen)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			if ctx.Debug {
				log.Printf("sendOnIntf to %s StatusOK\n",
					url)
			}
			return resp, contents, nil
		default:
			errStr := fmt.Sprintf("sendOnIntf to %s statuscode %d %s",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Println(errStr)
			if ctx.Debug {
				log.Printf("received response %v\n",
					resp)
			}
			// Get caller to schedule a retry based on StatusCode
			return resp, nil, errors.New(errStr)
		}
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(intf, url, 0, 0)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s using intf %s failed",
		url, intf)
	log.Println(errStr)
	return nil, nil, errors.New(errStr)
}
