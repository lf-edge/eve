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
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
)

// XXX should we add some Init() function to create this?
type ZedCloudContext struct {
	DeviceNetworkStatus *types.DeviceNetworkStatus
	TlsConfig           *tls.Config
	FailureFunc         func(intf string)
	SuccessFunc         func(intf string)
	Debug               bool
}

// Tries all interfaces (free first) until one succeeds. interation arg
// ensure load spreading across multiple interfaces.
// Returns response for first success
func SendOnAllIntf(ctx ZedCloudContext, url string, b *bytes.Buffer, iteration int) (*http.Response, error) {
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
			resp, err := sendOnIntf(ctx, url, intf, b)
			if err != nil {
				continue
			}
			return resp, nil
		}
	}
	errStr := fmt.Sprintf("All attempts to connect to %s failed",
		url)
	log.Println(errStr)
	return nil, errors.New(errStr)
}

func sendOnIntf(ctx ZedCloudContext, url string, intf string, b *bytes.Buffer) (*http.Response, error) {
	addrCount := types.CountLocalAddrAny(*ctx.DeviceNetworkStatus, intf)
	if ctx.Debug {
		log.Printf("Connecting to %s using intf %s #sources %d\n",
			url, intf, addrCount)
	}
	if addrCount == 0 {
		if ctx.FailureFunc != nil {
			ctx.FailureFunc(intf)
		}
		errStr := fmt.Sprintf("No IP addresses to connect to %s using intf %s",
			url, intf)
		log.Println(errStr)
		return nil, errors.New(errStr)
	}
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(*ctx.DeviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		if ctx.Debug {
			fmt.Printf("Connecting to %s using intf %s source %v\n",
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
			fmt.Println(err)
			continue
		}
		if b != nil {
			req.Header.Add("Content-Type", "application/x-proto-binary")
		}
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				fmt.Printf("Got RemoteAddr: %+v, LocalAddr: %+v\n",
					connInfo.Conn.RemoteAddr(),
					connInfo.Conn.LocalAddr())
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(),
			trace))
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("URL get fail: %v\n", err)
			continue
		}
		// Note that we are returning resp hence no resp.Body.Close()

		connState := resp.TLS
		if connState == nil {
			log.Println("no TLS connection state")
			// Inform ledmanager about broken cloud connectivity
			types.UpdateLedManagerConfig(10)
			resp.Body.Close()
			continue
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				log.Printf("no OCSP response for %s\n",
					url)
			} else {
				log.Printf("OCSP stapled check failed for %s\n",
					url)
			}
			//XXX OSCP is not implemented in cloud side so
			// commenting out it for now. Should be:
			// Inform ledmanager about broken cloud connectivity
			// types.UpdateLedManagerConfig(10)
			// resp.Body.Close()
			// continue
		}
		// Even if we got e.g., a 404 we consider the connection a
		// success since we care about the connectivity to the cloud.
		if ctx.SuccessFunc != nil {
			ctx.SuccessFunc(intf)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			if ctx.Debug {
				fmt.Printf("sendOnIntf to %s StatusOK\n",
					url)
			}
			return resp, nil
		default:
			errStr := fmt.Sprintf("sendOnIntf to %s statuscode %d %s",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Println(errStr)
			if ctx.Debug {
				fmt.Printf("received response %v\n",
					resp)
			}
			resp.Body.Close()
			// Get caller to schedule a retry
			return nil, errors.New(errStr)
		}
	}
	if ctx.FailureFunc != nil {
		ctx.FailureFunc(intf)
	}
	errStr := fmt.Sprintf("All attempts to connect to %s using intf %s failed",
		url, intf)
	log.Println(errStr)
	return nil, errors.New(errStr)
}
