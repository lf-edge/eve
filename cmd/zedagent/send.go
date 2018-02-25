// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"bytes"
	"fmt"
	"github.com/zededa/go-provision/types"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
)

// Tries all interfaces (free first) until one succeeds. interation arg
// ensure load spreading across multiple interfaces.
// Returns true, response for first success
func sendOnAllIntf(url string, data []byte, iteration int) (bool, *http.Response) {
	// If failed then try the non-free
	for try := 0; try < 2; try += 1 {
		var intfs []string
		if try == 0 {
			intfs = types.GetUplinksFree(deviceNetworkStatus,
				iteration)
			if debug {
				log.Printf("sendOnAllIntf trying free %v\n",
					intfs)
			}
		} else {
			intfs = types.GetUplinksNonFree(deviceNetworkStatus,
				iteration)
			if debug {
				log.Printf("sendOnAllIntf non-free %v\n",
					intfs)
			}
		}
		for _, intf := range intfs {
			ok, resp := sendOnIntf(url, intf, data)
			if !ok {
				zedCloudFailure(intf)
				continue
			}
			// Even if we got a 404 we consider the
			// connection a success
			zedCloudSuccess(intf)

			return ok, resp
		}
	}
	log.Printf("All attempts to connect to %s failed\n", url)
	return false, nil
}

func sendOnIntf(url string, intf string, data []byte) (bool, *http.Response) {
	addrCount := types.CountLocalAddrAny(deviceNetworkStatus, intf)
	if debug {
		log.Printf("Connecting to %s using intf %s #sources %d\n",
			url, intf, addrCount)
	}
	if addrCount == 0 {
		return false, nil
	}
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(deviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		if debug {
			fmt.Printf("Connecting to %s using intf %s source %v\n",
				url, intf, localTCPAddr)
		}
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}
		var req *http.Request
		if data != nil {
			req, err = http.NewRequest("POST",
				"https://"+url, bytes.NewBuffer(data))
		} else {
			req, err = http.NewRequest("GET", "https://"+url, nil)
		}
		if err != nil {
			fmt.Println(err)
			continue
		}
		if data != nil {
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

		switch resp.StatusCode {
		case http.StatusOK:
			if debug {
				fmt.Printf("sendOnIntf to %s StatusOK\n",
					url)
			}
			return true, resp
		default:
			log.Printf("sendOnIntf to %s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			if debug {
				fmt.Printf("received response %v\n",
					resp)
			}
			resp.Body.Close()
			// Get caller to schedule a retry
			return false, nil
		}
	}
	log.Printf("All attempts to connect to %s using intf %s failed\n",
		configUrl, intf)
	return false, nil
}
