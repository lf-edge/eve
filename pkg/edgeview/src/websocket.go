// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

const (
	serverCertFile = "/persist/certs/wss-server-cacert.pem"
	maxReconnWait  = 120 * 1000 // 120 seconds
	isEVserver     = "-EV-server"
	invalidIndex   = 2
)

var (
	readP           *os.File
	writeP          *os.File
	oldStdout       *os.File
	techSuppFile    *os.File
	socketOpen      bool
	wsMsgCount      int
	wsSentBytes     int
	websocketConn   *websocket.Conn
	isTechSupport   bool
	reconnectCnt    int
	websIndex       = invalidIndex
	pipeBufHalfSize int
)

func setupWebC(hostname, token string, u url.URL, isServer bool) bool {
	var pport int
	var pIP, serverStr string
	var useProxy int
	retry := 0
	durr := 10 * 1000 // 10 sec
	// if the device uses proxy cert, add to the container side
	if isServer {
		serverStr = isEVserver
		proxyIP, proxyPort, proxyPEM := getProxy(false)
		if len(proxyPEM) > 0 && basics.proxy == "" { // don't run this in re-connect cases
			err := addPackage("/usr/sbin/update-ca-certificates", "ca-certificates")
			if err == nil {
				dir := "/usr/local/share/ca-certificates"
				_ = os.MkdirAll(dir, 0644)
				for i, pem := range proxyPEM {
					ff, err := os.Create(dir + "/proxy-cert" + strconv.Itoa(i) + ".pem")
					if err != nil {
						log.Noticef("file create error %v", err)
						continue
					}
					_, _ = ff.WriteString(string(pem))
					_ = ff.Close()
				}
				prog := "/usr/sbin/update-ca-certificates"
				var args []string
				_, _ = runCmd(prog, args, false)
			}
		}
		if proxyIP != "" {
			basics.proxy = fmt.Sprintf("%s:%s", proxyIP, strconv.Itoa(proxyPort))
			log.Noticef("proxyIP %s, port %d", proxyIP, proxyPort)
		}
		pport = proxyPort
		pIP = proxyIP
	}
	for { // wait to be connected to the dispatcher
		var intfSrcs []net.IP
		if isServer {
			intfSrcs = getDefrouteIntfSrcs()
		}
		useProxy++
		// walk through default route intfs if exist, and try also without specifying the source
		// if we know the index it worked previously before disconnect, try that first
		for idx := len(intfSrcs) - 1; idx >= -1; idx-- {
			if websIndex != invalidIndex && websIndex < len(intfSrcs) {
				idx = websIndex
			}
			websIndex = invalidIndex
			var proxyIP string
			var proxyPort int
			// if proxy exists, sometimes not on all the interfaces, try with and without proxy
			// for dispatcher connection
			if pIP != "" && useProxy%2 == 0 {
				proxyIP = pIP
				proxyPort = pport
				basics.evUseProxy = true
			} else {
				basics.evUseProxy = false
			}
			tlsDialer, err := tlsDial(isServer, proxyIP, proxyPort, intfSrcs, idx)
			if err != nil {
				return false
			}
			c, resp, err := tlsDialer.Dial(u.String(),
				http.Header{
					"X-Session-Token": []string{token},
					"X-Hostname":      []string{hostname + serverStr}},
			)
			if err != nil {
				if resp == nil {
					log.Noticef("dial: %v, wait for retry, index %d, %v", err, idx, intfSrcs)
				} else {
					log.Noticef("dial: %v, status code %d, wait for retry", err, resp.StatusCode)
				}
				durr = durr * (retry + 1)
				if durr > maxReconnWait { // delay max of 2 minutes
					durr = maxReconnWait
				}
				time.Sleep(time.Duration(durr) * time.Millisecond)
			} else {
				websocketConn = c
				if isServer {
					websIndex = idx
					log.Noticef("connect success to websocket server, index %d, %v", idx, intfSrcs)
				} else {
					fmt.Printf("connect success to websocket server\n")
				}
				return true
			}
			retry++
			if !isServer && retry > 1 {
				return false
			}
		}
	}
}

// TLS Dialer
func tlsDial(isServer bool, pIP string, pport int, src []net.IP, idx int) (*websocket.Dialer, error) {
	tlsConfig := &tls.Config{}

	// if wss dispatcher server certificate file is mounted
	_, err0 := os.Stat(serverCertFile)
	if err0 == nil {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(serverCertFile)
		if err != nil {
			log.Errorf("can not read server cert file, %v", err)
			return nil, err
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Errorf("%s", "append cert failed")
			return nil, errors.New("append cert failed")
		}
		tlsConfig.RootCAs = caCertPool
		log.Noticef("wss server cert appended to TLS")
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}
	if pIP != "" && pport != 0 {
		proxyURL, _ := url.Parse("http://" + pIP + ":" + strconv.Itoa(pport))
		dialer.Proxy = http.ProxyURL(proxyURL)
	}
	if idx >= 0 && len(src) > 0 && idx < len(src) {
		dialer.NetDialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: src[idx]}}).DialContext
	}

	return dialer, nil
}

// get source IP addresses of ipv4 default route in main table
func getDefrouteIntfSrcs() []net.IP {
	var srcIPs []net.IP
	table254 := 254
	routes := getTableIPv4Routes(table254)
	for _, r := range routes {
		if r.Dst == nil && r.Gw.To4() != nil && r.Src.To4() != nil {
			srcIPs = append(srcIPs, r.Src)
		}
	}
	// if we have multiple source IPs, make sure they are returned in order always
	if len(srcIPs) > 1 {
		sort.Slice(srcIPs, func(i, j int) bool {
			return bytes.Compare(srcIPs[i], srcIPs[j]) < 0
		})
	}
	return srcIPs
}

// hijack the stdout to buffer and later send the content through
// websocket to the requester of the info
func openPipe() (*os.File, *os.File, error) {
	if socketOpen {
		return nil, nil, fmt.Errorf("socket already opened\n")
	}
	oldStdout = os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		log.Errorf("os.Pipe: %v", err)
		return nil, nil, err
	}
	os.Stdout = w
	socketOpen = true

	if pipeBufHalfSize == 0 {
		fd := r.Fd()
		pipeBufHalfSize, err = unix.FcntlInt(uintptr(fd), unix.F_GETPIPE_SZ, 0)
		if err != nil {
			log.Errorf("openPipe: fcntl: %v", err)
			pipeBufHalfSize = 8192
		} else {
			pipeBufHalfSize = pipeBufHalfSize / 2
		}
	}
	return r, w, nil
}

func closePipe(openAfter bool) {
	if !socketOpen {
		return
	}
	writeP.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, readP)
	socketOpen = false

	if isTechSupport {
		size := len(buf.String())
		if size > 0 {
			_, err := techSuppFile.WriteString(buf.String())
			if err != nil {
				log.Errorf("write techsupport string error: %v", err)
			}
		}
	} else if websocketConn != nil && len(buf.String()) > 0 {
		for _, buff := range splitBySize(buf.Bytes(), pipeBufHalfSize) {
			err := addEnvelopeAndWriteWss(buff, true)
			if err != nil {
				log.Errorf("write: %v", err)
				break
			} else {
				wsMsgCount++
				wsSentBytes += len(buff)
			}
		}
	}
	reOpenPipe(openAfter)
}

func reOpenPipe(doOpen bool) {
	if doOpen {
		var err error
		readP, writeP, err = openPipe()
		if err != nil {
			log.Errorf("open pipe error: %v", err)
		}
	}
}

func retryWebSocket(hostname, token string, urlWSS url.URL, err error) bool {
	websocketConn.Close()
	tcpRetryWait = true
	duration := 100
	if runOnServer {
		log.Noticef("retryWebSocket: timeout or reset, close and resetup websocket, %v", err)
		duration = duration * (reconnectCnt + 1)
		if duration > maxReconnWait {
			duration = maxReconnWait
		}
		reconnectCnt++
	} else {
		fmt.Printf("retryWebSocket: client timeout or reset, close and resetup websocket, %v\n", err)
	}
	time.Sleep(time.Duration(duration) * time.Millisecond)
	ok := setupWebC(hostname, token, urlWSS, true)
	tcpRetryWait = false
	if ok {
		reconnectCnt = 0
		return true
	} else {
		log.Noticef("retry failed.")
	}
	return false
}

func clientSendQuery(cmd cmdOpt) bool {
	// send the query command to websocket/server
	jdata, err := json.Marshal(cmd)
	if err != nil {
		fmt.Printf("json Marshal queryCmds error: %v\n", err)
		return false
	}

	err = addEnvelopeAndWriteWss(jdata, true)
	if err != nil {
		fmt.Printf("write: %v\n", err)
		return false
	}
	return true
}

func sendCloseToWss() {
	// send to dispatcher to close, no authentication
	err := addEnvelopeAndWriteWss([]byte(closeMessage), true)
	if err != nil {
		log.Noticef("sent done msg error: %v", err)
	}
}
