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
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

const serverCertFile = "/certs/wss-server-cacert.pem"
const maxReconnWait = 120 * 1000 // 120 seconds

var (
	readP         *os.File
	writeP        *os.File
	oldStdout     *os.File
	techSuppFile  *os.File
	socketOpen    bool
	wsMsgCount    int
	wsSentBytes   int
	websocketConn *websocket.Conn
	isTechSupport bool
	reconnectCnt  int
)

func setupWebC(hostname, token string, u url.URL, isServer bool) bool {
	var pport int
	var pIP string
	retry := 0
	// if the device uses proxy cert, add to the container side
	if isServer {
		proxyIP, proxyPort, proxyPEM := getProxy(false)
		if len(proxyPEM) > 0 {
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
			log.Noticef("proxyIP %s, port %d", proxyIP, proxyPort)
		}
		pport = proxyPort
		pIP = proxyIP
	}
	for { // wait to be connected to the dispatcher
		tlsDialer, err := tlsDial(isServer, pIP, pport)
		if err != nil {
			return false
		}
		c, resp, err := tlsDialer.Dial(u.String(),
			http.Header{
				"X-Session-Token": []string{token},
				"X-Hostname":      []string{hostname}},
		)
		if err != nil {
			if resp == nil {
				log.Noticef("dial: %v, wait for 10 sec", err)
			} else {
				log.Noticef("dial: %v, status code %d, wait for 10 sec", err, resp.StatusCode)
			}
			time.Sleep(10 * time.Second)
		} else {
			websocketConn = c
			if isServer {
				log.Noticef("connect success to websocket server")
			} else {
				fmt.Printf("connect success to websocket server\n")
			}
			break
		}
		retry++
		if !isServer && retry > 1 {
			return false
		}
	}
	return true
}

// TLS Dialer
func tlsDial(isServer bool, pIP string, pport int) (*websocket.Dialer, error) {
	tlsConfig := &tls.Config{}

	// if wss dispatcher server certificate file is mounted
	_, err0 := os.Stat(serverCertFile)
	if err0 == nil {
		caCertPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(serverCertFile)
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

	return dialer, nil
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
		for _, buff := range splitBySize(buf.Bytes(), 8192) {
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
		fmt.Printf("retryWebSocket: timeout or reset, close and resetup websocket, %v\n", err)
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
