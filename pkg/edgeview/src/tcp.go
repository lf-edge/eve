// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

type wsMessage struct {
	mtype int
	msg   []byte
}

type tcpData struct {
	Version   uint16 `json:"version"`
	MappingID uint16 `json:"mappingId"`
	ChanNum   uint16 `json:"chanNum"`
	Data      []byte `json:"data"`
}

type tcpconn struct {
	conn      net.Conn
	msgChan   chan wsMessage
	pending   bool
	closed    bool
	closeTime time.Time
	recvLocal int
	recvWss   int
	done      chan struct{}
}

// Endpt - endpoint struct
type Endpt struct {
	Host string
	Port int
}

func (endpoint *Endpt) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

// client TCP service to be forwarded, starts from 9001
var clientTCPEndpoint = Endpt{
	Host: "0.0.0.0",
	Port: 9000,
}

// internal proxy server endpoint on device side
var proxyServerEndpoint = Endpt{
	Host: "localhost",
	Port: 8888,
}

// tcpConnRWMap is fixed port-mapping, within it can have multiple flows each
// has it's tcpconn. In other words, the tcpConnRWMap defines the destination
// endpoint such as "10.1.0.4:8080", and it can have multiple source endpoints
type tcpConnRWMap struct {
	m map[int]tcpconn
}

const (
	tcpMaxMappingNUM  int           = 5
	tcpIdleTimeoutSec float64       = 1800.0
	tcpCheckTimeout   time.Duration = 300 * time.Second
	kubeYamlFile      string        = "/run/.kube/k3s/user.yaml"
	kubeConfigFile    string        = "kube-config.yaml"
	kubeServerFile    string        = "/tmp/" + kubeConfigFile
	kubeClientFile    string        = fileCopyDir + kubeConfigFile
)

const (
	tcpDONEMessage    = "+++tcpDone+++"
	tcpSetupOKMessage = "+++tcpSetupOK+++"
)

var (
	isTCPClient   bool
	tcpRetryWait  bool
	tcpClientRun  bool
	isTCPServer   bool
	tcpDataChn    []chan tcpData
	tcpServerDone chan struct{}

	tcpMapMutex sync.Mutex
	wssWrMutex  sync.Mutex
	tcpConnM    []tcpConnRWMap

	tcpServerRecvTime time.Time // updated by all the tcp sessions
	tcpTimeMutex      sync.Mutex
)

// Virtual TCP Port Mapping service

// tcp mapping on the client end
func tcpClientsLaunch(tcpclientCnt int, remotePorts map[int]int) {
	tcpConnM = make([]tcpConnRWMap, tcpclientCnt)
	idx := 0
	if edgeviewInstID > 1 { // in case multiple sessions on the same computer
		clientTCPEndpoint.Port += (edgeviewInstID - 1) * types.EdgeviewMaxInstNum
	}
	for {
		rPort := remotePorts[idx]
		go tcpClientStart(idx, rPort)
		idx++
		if idx >= tcpclientCnt {
			break
		}
	}
	tcpClientRun = true
}

func tcpClientStart(idx int, rport int) {
	clientep := clientTCPEndpoint
	clientep.Port += idx + 1
	listener, err := net.Listen("tcp", clientep.String())
	if err != nil {
		return
	}

	newChan := make(chan net.Conn)
	tcpConnM[idx].m = make(map[int]tcpconn)
	channelNum := 0
	cleanMapTimer := time.Tick(3 * time.Minute)
	go func(l net.Listener) {
		for {
			here, err := listener.Accept()
			if err != nil {
				fmt.Printf("Accept error %v\n", err)
				return
			}
			newChan <- here
		}
	}(listener)
	for {
		select {
		case here := <-newChan:
			channelNum++
			go clientTCPtunnel(here, idx, channelNum, rport)
		case <-cleanMapTimer:
			cleanClosedMapEntries(idx)
		}
	}
}

func clientTCPtunnel(here net.Conn, idx, chNum int, rport int) {

	fmt.Printf("tcp tunnel(idx %d): starts in chan %d, addr %v (remote port %d)\n", idx, chNum, here.RemoteAddr(), rport)
	done := make(chan struct{})
	myConn := tcpconn{
		conn:    here,
		msgChan: make(chan wsMessage, 50),
	}
	msgChan := tcpConnM[idx].AssignConn(chNum, myConn)

	go func(here net.Conn) {
		for {
			select {
			case tcpmsg := <-msgChan:
				myConn := tcpConnM[idx].RecvWssInc(chNum)
				buf := bytes.NewBuffer(tcpmsg.msg)
				log.Tracef("Ch-%d[idx %d port %d], From wss recv, %s, len %d",
					chNum, idx, rport, time.Now().Format("2006-01-02 15:04:05"), len(tcpmsg.msg))
				if myConn.pending {
					log.Tracef("Ch(%d)-%d, pending close send to client, %v", idx, chNum, time.Now())
				}
				_, _ = io.Copy(here, buf)
			case <-done:
				return
			}
		}
	}(here)

	buf := make([]byte, chunkSize)
	var justEnterVNC bool
	if rport >= 5900 && rport <= 5910 { // VNC does not send any data initially
		justEnterVNC = true
	}
	var reqLen int
	var err error
	for {
		if justEnterVNC {
			justEnterVNC = false
		} else {
			reqLen, err = here.Read(buf)
			if err != nil {
				log.Tracef("clientTCPtunnel-%d[idx %d rport %d]: tcp socket error from local client, %v, %v, break",
					chNum, idx, rport, time.Now(), err)
				if err == io.EOF {
					time.Sleep(1 * time.Second)
					log.Tracef("clientTCPtunnel-%d: delay 1 second pending close after EOF, %v", chNum, time.Now())
				}
				here.Close()
				tcpConnM[idx].CloseChan(chNum)
				break
			}
			tcpConnM[idx].RecvLocalInc(chNum)
		}

		wrdata := tcpData{
			MappingID: uint16(idx + 1),
			ChanNum:   uint16(chNum),
			Data:      buf[:reqLen],
		}
		jdata, err := json.Marshal(wrdata)
		if err != nil {
			fmt.Printf("ch(%d)-%d, client json marshal error %v\n", idx, chNum, err)
			continue
		}

		if tcpRetryWait {
			log.Noticef("wait for tcp retry before write to wss: ch-%d", chNum)
			time.Sleep(1 * time.Second)
		}
		log.Tracef("ch-%d[idx %d, port %d], client wrote len %d to wss, %s",
			chNum, idx, rport, len(jdata), time.Now().Format("2006-01-02 15:04:05"))

		if websocketConn == nil {
			close(done)
			log.Noticef("ch(%d)-%d, websocketConn nil. exit", idx, chNum)
			return
		}
		allowSend := true
		if !disableRateLimit {
			msgSize := len(jdata)
			ok := checkTCPRateLimit(msgSize)
			if !ok {
				allowSend = false
				log.Noticef("clientTCPtunnel: drop-pkt")
			}
		}
		if allowSend {
			err = addEnvelopeAndWriteWss(jdata, false)
			if err != nil {
				close(done)
				log.Errorf("ch(%d)-%d, client write wss error %v", idx, chNum, err)
				return
			}
		}
	}
}

// receive tcp message from server side
func recvServerData(mtype int, message []byte) {
	var jmsg tcpData
	err := json.Unmarshal(message, &jmsg)
	if err != nil {
		fmt.Printf("json unmarshal err %v\n", err)
		return
	}

	mid := jmsg.MappingID - 1
	if len(tcpConnM) <= int(mid) {
		fmt.Printf("tcpConnMap size %d, can not have index %d\n", len(tcpConnM), mid)
		return
	}
	myChan, ok := tcpConnM[mid].Get(int(jmsg.ChanNum))
	if !ok {
		fmt.Printf("tcpConnMap has no chan %d on client\n", jmsg.ChanNum)
		return
	}
	if myChan.closed {
		fmt.Printf("tcpConnMap chan %d on client is closed\n", jmsg.ChanNum)
		return
	}
	msg := wsMessage{
		mtype: mtype,
		msg:   jmsg.Data,
	}
	//fmt.Printf("in TCP Client, send msg to chan %d\n", jmsg.ChanNum)
	myChan.msgChan <- msg
}

// TCP mapping on server side
func setAndStartProxyTCP(opt string) {
	var ipAddrPort []string
	var proxySvr *http.Server
	var kubeport int
	var err error
	proxyServerDone := make(chan struct{})

	mappingCnt := 1
	ipAddrPort = make([]string, mappingCnt)

	var hasProxy, hasKube bool
	var proxyDNSIP, kubeAddrPort string
	kubenum := edgeviewInstID - 1
	if strings.Contains(opt, "/") {
		var gotProxy, gotKube bool
		params := strings.Split(opt, "/")
		mappingCnt = len(params)
		ipAddrPort = make([]string, mappingCnt)
		for i, ipport := range params {
			gotProxy, gotKube, proxyDNSIP, kubeAddrPort, err = getProxyOpt(ipport)
			if err != nil {
				fmt.Printf("tcp option error %v\n", err)
				return
			} else if !strings.Contains(opt, ":") && !gotProxy && !gotKube {
				fmt.Printf("tcp option needs ipaddress:port format, or in either 'proxy' or 'kube'\n")
				return
			}
			ipAddrPort[i] = ipport
			if gotProxy {
				hasProxy = true
			} else if gotKube {
				if !IsHVTypeKube {
					fmt.Printf("tcp kube option is only supported in kubevirt image\n")
					return
				}
				hasKube = true
				kubeport = 9001 + i + kubenum*types.EdgeviewMaxInstNum
				ipAddrPort[i] = kubeAddrPort
			}
			log.Tracef("setAndStartProxyTCP: (%d) ipport %s", i, ipport)
		}
	} else {
		hasProxy, hasKube, proxyDNSIP, kubeAddrPort, err = getProxyOpt(opt)
		if err != nil {
			fmt.Printf("tcp option error %v\n", err)
			return
		} else if !strings.Contains(opt, ":") && !hasProxy && !hasKube {
			fmt.Printf("tcp option needs ipaddress:port format, or in either 'proxy' or 'kube'\n")
			return
		}
		ipAddrPort[0] = opt
		if hasKube {
			ipAddrPort[0] = kubeAddrPort
			kubeport = 9001 + kubenum*types.EdgeviewMaxInstNum
		} else {
			ipAddrPort[0] = opt
		}
		log.Tracef("setAndStartProxyTCP: opt %s", opt)
	}

	if hasProxy {
		log.Tracef("setAndStartProxyTCP: launch proxy server")
		proxyServerEndpoint.Port += edgeviewInstID
		proxySvr = proxyServer(proxyServerDone, proxyDNSIP)
	}

	if hasKube {
		// XXX can check on this policy in the future if needed
		//if !kubPolicy.Enabled {
		//	fmt.Printf("tcp option for kubectl is not allowed")
		//	return
		//}
		kubefileName, err := genKubeConfigFile(kubeport)
		if err != nil {
			fmt.Printf("tcp kube copy file error: %v\n", err)
			return
		}
		err = runCopy("cp/"+kubefileName, nil)
		if err != nil {
			log.Errorf("setAndStartProxyTCP: copy kube file error %v", err)
		}

		err = os.Remove(kubefileName)
		if err != nil {
			log.Warn(err)
		}
		log.Tracef("setAndStartProxyTCP: copy kube file done, port %d", kubeport)
	}

	// send tcp-setup-ok to client side
	fmt.Printf(" %v\n", tcpSetupOKMessage)
	tcpConnM = make([]tcpConnRWMap, mappingCnt)
	tcpDataChn = make([]chan tcpData, mappingCnt)

	closePipe(false)
	isTCPServer = true
	tcpServerDone = make(chan struct{})

	idx := 0
	serverDone := make([]chan struct{}, mappingCnt)
	for {
		serverDone[idx] = make(chan struct{})
		go startTCPServer(idx, ipAddrPort[idx], serverDone[idx])
		idx++
		if idx >= mappingCnt {
			break
		}
	}

	t := time.NewTimer(tcpCheckTimeout)
	tcpRecvTimeUpdate()
	for {
		select {
		case <-t.C:
			// if sessions still ongoing, continue
			if !tcpRecvTimeCheckExpire() {
				t = time.NewTimer(tcpCheckTimeout)
				continue
			}
			log.Tracef("setAndStartProxyTCP: timer expired, close and notify client")
			_ = addEnvelopeAndWriteWss([]byte("\n"), true) // try send a text msg to other side
			if !isClosed(tcpServerDone) {
				close(tcpServerDone)
			} else if !isClosed(proxyServerDone) {
				close(proxyServerDone)
			} else {
				return
			}
		case <-tcpServerDone:
			for _, d := range serverDone {
				if !isClosed(d) {
					close(d)
				}
			}
			t.Stop()
			if hasProxy && proxySvr != nil {
				fmt.Printf("TCP exist. calling proxSvr.Close\n")
				proxySvr.Close()
			}
			isTCPServer = false
			return

		case <-proxyServerDone:
			for _, d := range serverDone {
				if !isClosed(d) {
					close(d)
				}
			}
			t.Stop()
			isTCPServer = false
			return
		}
	}
}

// need to modify the kubeconfig file for mapping the edgeview local port for kubectl
func genKubeConfigFile(kubeport int) (string, error) {
	// this kubeYamlFile is user.yaml, which is not the kubeconfig file
	// it only identify the user as 'debugging-user', who has only the kubernetes
	// 'get', 'list' and 'watch' permissions
	// thus the edgeview tcp/kube user can not change the kubernetes configuration
	yamlBytes, err := os.ReadFile(kubeYamlFile)
	if err != nil {
		err = fmt.Errorf("tcp kube can not read/process kubeConfig yaml file. error %v\n", err)
		return "", err
	}

	yamlString := string(yamlBytes)
	pattern := regexp.MustCompile(`https://[\d\.]+:6443`)
	newString := "https://localhost:" + strconv.Itoa(kubeport)

	yamlString = pattern.ReplaceAllString(yamlString, newString)

	err = os.WriteFile(kubeServerFile, []byte(yamlString), 0644)
	if err != nil {
		log.Errorf("genKubeConfigFile: write file error %v", err)
		return "", err
	}

	log.Noticef("genKubeConfigFile: write done")
	return kubeServerFile, nil
}

func delKubeConfigFile(isKube bool) {
	if !isKube {
		return
	}
	err := os.Remove(kubeClientFile)
	if err != nil {
		fmt.Printf("delKubeConfigFile: delete file error %v\n", err)
	}
}

// each mapping of port with 'idx', and each flow within the mapping in the 'ChnNum'
// the 'idx' is fixed after setup, but flow of 'Chn' is dynamic
func startTCPServer(idx int, ipAddrPort string, tcpServerDone chan struct{}) {
	tcpConnM[idx].m = make(map[int]tcpconn)
	cleanMapTimer := time.NewTicker(3 * time.Minute)
	tcpDataChn[idx] = make(chan tcpData)

	log.Tracef("tcp server(%d) starts to server %s, waiting for first client packet", idx, ipAddrPort)
	var tcpluanchCnt int
	for {
		select {
		case wssMsg := <-tcpDataChn[idx]:
			if int(wssMsg.ChanNum) > tcpluanchCnt {
				tcpluanchCnt++
			} else {
				log.Tracef("tcp re-launch channel(%d): %d", idx, wssMsg.ChanNum)
			}
			go tcpTransfer(ipAddrPort, wssMsg, idx)
		case <-tcpServerDone:
			log.Tracef("tcp server done(%d). exit", idx)
			isTCPServer = false
			cleanMapTimer.Stop()
			doneTCPtransfer(idx)
			cleanClosedMapEntries(idx)
			return
		case <-cleanMapTimer.C:
			cleanClosedMapEntries(idx)
		}
	}
}

func tcpTransfer(url string, wssMsg tcpData, idx int) {
	var conn net.Conn
	var err error
	var proxyStr string
	var connClosed bool

	chNum := int(wssMsg.ChanNum)
	done := make(chan struct{})
	d := net.Dialer{Timeout: 30 * time.Second}
	if strings.Contains(url, "proxy") {
		conn, err = d.Dial("tcp", proxyServerEndpoint.String())
		proxyStr = "(proxy)"
	} else {
		conn, err = d.Dial("tcp", url)
	}
	if err != nil {
		log.Errorf("tcp dial(%d) error%s: %v", idx, proxyStr, err)
		return
	}
	defer conn.Close()

	myConn := tcpconn{
		conn:    conn,
		msgChan: make(chan wsMessage, 50),
		done:    done,
	}
	oldChan, ok := tcpConnM[idx].Get(chNum)
	if ok {
		myConn.recvLocal = oldChan.recvLocal
		myConn.recvWss = oldChan.recvWss
	}

	msgChan := tcpConnM[idx].AssignConn(chNum, myConn)
	msg := wsMessage{
		mtype: websocket.BinaryMessage,
		msg:   []byte(wssMsg.Data),
	}
	myConn.msgChan <- msg // first message from client

	log.Tracef("tcpTrasfer(%d) starts%s for chNum %d. got conn, localaddr %s", idx, proxyStr, chNum, conn.LocalAddr())
	//done := make(chan struct{})
	// receive from clinet/websocket and relay to tcp server
	go func(conn net.Conn, done chan struct{}) {
		for {
			select {
			case <-done:
				log.Tracef("done here, ch(%d)-%d", idx, chNum)
				tcpConnM[idx].CloseChan(chNum)
				if !connClosed {
					conn.Close()
				}
				return
			case wsmsg := <-msgChan:
				tcpConnM[idx].RecvWssInc(chNum)
				if wsmsg.mtype == websocket.TextMessage {
					conn.Close()
					tcpConnM[idx].CloseChan(chNum)
					return
				}
				buf := bytes.NewBuffer(wsmsg.msg)
				_, _ = io.Copy(conn, buf)
				tcpRecvTimeUpdate()
			}
		}
	}(conn, done)

	buf := make([]byte, 25600)
	for {
		reqLen, err := conn.Read(buf)
		if err != nil {
			break
		}

		myConn = tcpConnM[idx].RecvLocalInc(chNum)
		wrdata := tcpData{
			MappingID: uint16(idx + 1),
			ChanNum:   uint16(chNum),
			Data:      buf[:reqLen],
		}
		jdata, err := json.Marshal(wrdata)
		if err != nil {
			fmt.Printf("ch(%d)-%d, server json marshal error %v\n", idx, chNum, err)
			continue
		}

		if tcpRetryWait {
			fmt.Printf("wait for tcp retry before write to wss: ch-%d\n", chNum)
			time.Sleep(1 * time.Second)
		}
		if websocketConn == nil {
			close(done)
			return
		}
		// apply ratelimit to outbound server tcp traffic
		allowSend := true
		if !disableRateLimit {
			msgSize := len(jdata)
			ok := checkTCPRateLimit(msgSize)
			if !ok {
				allowSend = false
				log.Noticef("tcpTransfer: drop-pkt")
			}
		}
		if allowSend {
			err = addEnvelopeAndWriteWss(jdata, false)
			if err != nil {
				log.Errorf("ch(%d)-%d, server wrote error %v", idx, chNum, err)
				break
			}
		}
	}
	if !isClosed(done) {
		close(done)
	}
	connClosed = true
}

// receive tcp message from client side
func recvClientData(mtype int, message []byte) {
	var jmsg tcpData
	err := json.Unmarshal(message, &jmsg)
	if err != nil {
		log.Errorf("json unmarshal err %v", err)
		return
	}

	mid := jmsg.MappingID - 1
	if len(tcpConnM) <= int(mid) {
		log.Errorf("receive tcp mapping incorrect ID: %d", mid)
		return
	}
	myChan, ok := tcpConnM[mid].Get(int(jmsg.ChanNum))
	if !ok || myChan.closed {
		log.Tracef("tcpConnMap(%d) has no chan %d on server, launch", mid, jmsg.ChanNum)
		tcpDataChn[mid] <- jmsg
		return
	}
	msg := wsMessage{
		mtype: mtype,
		msg:   jmsg.Data,
	}
	myChan.msgChan <- msg
}

func cleanClosedMapEntries(idx int) {
	tcpMapMutex.Lock()
	deleted := 0
	recvlocal := 0
	recvWss := 0
	for i, m := range tcpConnM[idx].m {
		if m.closed && time.Since(m.closeTime).Seconds() > 60 {
			recvlocal += m.recvLocal
			recvWss += m.recvWss
			delete(tcpConnM[idx].m, i)
			deleted++
		}
	}
	log.Tracef("done with cleanup(%d). deleted %d, exist num %d", idx, deleted, len(tcpConnM[idx].m))
	tcpMapMutex.Unlock()
}

func doneTCPtransfer(idx int) {
	tcpMapMutex.Lock()
	closed := 0
	for _, m := range tcpConnM[idx].m {
		if m.done != nil && !isClosed(m.done) {
			close(m.done)
			closed++
		}
	}
	tcpMapMutex.Unlock()
	log.Noticef("doneTCPtransfer(%d) closed %d threads", idx, closed)
}

func (r tcpConnRWMap) Get(ch int) (tcpconn, bool) {
	tcpMapMutex.Lock()
	t, ok := r.m[ch]
	if !ok {
		tcpMapMutex.Unlock()
		return tcpconn{}, ok
	}
	tcpMapMutex.Unlock()
	return t, ok
}

func (r tcpConnRWMap) RecvWssInc(ch int) tcpconn {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.recvWss++
	r.m[ch] = m
	tcpMapMutex.Unlock()
	return m
}

func (r tcpConnRWMap) RecvLocalInc(ch int) tcpconn {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.recvLocal++
	r.m[ch] = m
	tcpMapMutex.Unlock()
	return m
}

func (r tcpConnRWMap) CloseChan(ch int) {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.closed = true
	m.closeTime = time.Now()
	r.m[ch] = m
	tcpMapMutex.Unlock()
}

func (r tcpConnRWMap) PendingChan(ch int) {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.pending = true
	r.m[ch] = m
	tcpMapMutex.Unlock()
}

func (r tcpConnRWMap) AssignConn(ch int, m tcpconn) chan wsMessage {
	tcpMapMutex.Lock()
	r.m[ch] = m
	tcpMapMutex.Unlock()
	return m.msgChan
}

func tcpRecvTimeUpdate() {
	tcpTimeMutex.Lock()
	tcpServerRecvTime = time.Now()
	tcpTimeMutex.Unlock()
}

func tcpRecvTimeCheckExpire() bool {
	var expired bool
	tcpTimeMutex.Lock()
	if time.Since(tcpServerRecvTime).Seconds() > tcpIdleTimeoutSec {
		expired = true
	}
	tcpTimeMutex.Unlock()
	return expired
}

func tcpClientSendDone() {
	if !isTCPClient {
		sendCloseToWss()
		return
	}
	// send to server first, then to dispatcher to close
	_ = addEnvelopeAndWriteWss([]byte(tcpDONEMessage), true)
	sendCloseToWss()
}

func getProxyOpt(opt string) (bool, bool, string, string, error) {
	var proxyDNSIP, kubeAPIAddrPort string
	var hasProxy, hasKube bool
	if strings.HasPrefix(opt, "proxy") {
		hasProxy = true
		if strings.Contains(opt, "proxy@") {
			strs := strings.Split(opt, "proxy@")
			if len(strs) == 2 {
				proxyDNSIP = strs[1]
			}
		}
	} else if strings.HasPrefix(opt, "kube") {
		// get kubeConfig server's IP address and port
		addrPort, err := getKubeServerIPandPort(kubeYamlFile)
		if err == nil {
			kubeAPIAddrPort = addrPort
			hasKube = true
		} else {
			return false, false, "", "", fmt.Errorf("tcp kube option get cluster IP and port error %v", err)
		}
	}
	return hasProxy, hasKube, proxyDNSIP, kubeAPIAddrPort, nil
}

func processTCPcmd(opt string, remotePorts map[int]int) (bool, bool, int, map[int]int) {
	tcpopts := strings.SplitN(opt, "tcp/", 2)
	if len(tcpopts) != 2 {
		fmt.Printf("tcp options need to be specified\n")
		return false, false, 0, map[int]int{}
	}
	tcpparam := tcpopts[1]

	var params []string
	tcpclientCnt := 1
	if strings.Contains(tcpparam, "/") {
		params = strings.Split(tcpparam, "/")
		tcpclientCnt = len(params)
		if tcpclientCnt > tcpMaxMappingNUM {
			fmt.Printf("tcp maximum mapping is: %d\n", tcpMaxMappingNUM)
			return false, false, tcpclientCnt, map[int]int{}
		}
	} else {
		params = append(params, tcpparam)
	}

	proxycnt := 0
	hasKube := false
	for i, pStr := range params {
		if strings.Contains(pStr, ":") {
			pPort := strings.Split(pStr, ":")
			if len(pPort) == 2 {
				portStr := pPort[1]
				portNum, _ := strconv.Atoi(portStr)
				remotePorts[i] = portNum
			}
		} else if strings.HasPrefix(pStr, "proxy") {
			if proxycnt > 0 {
				fmt.Printf("can not setup multiple proxies\n")
				return false, false, tcpclientCnt, map[int]int{}
			}
			remotePorts[i] = 0
			proxycnt++
		} else if strings.HasPrefix(pStr, "kube") {
			remotePorts[i] = 0
			hasKube = true
		}
	}

	if len(remotePorts) != tcpclientCnt {
		fmt.Printf("tcp port mapping not matching %d, %v\n", tcpclientCnt, remotePorts)
		return false, false, tcpclientCnt, map[int]int{}
	}

	isTCPClient = true
	fmt.Printf("tcp mapping locally listening %d ports to remote:\n", len(remotePorts))
	for i, p := range params {
		var addports int
		if edgeviewInstID > 1 {
			addports = (edgeviewInstID - 1) * types.EdgeviewMaxInstNum
		}
		mapline := fmt.Sprintf("  0.0.0.0:%d -> %s\n", 9001+addports+i, p)
		printColor(mapline, colorGREEN)
	}

	return true, hasKube, tcpclientCnt, remotePorts
}

func checkTCPRateLimit(msgSize int) bool {
	now := time.Now()
	var ok bool
	res := tcpRl.ReserveN(now, msgSize)
	if !res.OK() {
		ok = false
	} else {
		ok = true
		time.Sleep(res.Delay())
	}
	return ok
}
