// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type endPoint struct {
	hostname string
	wsConn   *websocket.Conn
}

const (
	noDeviceMsg string = "no device online\n+++Done+++"
	tokenReqMsg string = "token is required"
	moretwoMsg  string = "can't have more than 2 peers"
	clientIPMsg string = "YourEndPointIPAddr:"
)

var upgrader = websocket.Upgrader{} // use default options
// reqAddrTokeConn indexed by 'token' then 'remoteAddr' strings
var reqAddrTokenEP map[string]map[string]endPoint

// mutex for access the maps
var connMutex sync.Mutex

// connection id, keep inc
var connID int

// debug set
var needDebug bool

// There are three entities in the edge-view data operation, the user,
// the dispatcher and the edge-node.
// From TCP/TLS/Websocket connection POV, user does not have any
// relation to the edge-node. The connections are between the
// user with the wss-server, and the edge-node with the wss-server.
// Think of this as the Hub-spoke model, with the wss-server as the hub,
// and user and edge-node are two spokes.
// The user and the edge-node only have a 'virtual' connection which
// contains the 'application' layer packets, and the wss-server is switching
// the packets for user and edge-node based on a 'token'. This is
// analogous to the hub-spoke in SD-WAN, where the hub installs the
// routing from each spoke node, and based on the packet destination
// and VPN-index to do a lookup to forward packets to the right
// destination spoke. Here the 'token' lookup is similar to lookup
// for a VPN-ID to find the VPN-table. Since we only allow one user
// to interact with one edge-node (only two spokes within the same VPN),
// the hub only needs to find the 'other' spoke for the packet switching.
// This may change for more complex topology.
func socketHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade our raw HTTP connection to a websocket based one
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Error during connection upgradation: %v\n", err)
		return
	}
	defer conn.Close()

	if _, ok := r.Header["X-Session-Token"]; !ok {
		err := conn.WriteMessage(websocket.TextMessage, []byte(tokenReqMsg))
		if needDebug {
			fmt.Printf("websocket write: %v\n", err)
		}
		return
	}
	if len(r.Header["X-Session-Token"]) == 0 {
		err := conn.WriteMessage(websocket.TextMessage, []byte(tokenReqMsg))
		if needDebug {
			fmt.Printf("websocket write: %v\n", err)
		}
		return
	}
	token := r.Header["X-Session-Token"][0]

	connID++
	myConnID := connID
	var hostname string
	if _, ok := r.Header["X-Hostname"]; ok {
		if len(r.Header["X-Hostname"]) > 0 {
			hostname = r.Header["X-Hostname"][0]
		}
	}

	remoteAddr := r.RemoteAddr
	if addrStr, ok := r.Header["Cf-Connecting-Ip"]; ok {
		if len(addrStr) > 0 {
			remoteAddr = addrStr[0]
		}
	}
	connMutex.Lock()
	tmpMap := reqAddrTokenEP[token]
	if tmpMap == nil {
		tmpMap := make(map[string]endPoint)
		reqAddrTokenEP[token] = tmpMap
	}

	if len(tmpMap) == 2 {
		var addOK bool
		// check to see if this one is from the same host
		for addr, e := range tmpMap {
			if e.hostname == hostname {
				fmt.Printf("%v received connection with same hostname %s, close old w/Addr %s\n", time.Now(), hostname, addr)
				e.wsConn.Close()
				addOK = true
			}
		}
		if !addOK {
			err := conn.WriteMessage(websocket.TextMessage, []byte(moretwoMsg))
			if needDebug {
				fmt.Printf("websocket write: %v\n", err)
			}
			connMutex.Unlock()
			return
		}
	}

	ep := endPoint{
		wsConn:   conn,
		hostname: hostname,
	}
	if _, ok := reqAddrTokenEP[token][remoteAddr]; !ok {
		reqAddrTokenEP[token][remoteAddr] = ep
	}
	sizeMap := len(tmpMap)
	connMutex.Unlock()
	if sizeMap < 2 {
		err := conn.WriteMessage(websocket.TextMessage, []byte(noDeviceMsg))
		if needDebug {
			fmt.Printf("websocket write: %v\n", err)
		}
	}
	fmt.Printf("%v client %s from %s connected, ID: %d\n",
		time.Now().Format("2006-01-02 15:04:05"), hostname, remoteAddr, myConnID)

	// send peer's own endpoint IP over first
	_ = conn.WriteMessage(websocket.TextMessage, []byte(clientIPMsg+remoteAddr))

	cnt := 0
	nopeerPkts := 0
	for {
		messageType, message, err := conn.ReadMessage()
		now := time.Now()
		nowStr := now.Format("2006-01-02 15:04:05")
		if err != nil {
			fmt.Printf("%s on reading host %s from %s, ID %d: %v\n", nowStr, hostname, remoteAddr, myConnID, err)
			cleanConnMap(token, remoteAddr)
			break
		}

		connMutex.Lock()
		tmpMap = reqAddrTokenEP[token]
		if tmpMap == nil {
			connMutex.Unlock()
			continue
		}

		myEP := endPoint{}
		var peerAddr string

		for addr, e := range tmpMap {
			if remoteAddr == addr {
				continue
			}
			dest := strings.Split(addr, ":")
			if len(dest) == 2 {
				addr = dest[1]
			}
			if needDebug {
				fmt.Printf("%s (%d/%d): [%v], t-%d len %d, to %s\n",
					nowStr, myConnID, cnt, hostname, messageType, len(message), addr)
			}
			peerAddr = addr
			myEP = e
			nopeerPkts = 0
			break
		}
		connMutex.Unlock()

		if myEP.wsConn == nil {
			nopeerPkts++
			fmt.Printf("%s can not find peer %d\n", nowStr, nopeerPkts)
			if nopeerPkts < 50 { // need sometime for ep to reconnect
				continue
			}
			err = conn.WriteMessage(websocket.TextMessage, []byte(noDeviceMsg))
			if err != nil {
				fmt.Printf("Error during message writing: %v\n", err)
				cleanConnMap(token, remoteAddr)
				break
			}
			continue
		}
		err = myEP.wsConn.WriteMessage(messageType, message)
		if err != nil {
			fmt.Printf("Error during message from %s writing to %s, ID %d: %v\n", hostname, peerAddr, myConnID, err)
			cleanConnMap(token, remoteAddr)
			break
		}
		cnt++
	}
}

func cleanConnMap(token, remoteAddr string) {
	connMutex.Lock()
	tmpMap := reqAddrTokenEP[token]
	if tmpMap != nil {
		delete(tmpMap, remoteAddr)
		if len(tmpMap) == 0 {
			delete(reqAddrTokenEP, token)
		}
	}
	connMutex.Unlock()
}

// Get preferred outbound ip of this machine
func getOutboundIP() string {
	retryMax := 10

	var conn net.Conn
	var err error
	var count int
	for count < retryMax {
		conn, err = net.Dial("udp", "8.8.8.8:80")
		if err != nil {
			fmt.Println(err)
		} else {
			defer conn.Close()
			break
		}
		time.Sleep(2 * time.Second)
		count++
	}
	if conn == nil {
		return ""
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fmt.Fprintf(w, "pong\n")
	}
}

// the edge-view websocket dispatcher example
func main() {
	reqAddrTokenEP = make(map[string]map[string]endPoint)
	helpPtr := flag.Bool("h", false, "help string")
	debugPtr := flag.Bool("debug", false, "more debug info")
	portPtr := flag.String("port", "", "websocket listen port")
	certFilePtr := flag.String("cert", "", "server certificate pem file")
	keyFilePtr := flag.String("key", "", "server key pem file")
	flag.Parse()

	if *helpPtr {
		fmt.Println(" -h                    this help")
		fmt.Println(" -port <port number>   mandatory, tcp port number")
		fmt.Println(" -cert <path>          mandatory, server certificate path in PEM format")
		fmt.Println(" -key <path>           mandatory, server key file path in PEM format")
		fmt.Println(" -debug                optional, turn on more debug")
		return
	}

	if *debugPtr {
		needDebug = true
	}
	if *portPtr == "" {
		fmt.Println("port needs to be specified")
		return
	}
	if *certFilePtr == "" || *keyFilePtr == "" {
		fmt.Println("server cert and key files need to be specified")
		return
	}

	localIP := getOutboundIP()
	server := &http.Server{
		Addr: localIP + ":" + *portPtr,
	}

	http.HandleFunc("/edge-view", socketHandler)
	http.HandleFunc("/v1/ping", pingHandler)
	fmt.Printf("Listen TLS on: %s:%s\n", localIP, *portPtr)
	log.Fatal(server.ListenAndServeTLS(*certFilePtr, *keyFilePtr))
}
