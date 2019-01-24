package zedcloud

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var localTCP string
var binaryMode bool

//var addr = flag.String("addr", "zedcontrol.zededa.net", "http service address")
var addr = flag.String("addr", "zedcontrol.zededa.net", "http service address")
var localConnection net.Conn

// WSTunnelClient represents a persistent tunnel that can cycle through many websockets. The
// fields in this struct are relatively static/constant. The conn field points to the latest
// websocket, but it's important to realize that there may be goroutines handling older
// websockets that are not fully closed yet running at any point in time
type WSTunnelClient struct {
	TunnelServerName string        // hostname[:port] string representation of remote tunnel server
	Tunnel           string        // websocket server to connect to (ws[s]://hostname:port)
	Server           string        // local HTTP(S) server to send received requests to (default server)
	Insecure         bool          // accept self-signed SSL certs from local HTTPS servers
	Timeout          time.Duration // timeout on websocket
	Proxy            *url.URL      // if non-nil, external proxy to use
	Connected        bool          // true when we have an active connection to wstunsrv
	exitChan         chan struct{} // channel to tell the tunnel goroutines to end
	conn             *WSConnection
}

// WSConnection represents a single websocket connection
type WSConnection struct {
	ws  *websocket.Conn // websocket connection
	tun *WSTunnelClient // link back to tunnel
}

var httpClient http.Client // client used for all requests, gets special transport for -insecure

func InitializeTunnelClient(serverName string, localRelay string) *WSTunnelClient {
	tunnelClient := WSTunnelClient{
		TunnelServerName: serverName,
		Tunnel:           "wss://" + serverName,
		Server:           localRelay,
		Insecure:         false,
		Timeout:          calcWsTimeout(30),
	}

	/*var proxy *string = cliFlag.String("proxy", "",
		"use HTTPS proxy http://user:pass@hostname:port")

	cliFlag.Parse(args)*/

	// process -proxy or look for standard unix env variables
	/*if *proxy == "" {
		envNames := []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}
		for _, n := range envNames {
			if p := os.Getenv(n); p != "" {
				*proxy = p
				break
			}
		}
	}
	if *proxy != "" {
		proxyURL, err := url.Parse(*proxy)
		if err != nil || !strings.HasPrefix(proxyURL.Scheme, "http") {
			// proxy was bogus. Try prepending "http://" to it and
			// see if that parses correctly. If not, we fall
			// through and complain about the original one.
			if proxyURL, err = url.Parse("http://" + *proxy); err != nil {
				////log.Printf(fmt.Sprintf("Invalid proxy address: %q, %v", *proxy, err.Error()))
				os.Exit(1)
			}
		}

		tunnelClient.Proxy = proxyURL
	}*/

	return &tunnelClient
}

// Start connection to tunnel server
func (t *WSTunnelClient) Start() {

	t.SetupConnection()
	<-make(chan struct{}, 0)
}

// SetupConnection connects to configured backend on a
// secure websocket and waits for commands from the backend
// to forward to local relay.
func (t *WSTunnelClient) SetupConnection() error {

	// validate -tunnel
	if t.Tunnel == "" {
		return fmt.Errorf("Must specify tunnel server ws://hostname:port using -tunnel option")
	}
	if !strings.HasPrefix(t.Tunnel, "ws://") && !strings.HasPrefix(t.Tunnel, "wss://") {
		return fmt.Errorf("Remote tunnel (-tunnel option) must begin with ws:// or wss://")
	}
	t.Tunnel = strings.TrimSuffix(t.Tunnel, "/")

	// validate -server
	if t.Server != "" {
		if strings.HasPrefix(t.Server, "http://") && strings.HasPrefix(t.Server, "https://") {
			return fmt.Errorf("Local server relay must not begin with http:// or https://")
		}
		t.Server = strings.TrimSuffix(t.Server, "/")
	}

	if t.Insecure {
		log.Println("Accepting unverified SSL certs from local HTTPS servers")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		httpClient = http.Client{Transport: tr}
	}

	if t.Server == "" {
		return fmt.Errorf("Must specify server")
	}

	/*if t.Proxy != nil {
		username := "(none)"
		if u := t.Proxy.User; u != nil {
			username = u.Username()
		}
		log.Println("Using HTTPS proxy", "url", t.Proxy.Host, "user", username)
	}*/

	// for test purposes we have a signal that tells wstuncli to exit instead of reopening
	// a fresh connection.
	t.exitChan = make(chan struct{}, 1)

	//===== Goroutine =====

	// Keep opening websocket connections to tunnel requests
	go func() {
		log.Println("Looping through websocket connection requests")
		tlsConfig, err := GetTlsConfig(t.TunnelServerName, nil)
		if err != nil {
			log.Fatal(err)
		}
		for {
			log.Println("Initializing websocket dialer")
			dialer := &websocket.Dialer{
				NetDial:         t.wsProxyDialer,
				ReadBufferSize:  100 * 1024,
				WriteBufferSize: 100 * 1024,
				TLSClientConfig: tlsConfig,
			}
			log.Println("Initializing websocket header")
			header := make(http.Header)
			header.Add("Origin", *addr)
			url := fmt.Sprintf("%s/api/v1/edgedevice/connection/tunnel", t.Tunnel)
			log.Printf("WS Connection url: %s", url)
			timer := time.NewTimer(10 * time.Second)
			ws, resp, err := dialer.Dial(url, header)
			if err != nil {
				extra := ""
				if resp != nil {
					extra = resp.Status
					buf := make([]byte, 80)
					resp.Body.Read(buf)
					if len(buf) > 0 {
						extra = extra + " -- " + string(buf)
					}
					resp.Body.Close()
				}
				log.Printf("Error opening connection: %v, response: %v", err.Error(), resp)
			} else {
				t.conn = &WSConnection{ws: ws, tun: t}
				// Safety setting
				ws.SetReadLimit(100 * 1024 * 1024)
				// Request Loop
				t.Connected = true
				t.conn.handleRequests()
				t.Connected = false
			}
			// check whether we need to exit
			select {
			case <-t.exitChan:
				break
			default: // non-blocking receive
			}

			<-timer.C // ensure we don't open connections too rapidly
		}
	}()

	return nil
}

// Stop tunnel client
func (t *WSTunnelClient) Stop() {
	t.exitChan <- struct{}{}
}

// Main function to handle WS requests: it reads a request from the socket, then forks
// a goroutine to perform the actual http request and return the result
func (wsc *WSConnection) handleRequests() {
	go wsc.pinger()
	for {
		wsc.ws.SetReadDeadline(time.Time{}) // separate ping-pong routine does timeout
		messageType, reader, err := wsc.ws.NextReader()
		if err != nil {
			log.Printf("WS ReadMessage Error: %s", err.Error())
			break
		}
		if messageType != websocket.BinaryMessage {
			log.Printf("WS ReadMessage Invalid message type: %d", messageType)
			break
		}
		// give the sender a minute to produce the request
		wsc.ws.SetReadDeadline(time.Now().Add(time.Minute))
		// read request id
		var id int16
		_, err = fmt.Fscanf(io.LimitReader(reader, 4), "%04x", &id)
		if err != nil {
			log.Printf("WS cannot read request ID Error: %s", err.Error())
			break
		}
		// read the whole message, this is bounded (to something large) by the
		// SetReadLimit on the websocket. We have to do this because we want to handle
		// the request in a goroutine (see "go finish..Request" calls below) and the
		// websocket doesn't allow us to have multiple goroutines reading...
		request, err := ioutil.ReadAll(reader)
		if err != nil {
			log.Printf("[id=%d] WS cannot read request message Error: %s", id, err.Error())
			break
		}
		log.Printf("[id=%d] WS processing request payload: %s of length: %d", id, string(request), len(request))

		// Finish off while we read the next request
		wsc.processRequest(id, request)
	}
	// delay a few seconds to allow for writes to drain and then force-close the socket
	go func() {
		log.Println("Closing websocket connection")
		time.Sleep(5 * time.Second)
		wsc.ws.Close()
	}()
}

//===== Keep-alive ping-pong =====

// Pinger that keeps connections alive and terminates them if they seem stuck
func (wsc *WSConnection) pinger() {
	defer func() {
		// panics may occur in WriteControl (in unit tests at least) for closed
		// websocket connections
		if x := recover(); x != nil {
			log.Printf("Panic in pinger: %s", x)
		}
	}()
	log.Println("pinger starting")
	tunTimeout := wsc.tun.Timeout

	// timeout handler sends a close message, waits a few seconds, then kills the socket
	timeout := func() {
		if wsc.ws == nil {
			return
		}
		wsc.ws.WriteControl(websocket.CloseMessage, nil, time.Now().Add(1*time.Second))
		log.Println("ping timeout, closing WS")
		time.Sleep(15 * time.Second)
		if wsc.ws != nil {
			wsc.ws.Close()
		}
	}
	// timeout timer
	timer := time.AfterFunc(tunTimeout, timeout)
	// pong handler resets last pong time
	ph := func(message string) error {
		timer.Reset(tunTimeout)
		return nil
	}
	wsc.ws.SetPongHandler(ph)
	// ping loop, ends when socket is closed...
	for {
		if wsc.ws == nil {
			log.Println("WS not found")
			break
		}
		err := wsc.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(tunTimeout/3))
		if err != nil {
			log.Fatalf("WS WriteControl Error: %s", err.Error())
			break
		}
		time.Sleep(tunTimeout / 3)
	}
	log.Println("pinger ending (WS errored or closed)")
	wsc.ws.Close()
}

//===== Proxy support =====
// Bits of this taken from golangs net/http/transport.go. Gorilla websocket lib
// allows you to pass in a custom net.Dial function, which it will call instead
// of net.Dial. net.Dial normally just opens up a tcp socket for you. We go one
// extra step and issue an HTTP CONNECT command after the socket is open. After
// HTTP CONNECT is issued and successful, we hand the reins back to gorilla,
// which will then set up SSL and handle the websocket UPGRADE request.
// Note this only handles HTTPS connections through the proxy. HTTP requires
// header rewriting.
func (t *WSTunnelClient) wsProxyDialer(network string, addr string) (conn net.Conn, err error) {
	if t.Proxy == nil {
		log.Printf("WS Connect to : %s::%s", network, addr)
		return net.Dial(network, addr)
	}

	conn, err = net.Dial("tcp", t.Proxy.Host)
	if err != nil {
		err = fmt.Errorf("WS: error connecting to proxy %s: %s", t.Proxy.Host, err.Error())
		return nil, err
	}

	pa := proxyAuth(t.Proxy)

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	if pa != "" {
		connectReq.Header.Set("Proxy-Authorization", pa)
	}
	connectReq.Write(conn)

	// Read and parse CONNECT response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		f := strings.SplitN(resp.Status, " ", 2)
		conn.Close()
		return nil, fmt.Errorf(f[1])
	}
	return conn, nil
}

// proxyAuth returns the Proxy-Authorization header to set
// on requests, if applicable.
func proxyAuth(proxy *url.URL) string {
	if u := proxy.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + basicAuth(username, password)
	}
	return ""
}

// See 2 (end of page 4) http://www.ietf.org/rfc/rfc2617.txt
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

//===== TCP driver and response sender =====

var wsWriterMutex sync.Mutex // mutex to allow a single goroutine to send a response at a time
var connMutex sync.Mutex     //mutex to allow a single goroutine to check and re-initialize connection if required

func (wsc *WSConnection) processRequest(id int16, req []byte) {

	host := wsc.tun.Server
	conn := getLocalConnection(host)
	log.Printf("[id=%d] Forwarding request: \"%s\" to local connection: %s", id, string(req), host)
	for tries := 1; tries <= 3; tries++ {
		_, err := conn.Write(req)
		if err == nil {
			log.Printf("[id=%d] Completed writing request: \"%s\" to local connection", id, string(req))
			break
		} else {
			log.Fatalf("[id=%d] Error encountered while writing request to local connection : %s", id, err.Error())
		}
	}
	go wsc.listenForResponse(id, conn)
}

func getLocalConnection(host string) (conn net.Conn) {

	connMutex.Lock()
	defer connMutex.Unlock()

	if localConnection != nil {
		c := localConnection
		one := []byte{}
		c.SetReadDeadline(time.Now())
		_, err := c.Read(one)
		if err != nil {
			log.Fatalf("Error encountered while testing local connection: %s", err.Error())
			if err == io.EOF ||
				err == io.ErrClosedPipe ||
				err == io.ErrUnexpectedEOF {
				log.Println("Lost local server connection, reconnecting...")
				dialLocalConnection(host)
			}
		}
	} else {
		log.Println("No local server connection found, connecting...")
		dialLocalConnection(host)
	}
	return localConnection
}

func dialLocalConnection(host string) {

	if host == "" {
		log.Println("Local server not found for WS connection")
		return
	}

	log.Printf("Initializing local server connection: %s", host)
	var err error
	localConnection, err = net.Dial("tcp", host)
	if err != nil {
		log.Printf("Could not connect to local server: %s, error: %s", host, err.Error())
		return
	}
	log.Printf("Successfully connected to local server: %s", host)
}

func (wsc *WSConnection) listenForResponse(id int16, conn net.Conn) {
	log.Printf("[id=%d] Waiting for response on local connection", id)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuffer := make([]byte, 8192)
	num, err := conn.Read(responseBuffer)
	if err != nil {
		log.Printf("[id=%d] Could not read response on local connection: %s", id, err.Error())
	} else {
		if num > 0 {
			response := responseBuffer[:num]
			log.Printf("[id=%d] Read local connection data of length: %d, payload: \"%s\"", id, num, string(response))
			wsc.writeResponseMessage(id, bytes.NewBuffer(response))
		} else {
			log.Printf("[id=%d] Empty response received from local connection", id)
		}
	}
}

// Write the response message to the websocket
func (wsc *WSConnection) writeResponseMessage(id int16, resp *bytes.Buffer) {
	// Get writer's lock
	wsWriterMutex.Lock()
	defer wsWriterMutex.Unlock()
	// Write response into the tunnel
	wsc.ws.SetWriteDeadline(time.Now().Add(time.Minute))
	writer, err := wsc.ws.NextWriter(websocket.BinaryMessage)
	// got an error, reply with a "hey, retry" to the request handler
	if err != nil {
		wsc.ws.Close()
		return
	}

	// write the request Id
	_, err = fmt.Fprintf(writer, "%04x", id)
	if err != nil {
		wsc.ws.Close()
		return
	}

	// write the response itself
	_, err = io.Copy(writer, resp)
	if err != nil {
		log.Printf("WS cannot write response: %s", err.Error())
		wsc.ws.Close()
		return
	}

	// done
	err = writer.Close()
	if err != nil {
		wsc.ws.Close()
		return
	}
}

func calcWsTimeout(tout int) time.Duration {
	var wsTimeout time.Duration
	if tout < 3 {
		wsTimeout = 3 * time.Second
	} else if tout > 600 {
		wsTimeout = 600 * time.Second
	} else {
		wsTimeout = time.Duration(tout) * time.Second
	}
	return wsTimeout
}
