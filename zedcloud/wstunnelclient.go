// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

package zedcloud

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	maxRetryAttempts = 50
)

// WSTunnelClient represents a persistent tunnel that can cycle through many websockets.
// The conn field points to the latest websocket,
// but it's important to realize that there may be goroutines handling older
// websockets that are not fully closed yet running at any point in time
type WSTunnelClient struct {
	TunnelServerName string        // hostname[:port] string representation of remote tunnel server
	Tunnel           string        // websocket server to connect to (ws[s]://hostname[:port])
	Server           string        // local HTTP(S) server to send received requests to
	Timeout          time.Duration // timeout on websocket
	Proxy            *url.URL      // if non-nil, external proxy to use
	Connected        bool          // true when we have an active connection to remote server
	exitChan         chan struct{} // channel to tell the tunnel goroutines to end
	conn             *WSConnection // reference to remote websocket connection
	failRetryCount   int           // no of times the ws connection attempts have continuously failed
}

// WSConnection represents a single websocket connection
type WSConnection struct {
	ws              *websocket.Conn // websocket connection
	tun             *WSTunnelClient // link back to tunnel
	localConnection net.Conn        // connection to local relay
}

var wsWriterMutex sync.Mutex // mutex to allow a single goroutine to send a response at a time
var connMutex sync.Mutex     // mutex to allow a single goroutine to check and re-initialize connection if required

// InitializeTunnelClient returns a websocket tunnel client configured with the
// requested remote and local servers.
func InitializeTunnelClient(serverName string, localRelay string) *WSTunnelClient {
	tunnelClient := WSTunnelClient{
		TunnelServerName: serverName,
		Tunnel:           "wss://" + serverName,
		Server:           localRelay,
		Timeout:          calcWsTimeout(30),
	}

	return &tunnelClient
}

// Start triggers the connection to remote tunnel server
func (t *WSTunnelClient) Start(proxyURL *url.URL) {
	go func() {
		t.SetupConnection(proxyURL)
		<-make(chan struct{}, 0)
	}()
}

// SetupConnection connects to configured backend on a
// secure websocket and waits for commands from the backend
// to forward to local relay.
func (t *WSTunnelClient) SetupConnection(proxyURL *url.URL) error {

	if t.Tunnel == "" {
		return fmt.Errorf("Must specify tunnel server ws://hostname:port using -tunnel option")
	}
	if !strings.HasPrefix(t.Tunnel, "ws://") && !strings.HasPrefix(t.Tunnel, "wss://") {
		return fmt.Errorf("Remote tunnel (-tunnel option) must begin with ws:// or wss://")
	}
	t.Tunnel = strings.TrimSuffix(t.Tunnel, "/")

	if t.Server != "" {
		if strings.HasPrefix(t.Server, "http://") && strings.HasPrefix(t.Server, "https://") {
			return fmt.Errorf("Local server relay must not begin with http:// or https://")
		}
		t.Server = strings.TrimSuffix(t.Server, "/")
	}

	if t.Server == "" {
		return fmt.Errorf("Must specify server")
	}

	if proxyURL != nil {
		t.Proxy = proxyURL
	}

	// signal that tells tunnel client to exit instead of reopening
	// a fresh connection.
	t.exitChan = make(chan struct{}, 1)

	t.failRetryCount = 0

	// Keep opening websocket connections to tunnel requests
	go func() {
		log.Println("Looping through websocket connection requests")
		for {
			// Retry timer of 30 seconds between attempts.
			timer := time.NewTimer(30 * time.Second)

			tlsConfig, err := GetTlsConfig(t.TunnelServerName, nil)
			if err != nil {
				log.Fatal(err)
			}
			dialer := &websocket.Dialer{
				ReadBufferSize:  100 * 1024,
				WriteBufferSize: 100 * 1024,
				TLSClientConfig: tlsConfig,
			}
			if t.Proxy != nil {
				dialer.Proxy = http.ProxyURL(t.Proxy)
			}

			url := fmt.Sprintf("%s/api/v1/edgedevice/connection/tunnel", t.Tunnel)
			log.Printf("Attempting WS connection to url: %s", url)

			ws, resp, err := dialer.Dial(url, nil)
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
				t.failRetryCount++
				if t.failRetryCount == maxRetryAttempts {
					log.Errorf("Initiating tunnel client shutdown after %d failed attempts.", maxRetryAttempts)
					t.Stop()
				}
			} else {
				t.conn = &WSConnection{ws: ws, tun: t}
				// Safety setting
				ws.SetReadLimit(100 * 1024 * 1024)
				// Request Loop
				t.Connected = true
				t.failRetryCount = 0
				t.conn.handleRequests()
				t.Connected = false
			}
			// check whether we need to exit
			select {
			case <-t.exitChan:
				log.Println("Received WS tunnel client exit")
				break
			default: // non-blocking receive
			}

			// ensure we don't open connections too rapidly,
			<-timer.C
		}
	}()

	log.Println("Shutting down WS tunnel client, exit!")
	return nil
}

// Stop tunnel client
func (t *WSTunnelClient) Stop() {
	log.Println("Stopping WS tunnel client")
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
			log.Errorf("WS ReadMessage Error: %s", err.Error())
			break
		}
		if messageType != websocket.BinaryMessage {
			log.Errorf("WS ReadMessage Invalid message type: %d", messageType)
			break
		}
		// give the sender a minute to produce the request
		wsc.ws.SetReadDeadline(time.Now().Add(time.Minute))
		// read request id
		var id int16
		_, err = fmt.Fscanf(io.LimitReader(reader, 4), "%04x", &id)
		if err != nil {
			log.Errorf("WS cannot read request ID Error: %s", err.Error())
			break
		}
		// read the whole message, this is bounded (to something large) by the
		// SetReadLimit on the websocket. We have to do this because we want to handle
		// the request in a goroutine (see "go process..Request" calls below) and the
		// websocket doesn't allow us to have multiple goroutines reading...
		request, err := ioutil.ReadAll(reader)
		if err != nil {
			//log.Printf("[id=%d] WS cannot read request message Error: %s", id, err.Error())
			break
		}
		log.Printf("[id=%d] WS processing request payload: %v", id, string(request))

		// Finish off while we read the next request

		if len(request) > 0 {
			if err := wsc.processRequest(id, request); err != nil {
				log.Error(err)
			}
		} else {
			log.Errorf("[id=%d] Encountered WS request to process with no payload", id)
		}

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

//===== TCP driver and response sender =====
func (wsc *WSConnection) processRequest(id int16, req []byte) (err error) {

	host := wsc.tun.Server
	if err := wsc.refreshLocalConnection(host, false); err != nil {
		return err
	}
	//log.Printf("[id=%d] Forwarding request: %v to local connection: %s", id, string(req), host)
	for tries := 1; tries <= 3; tries++ {
		_, err := wsc.localConnection.Write(req)
		if err == nil {
			//log.Printf("[id=%d] Completed writing request: \"%s\" to local connection", id, string(req))
			break
		} else {
			log.Errorf("[id=%d] Error encountered while writing request to local connection : %s", id, err.Error())
			if err := wsc.refreshLocalConnection(host, true); err != nil {
				return err
			}
		}
	}
	go wsc.listenForResponse(id)
	return nil
}

func (wsc *WSConnection) refreshLocalConnection(host string, forceCreate bool) (err error) {

	connMutex.Lock()
	defer connMutex.Unlock()

	if wsc.localConnection != nil && !forceCreate {
		c := wsc.localConnection
		one := []byte{}
		c.SetReadDeadline(time.Now())
		_, err := c.Read(one)
		if err != nil {
			log.Errorf("Error encountered while testing local connection: %s", err.Error())
			if err == io.EOF ||
				err == io.ErrClosedPipe ||
				err == io.ErrUnexpectedEOF {
				log.Println("Lost local server connection, reconnecting...")
				if err := wsc.dialLocalConnection(host); err != nil {
					return err
				}
			}
		}
	} else {
		if err := wsc.dialLocalConnection(host); err != nil {
			return err
		}
	}
	return nil
}

func (wsc *WSConnection) dialLocalConnection(host string) (err error) {

	if host == "" {
		log.Error("Local server not found for WS connection")
		return
	}

	log.Printf("Initializing local server connection: %s", host)
	wsc.localConnection, err = net.Dial("tcp", host)
	if err != nil {
		log.Errorf("Could not connect to local server: %s, error: %s", host, err.Error())
		return err
	}
	log.Printf("Successfully connected to local server: %s", host)
	return nil
}

func (wsc *WSConnection) listenForResponse(id int16) {
	//log.Printf("[id=%d] Waiting for response on local connection", id)
	wsc.localConnection.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuffer := make([]byte, 8192)
	num, err := wsc.localConnection.Read(responseBuffer)
	if err != nil {
		//log.Printf("[id=%d] Could not read response on local connection: %s", id, err.Error())
	} else {
		if num > 0 {
			response := responseBuffer[:num]
			log.Printf("[id=%d] Read local connection payload: \"%s\"", id, string(response))
			wsc.writeResponseMessage(id, bytes.NewBuffer(response))
		} else {
			//log.Printf("[id=%d] Empty response received from local connection", id)
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
