// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/sirupsen/logrus"
)

// HTTPServer : HTTP server.
type HTTPServer struct {
	// ServerName : logical name for the HTTP server.
	ServerName string
	// ListenIP : IP address on which the server should listen.
	ListenIP net.IP
	// ListenIf : reference to interface which is expected to have ListenIP assigned.
	ListenIf NetworkIf
	// Port : port to listen for HTTP requests.
	Port uint16
	// Handler is used to respond to an HTTP request.
	Handler http.Handler
}

// Name returns the logical label assigned to the HTTP server.
func (s HTTPServer) Name() string {
	return s.ServerName
}

// Label for the HTTP server.
func (s HTTPServer) Label() string {
	return s.ServerName + " (HTTP server)"
}

// Type of the item.
func (s HTTPServer) Type() string {
	return HTTPServerTypename
}

// Equal compares two HTTPServer instances
// However, only HTTP server addresses are compared, skipping Handler attributes
// This is because:
//   - not possible to compare (interface)
//   - HTTPServerConfigurator only cares about starting/stopping the HTTP server
//     and the handlers can freely change without having to restart the server.
func (s HTTPServer) Equal(other dg.Item) bool {
	s2 := other.(HTTPServer)
	return s.ServerName == s2.ServerName &&
		utils.EqualIPs(s.ListenIP, s2.ListenIP) &&
		s.ListenIf == s2.ListenIf &&
		s.Port == s2.Port
}

// External returns false.
func (s HTTPServer) External() bool {
	return false
}

// String describes the HTTP server.
func (s HTTPServer) String() string {
	return fmt.Sprintf("HTTPServer: {serverName: %s, listenIP: %s, "+
		"listenIf: %s, port: %d}", s.ServerName, s.ListenIP, s.ListenIf.IfName, s.Port)
}

// Dependencies returns the interface on which the HTTP server listens
// as the only dependency. It is assumed that if the interface is created,
// it has ListenIP assigned.
func (s HTTPServer) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: s.ListenIf.ItemRef,
		Description:  "interface on which the HTTP server listens must exist",
	})
	return deps
}

// HTTPServerConfigurator implements Configurator interface (libs/reconciler)
// for HTTPServer.
type HTTPServerConfigurator struct {
	Log         *base.LogObject
	Logger      *logrus.Logger
	httpServers map[string]httpSrvGoRoutine // key: ServerName
}

type httpSrvGoRoutine struct {
	ctx         context.Context
	cancelFn    context.CancelFunc
	serveDoneCh chan error
}

// Create starts HTTP server.
// Create executes in the background and is done (from the Reconciler point of view)
// once net.Listen succeeds - however the same Go routine is used to run the HTTP server
// (and is stopped only later by Delete()).
func (c *HTTPServerConfigurator) Create(ctx context.Context, item dg.Item) error {
	httpServer, isHTTPServer := item.(HTTPServer)
	if !isHTTPServer {
		return fmt.Errorf("invalid item type %T, expected HTTPServer", item)
	}
	listenDoneFn := reconciler.ContinueInBackground(ctx)
	serveDoneCh := make(chan error, 1)
	serveDoneFn := func(err error) {
		serveDoneCh <- err
	}
	goRoutineCtx, cancelFn := context.WithCancel(ctx)
	goRoutine := httpSrvGoRoutine{
		ctx:         goRoutineCtx,
		cancelFn:    cancelFn,
		serveDoneCh: serveDoneCh,
	}
	if c.httpServers == nil {
		c.httpServers = make(map[string]httpSrvGoRoutine)
	}
	c.httpServers[httpServer.ServerName] = goRoutine
	go c.runServer(goRoutineCtx, httpServer.ServerName, httpServer.Handler,
		httpServer.ListenIP, listenDoneFn, serveDoneFn)
	return nil
}

// Modify is not implemented.
func (c *HTTPServerConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops HTTP server.
func (c *HTTPServerConfigurator) Delete(ctx context.Context, item dg.Item) error {
	httpServer, isHTTPServer := item.(HTTPServer)
	if !isHTTPServer {
		return fmt.Errorf("invalid item type %T, expected HTTPServer", item)
	}
	goRoutine, isRunning := c.httpServers[httpServer.ServerName]
	if !isRunning {
		return fmt.Errorf("go routine for HTTP server %s is not running",
			httpServer.ServerName)
	}
	delete(c.httpServers, httpServer.ServerName)
	// Shutdown procedure waits (sleeps) some (fixed) time for all sockets associated
	// with the server to close - better to run this asynchronously.
	shutdownDoneFn := reconciler.ContinueInBackground(ctx)
	go func() {
		goRoutine.cancelFn()
		err := <-goRoutine.serveDoneCh
		shutdownDoneFn(err)
	}()
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *HTTPServerConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}

func (c *HTTPServerConfigurator) runServer(ctx context.Context, srvName string,
	handler http.Handler, listenIP net.IP, listenDoneFn, serveDoneFn func(error)) {
	w := c.Logger.Writer()
	defer w.Close()
	srv := http.Server{
		Addr:         listenIP.String() + ":80",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ErrorLog:     stdlog.New(w, fmt.Sprintf("http server(%v): ", listenIP), 0),
	}
	// No need for http keepalives for the cloud-init API endpoints
	srv.SetKeepAlivesEnabled(false)

	var listener net.Listener
	logPrefix := fmt.Sprintf("HTTPServerConfigurator (%s)", srvName)

	// Try with sleep in case the listener isn't yet gone from the kernel
	// (the golang net/http on Linux seems to sometimes have it remain
	// for a long time after the Shutdown)
	// Since we are running in a separate go routine we can keep on trying
	// and poking forever, however we look at ctx to bail if Delete is going
	// to be called.
	startListen := time.Now()
	first := true
	for {
		ubSockets := c.getConnStats(srv.Addr)
		if len(ubSockets) != 0 {
			c.Log.Warnf("%s: waiting for %d sockets: %s",
				logPrefix, len(ubSockets), ubSockets)
		}
		var err error
		listener, err = net.Listen("tcp", srv.Addr)
		if err == nil {
			break
		}
		c.Log.Warnf("%s: listen on %s failed: %s", logPrefix, srv.Addr, err)
		if listener != nil {
			_ = listener.Close()
		}
		// dump stacks for debug once
		if first {
			agentlog.DumpAllStacks(c.Log, "zedrouter")
			first = false
		}
		// Force any previous listener blocked in Accept() to unblock by connecting to it.
		c.unblockAccept(srv.Addr, "listen wait")
		select {
		case <-ctx.Done():
			c.Log.Noticef("%s: stopped trying to Listen, context is done", logPrefix)
			// Return error from net.Listen to Reconciler.
			listenDoneFn(err)
			return
		case <-time.After(2 * time.Second):
			// Try Listen again.
			continue
		}
	}
	if listener == nil {
		// Will not happen due to loop above.
		c.Log.Fatalf("%s: listen %s failed", logPrefix, srv.Addr)
	}
	c.Log.Noticef("%s: Got listener for %s after %v",
		logPrefix, srv.Addr, time.Since(startListen))
	// Create(HTTPServer) is done.
	listenDoneFn(nil)

	// Use a separate Go routine to shut down the server when requested
	// from Delete().
	idleConnsClosed := make(chan struct{})
	go func() {
		<-ctx.Done()
		c.Log.Noticef("%s: context is done for %s", logPrefix, srv.Addr)
		// We received an interrupt signal, shut down.
		// Use short deadline to make Accept() wake up after the Shutdown has marked
		// the internal state as closing.
		tcpListener := listener.(*net.TCPListener)
		if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			c.Log.Errorf("%s: SetDeadline failed for %s: %s", logPrefix, srv.Addr, err)
		}
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			c.Log.Noticef("%s: shutdown of server on %s failed: %s",
				logPrefix, srv.Addr, err)
		}
		// Wait for the above deadline to pass.
		time.Sleep(2 * time.Second)
		// Force Accept() to unblock by connecting.
		c.unblockAccept(srv.Addr, "shutdown")
		close(idleConnsClosed)
		c.Log.Noticef("%s: closed idleConnsClosed for %s", logPrefix, srv.Addr)
	}()

	serveErr := srv.Serve(listener)
	if serveErr == http.ErrServerClosed {
		// This is normal shutdown of the server
		c.Log.Noticef("%s: server on %s closed", logPrefix, srv.Addr)
		serveErr = nil
	}

	// Cleanup after shutdown to make sure we do not leave any open sockets.
	c.Log.Noticef("%s: waiting for idleConnsClosed on %s", logPrefix, srv.Addr)
	<-idleConnsClosed
	c.Log.Noticef("%s: done waiting for idleConnsClosed on %s", logPrefix, srv.Addr)
	// Just in case
	if err := srv.Close(); err != nil {
		c.Log.Errorf("%s: srv.Close failed: %s", logPrefix, err)
	}
	// Did all the sockets go away?
	sockets := c.getConnStats(srv.Addr)
	if len(sockets) != 0 {
		c.Log.Warnf(
			"%s: %d sockets still open after Close for %s: %v",
			logPrefix, len(sockets), srv.Addr, sockets)
		// Force Accept() to unblock by connecting.
		c.unblockAccept(srv.Addr, "post Close")
		sockets = c.getConnStats(srv.Addr)
		if len(sockets) != 0 {
			c.Log.Warnf(
				"%s: %d sockets still open after Close AND unblockAccept for %s: %v",
				logPrefix, len(sockets), srv.Addr, sockets)
		}
	}
	c.Log.Noticef("%s: stopped HTTP server on %s", logPrefix, srv.Addr)
	serveDoneFn(serveErr)
}

// unblockAccept connects to ourselves in case the server is blocked in
// the Accept call
// Normally when this is called we get a "connection refused" since the
// listener should have closed.
func (c *HTTPServerConfigurator) unblockAccept(addr string, where string) {
	// Just want to send the SYN to unblock
	d := net.Dialer{Timeout: 100 * time.Millisecond}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		if isECONNREFUSED(err) {
			c.Log.Noticef("unblockAccept(%s tag %s) got expected connection refused",
				addr, where)
		} else {
			c.Log.Errorf("unblockAccept(%s tag %s) dial failed: %s",
				addr, where, err)
		}
		return
	}
	if err := conn.Close(); err != nil {
		c.Log.Errorf("unblockAccept(%s tag %s) close failed: %s",
			addr, where, err)
		return
	}
	c.Log.Warnf("unblockAccept(%s tag %s) unexpectedly succeeded and closed",
		addr, where)
}

// getConnStats is used to collect some debug output from netstat.
func (c *HTTPServerConfigurator) getConnStats(match string) string {
	cmd := "netstat -antwp | grep " + match
	output, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		// Normal if empty output
		c.Log.Functionf("exec netstat failed: %v", err)
	}
	return string(output)
}

func isECONNREFUSED(e0 error) bool {
	e1, ok := e0.(*net.OpError)
	if !ok {
		return false
	}
	e2, ok := e1.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errno, ok := e2.Err.(syscall.Errno)
	if !ok {
		return false
	}
	return errno == syscall.ECONNREFUSED
}
