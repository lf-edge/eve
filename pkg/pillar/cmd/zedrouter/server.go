// Copyright (c) 2020-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A http server providing meta-data information to application instances
// at http://169.254.169.254. The source IP address is used to tell
// which app instance is sending the request

package zedrouter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Provides a json file
type networkHandler struct {
	ctx *zedrouterContext
}

// Provides a LF-terminated text
type externalIPHandler struct {
	ctx *zedrouterContext
}

// Provides a LF-terminated text
type hostnameHandler struct {
	ctx *zedrouterContext
}

// Provides links for OpenStack metadata/userdata
type openstackHandler struct {
	ctx *zedrouterContext
}

// Provides k3s cluster kubeconfig
type kubeConfigHandler struct {
	ctx *zedrouterContext
}

// KubeconfigFileSizeLimitInBytes holds the maximum expected size of Kubeconfig file received from k3s server appInst.
// Note: KubeconfigFileSizeLimitInBytes should always be < AppInstMetadataResponseSizeLimitInBytes.
const KubeconfigFileSizeLimitInBytes = 32768 // 32KB

// AppInstMetadataResponseSizeLimitInBytes holds the maximum expected size of appInst metadata received in the response.
// Note: KubeconfigFileSizeLimitInBytes should always be < AppInstMetadataResponseSizeLimitInBytes.
const AppInstMetadataResponseSizeLimitInBytes = 35840 // 35KB

func createServer4(ctx *zedrouterContext, bridgeIP string, bridgeName string) error {
	if bridgeIP == "" {
		err := fmt.Errorf("can't run meta-data server on %s: no bridgeIP", bridgeName)
		log.Warn(err)
		return err
	}
	done := incrementDoneChanRefcount(bridgeName, bridgeIP)
	if done {
		log.Functionf("http meta-data server already running for Bridge %s, IP %s: incremented refcount",
			bridgeName, bridgeIP)
		return nil
	}
	mux := http.NewServeMux()
	nh := &networkHandler{ctx: ctx}
	mux.Handle("/eve/v1/network.json", nh)
	ipHandler := &externalIPHandler{ctx: ctx}
	mux.Handle("/eve/v1/external_ipv4", ipHandler)
	hostnameHandler := &hostnameHandler{ctx: ctx}
	mux.Handle("/eve/v1/hostname", hostnameHandler)

	openstackHandler := &openstackHandler{ctx: ctx}
	mux.Handle("/openstack", openstackHandler)
	mux.Handle("/openstack/", openstackHandler)

	kubeConfigHandler := &kubeConfigHandler{ctx: ctx}
	mux.Handle("/eve/v1/kubeconfig", kubeConfigHandler)

	targetPort := 80
	subnetStr := "169.254.169.254/32"
	target := fmt.Sprintf("%s:%d", bridgeIP, targetPort)
	log.Noticef("add NAT to target %s", target)
	if err := iptables.IptableCmd(log, "-t", "nat", "-I", "PREROUTING",
		"-i", bridgeName, "-p", "tcp", "-d", subnetStr,
		"--dport", strconv.Itoa(targetPort),
		"-j", "DNAT", "--to-destination", target); err != nil {
		log.Errorf("failed to add DNAT: %s", err)
	}
	doneChan := make(chan struct{})
	ackChan := make(chan struct{})
	// Need one server per local IP address
	// XXX once we have an IPv6 bridge IP address add:
	// go runServer(mux, "tcp6", "["+bridgeIP6+"%"+bridgeName+"]")
	go runServer(mux, "tcp4", bridgeIP, doneChan, ackChan)
	setDoneChan(bridgeName, bridgeIP, doneChan, ackChan)
	log.Noticef("started http server on %s/%s", bridgeName, bridgeIP)
	return nil
}

func deleteServer4(ctx *zedrouterContext, bridgeIP string, bridgeName string) {
	log.Noticef("deleteServer4(%s %s)", bridgeIP, bridgeName)
	keepGoing := decrementDoneChanRefcount(bridgeName, bridgeIP)
	if keepGoing {
		log.Functionf("deleteServer4: Done chan refCount decremented for Bridge %s, IP %s",
			bridgeName, bridgeIP)
		return
	}
	targetPort := 80
	subnetStr := "169.254.169.254/32"
	target := fmt.Sprintf("%s:%d", bridgeIP, targetPort)
	log.Noticef("delete NAT from target %s", target)
	if err := iptables.IptableCmd(log, "-t", "nat", "-D", "PREROUTING",
		"-i", bridgeName, "-p", "tcp", "-d", subnetStr,
		"--dport", strconv.Itoa(targetPort),
		"-j", "DNAT", "--to-destination", target); err != nil {
		log.Errorf("failed to delete DNAT: %s", err)
	}
	doneChan, ackChan, ok := getDoneChan(bridgeName, bridgeIP)
	if !ok {
		log.Errorf("no doneChan to stop server on %s/%s",
			bridgeName, bridgeIP)
	} else {
		log.Noticef("telling server on %s/%s to exit",
			bridgeName, bridgeIP)
		doneChan <- struct{}{}
		log.Noticef("waiting for server on %s/%s to exit",
			bridgeName, bridgeIP)
		<-ackChan
	}
	log.Noticef("stopped http server on %s/%s", bridgeName, bridgeIP)
}

// map from bridgeName/bridgeIP to doneChanVal
type doneChanKey struct {
	bridgeName string
	bridgeIP   string
}

type doneChanVal struct {
	doneChan chan<- struct{}
	ackChan  <-chan struct{}
	refCount uint32
}

var mapToDoneChan = make(map[doneChanKey]doneChanVal)

func setDoneChan(bridgeName string, bridgeIP string, doneChan chan<- struct{},
	ackChan <-chan struct{}) {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	if _, exists := mapToDoneChan[key]; exists {
		log.Fatalf("setDoneChan: key already exists %+v", key)
	}
	mapToDoneChan[key] = doneChanVal{doneChan: doneChan, ackChan: ackChan, refCount: 1}
}

func getDoneChan(bridgeName string, bridgeIP string) (chan<- struct{}, <-chan struct{}, bool) {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	val, exists := mapToDoneChan[key]
	if !exists {
		log.Errorf("getDoneChan: key does not exist %+v", key)
	} else {
		delete(mapToDoneChan, key)
	}
	return val.doneChan, val.ackChan, exists
}

func incrementDoneChanRefcount(bridgeName string, bridgeIP string) bool {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	val, exists := mapToDoneChan[key]
	if !exists {
		log.Functionf("incrementDoneChanRefcount: Done chan does not exist yet for Bridge %s, IP %s",
			bridgeName, bridgeIP)
		return false
	} else {
		mapToDoneChan[key] = doneChanVal{
			doneChan: val.doneChan,
			ackChan:  val.ackChan,
			refCount: val.refCount + 1,
		}
	}
	return true
}

// Returns false if the caller should continue to stop/destroy the http meta-data server
func decrementDoneChanRefcount(bridgeName string, bridgeIP string) bool {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	val, exists := mapToDoneChan[key]
	if !exists {
		log.Fatalf("decrementDoneChanRefcount: Done chan does not exist yet for Bridge %s, IP %s",
			bridgeName, bridgeIP)
	} else {
		if val.refCount > 1 {
			mapToDoneChan[key] = doneChanVal{
				doneChan: val.doneChan,
				ackChan:  val.ackChan,
				refCount: val.refCount - 1,
			}
			return true
		}
	}
	return false
}

// getTCP is used to collect some debug output from netstat
func getTCP(match string) string {
	cmd := "netstat -antwp | grep " + match
	output, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		// Normal if empty output
		log.Functionf("exec netstat failed: %v", err)
	}
	return string(output)
}

func runServer(mux http.Handler, network string, ipaddr string,
	doneChan <-chan struct{}, ackChan chan<- struct{}) {

	w := logger.Writer()
	defer w.Close()
	srv := http.Server{
		Addr:         ipaddr + ":80",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ErrorLog:     stdlog.New(w, "http server("+ipaddr+"): ", 0),
	}
	// No need for http keepalives for the cloud-init API endpoints
	srv.SetKeepAlivesEnabled(false)

	var listener net.Listener

	// Try with sleep in case the listener isn't yet gone from the kernel
	// (the golang net/http on Linux seems to sometimes have it remain
	// for a long time after the Shutdown)
	// Since we are running in a separate go routine we can keep on trying
	// and poking forever, however we look at doneChan to bail if
	// deleteServer4 is telling us to go away
	startListen := time.Now()
	first := true
	for {
		// check if doneChan is telling is us to exit
		select {
		case <-doneChan:
			log.Noticef("Listener wait: read doneChan for %s",
				srv.Addr)
			ackChan <- struct{}{}
			log.Noticef("Listener wait: server on %s done after %v",
				srv.Addr, time.Since(startListen))
			return
		default:
		}
		var err error
		listener, err = net.Listen("tcp", srv.Addr)
		if err == nil {
			break
		}
		log.Warnf("listen %s failed: %s", srv.Addr, err)
		if listener != nil {
			listener.Close()
		}
		// dump stacks for debug once
		if first {
			agentlog.DumpAllStacks(log, "zedrouter")
			first = false
		}
		// Force any previous listener blocked in Accept() to unblock
		// by connecting to it
		unblockAccept(srv.Addr, "listen wait")
		time.Sleep(2 * time.Second)

		ubSockets := getTCP(srv.Addr)
		if len(ubSockets) != 0 {
			log.Warnf("Waiting for %d sockets: %s",
				len(ubSockets), ubSockets)
		}
	}
	if listener == nil {
		// Will not happen due to loop above
		log.Fatalf("listen %s failed", srv.Addr)
	}
	log.Noticef("Got listener for %s after %v",
		srv.Addr, time.Since(startListen))

	// Set up a handler for doneChan
	idleConnsClosed := make(chan struct{})
	go func() {
		log.Noticef("Waiting to read doneChan for %s", srv.Addr)
		<-doneChan
		log.Noticef("Done read doneChan for %s", srv.Addr)

		// We received an interrupt signal, shut down.

		// Use short deadline make Accept() wake up after the Shutdown
		// has marked the internal state as closing
		tcpListener := listener.(*net.TCPListener)
		if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			log.Errorf("SetDeadline failed for %s: %s",
				srv.Addr, err)
		}

		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Noticef("server on %s shutdown failed: %s",
				srv.Addr, err)
		}
		// Wait for the above deadline to pass
		time.Sleep(2 * time.Second)

		// Force Accept() to unblock by connecting
		unblockAccept(srv.Addr, "shutdown")

		close(idleConnsClosed)
		log.Noticef("Closed idleConnsClosed for %s", srv.Addr)
	}()

	if err := srv.Serve(listener); err != nil {
		if err == http.ErrServerClosed {
			log.Noticef("server on %s closed", srv.Addr)
		} else {
			log.Fatalf("server on %s failed: %s", srv.Addr, err)
		}
	}
	log.Noticef("Waiting for idleConnsClosed on %s", srv.Addr)
	<-idleConnsClosed
	log.Noticef("Done waiting for idleConnsClosed on %s", srv.Addr)
	ackChan <- struct{}{}
	// Just in case
	if err := srv.Close(); err != nil {
		log.Errorf("srv.Close failed: %s", err)
	}
	// Did all the sockets go away?
	doneSockets := getTCP(srv.Addr)
	if len(doneSockets) != 0 {
		log.Noticef("doneSockets for %s: %d %s",
			srv.Addr, len(doneSockets), doneSockets)

		// Force accept to unblock by connecting
		unblockAccept(srv.Addr, "post Close")
		ubSockets := getTCP(srv.Addr)
		if len(doneSockets) != 0 || len(ubSockets) != 0 {
			log.Warnf("post unblock sockets for %s: %d %s",
				srv.Addr, len(ubSockets), ubSockets)
		}
	}
	log.Noticef("Server on %s done", srv.Addr)
}

// unblockAccept connects to ourselves in case the server is blocked in
// the Accept call
// Normally when this is called we get a "connection refused" since the
// listener should have closed.
func unblockAccept(addr string, where string) {
	// Just want to send the SYN to unblock
	d := net.Dialer{Timeout: 100 * time.Millisecond}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		if isECONNREFUSED(err) {
			log.Noticef("unblockAccept(%s tag %s) got expected connection refused",
				addr, where)
		} else {
			log.Errorf("unblockAccept(%s tag %s) dial failed: %s",
				addr, where, err)
		}
		return
	}
	if err := conn.Close(); err != nil {
		log.Errorf("unblockAccept(%s tag %s) close failed: %s",
			addr, where, err)
		return
	}
	log.Warnf("unblockAccept(%s tag %s) unexpectedly succeeded and closed",
		addr, where)
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

// ServeHTTP for networkHandler provides a json return
func (hdl networkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("networkHandler.ServeHTTP")
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	externalIP, code := getExternalIPForApp(hdl.ctx, remoteIP)
	var ipStr string
	var hostname string
	// Avoid returning the string <nil>
	if len(externalIP) != 0 {
		ipStr = externalIP.String()
	}
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	if anStatus != nil {
		hostname = anStatus.UUIDandVersion.UUID.String()
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	resp, _ := json.Marshal(map[string]string{
		"caller-ip":     r.RemoteAddr,
		"external-ipv4": ipStr,
		"hostname":      hostname,
		// TBD: add public-ipv4 when controller tells us
	})
	w.Write(resp)
}

// ServeHTTP for externalIPHandler provides a text IP address
func (hdl externalIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("externalIPHandler.ServeHTTP")
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	externalIP, code := getExternalIPForApp(hdl.ctx, remoteIP)
	w.WriteHeader(code)
	w.Header().Add("Content-Type", "text/plain")
	// Avoid returning the string <nil>
	if len(externalIP) != 0 {
		resp := []byte(externalIP.String() + "\n")
		w.Write(resp)
	}
}

func getExternalIPForApp(ctx *zedrouterContext, remoteIP net.IP) (net.IP, int) {
	netstatus := lookupNetworkInstanceStatusByAppIP(ctx, remoteIP)
	if netstatus == nil {
		log.Errorf("No NetworkInstanceStatus for %s",
			remoteIP.String())
		return net.IP{}, http.StatusNotFound
	}
	if netstatus.CurrentUplinkIntf == "" {
		log.Warnf("No CurrentUplinkIntf for %s",
			remoteIP.String())
		// Nothing to report */
		return net.IP{}, http.StatusNoContent
	}
	ip, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus,
		0, netstatus.CurrentUplinkIntf)
	if err != nil {
		log.Errorf("No externalIP for %s: %s",
			remoteIP.String(), err)
		return net.IP{}, http.StatusNoContent
	}
	return ip, http.StatusOK
}

// ServeHTTP for hostnameHandler returns text
func (hdl hostnameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("hostnameHandler.ServeHTTP")
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	w.Header().Add("Content-Type", "text/plain")
	if anStatus == nil {
		w.WriteHeader(http.StatusNoContent)
		log.Errorf("No AppNetworkStatus for %s",
			remoteIP.String())
	} else {
		w.WriteHeader(http.StatusOK)
		resp := []byte(anStatus.UUIDandVersion.UUID.String() + "\n")
		w.Write(resp)
	}
}

// ServeHTTP for openstackHandler metadata service
func (hdl openstackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("openstackHandler ServeHTTP request: %s", r.URL.String())
	dirname, filename := path.Split(strings.TrimSuffix(r.URL.Path, "/"))
	dirname = strings.TrimSuffix(dirname, "/")
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	var hostname string
	var id string
	if anStatus != nil {
		hostname = anStatus.DisplayName
		id = anStatus.UUIDandVersion.UUID.String()
	} else {
		errorLine := fmt.Sprintf("no AppNetworkStatus for %s",
			remoteIP.String())
		log.Error(errorLine)
		http.Error(w, errorLine, http.StatusNotImplemented)
		return
	}
	anConfig := lookupAppNetworkConfig(hdl.ctx, anStatus.Key())
	if anConfig == nil {
		errorLine := fmt.Sprintf("no AppNetworkConfig for %s",
			anStatus.Key())
		log.Error(errorLine)
		http.Error(w, errorLine, http.StatusNotImplemented)
		return
	}
	if anConfig.MetaDataType != types.MetaDataOpenStack {
		errorLine := fmt.Sprintf("no MetaDataOpenStack for %s",
			anStatus.Key())
		log.Tracef(errorLine)
		http.Error(w, errorLine, http.StatusNotFound)
		return
	}
	switch filename {
	case "openstack":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "latest")
	case "meta_data.json":
		keys := getSSHPublicKeys(hdl.ctx, anConfig)
		var keysMap []map[string]string
		publicKeys := make(map[string]string)
		for ind, key := range keys {
			keysMap = append(keysMap, map[string]string{
				"data": fmt.Sprintf("%s\n", key),
				"type": "ssh",
				"name": fmt.Sprintf("key-%d", ind),
			})
			publicKeys[fmt.Sprintf("key-%d", ind)] = fmt.Sprintf("%s\n", key)
		}
		resp, _ := json.Marshal(map[string]interface{}{
			"uuid":         id,
			"hostname":     hostname,
			"name":         hostname,
			"launch_index": 0,
			"keys":         keysMap,
			"public_keys":  publicKeys,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	case "network_data.json":
		resp, _ := json.Marshal(map[string]interface{}{
			"services": []string{},
			"networks": []string{},
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	case "user_data":
		userData, err := getCloudInitUserData(hdl.ctx, anConfig)
		if err != nil {
			errorLine := fmt.Sprintf("cannot get userData for %s: %v",
				anStatus.Key(), err)
			log.Error(errorLine)
			http.Error(w, errorLine, http.StatusInternalServerError)
			return
		}
		ud, err := base64.StdEncoding.DecodeString(userData)
		if err != nil {
			errorLine := fmt.Sprintf("cannot decode userData for %s: %v",
				anStatus.Key(), err)
			log.Error(errorLine)
			http.Error(w, errorLine, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/yaml")
		w.WriteHeader(http.StatusOK)
		w.Write(ud)
	case "vendor_data.json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}
	w.WriteHeader(http.StatusNotFound)
}

// ServeHTTP for kubeConfigHandler provides cluster kube config
func (hdl kubeConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := "kube config handler: request method is not Post"
		log.Error(msg)
		http.Error(w, msg, http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		msg := "kube config handler: Content-Type header is not application/json"
		log.Error(msg)
		http.Error(w, msg, http.StatusUnsupportedMediaType)
		return
	}

	kubeConfig, err := ioutil.ReadAll(io.LimitReader(r.Body, AppInstMetadataResponseSizeLimitInBytes))
	if err != nil {
		msg := fmt.Sprintf("kube config handler: ioutil read failed: %v", err)
		log.Errorf(msg)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if binary.Size(kubeConfig) > KubeconfigFileSizeLimitInBytes {
		msg := fmt.Sprintf("kube config handler: kubeconfig size exceeds limit. Expected <= %v, actual size: %v",
			KubeconfigFileSizeLimitInBytes, binary.Size(kubeConfig))
		log.Errorf(msg)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	if anStatus == nil {
		msg := fmt.Sprintf("kube config handler: no AppNetworkStatus for %s", remoteIP.String())
		log.Errorf(msg)
		http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
		return
	}

	var appInstMetaData = &types.AppInstMetaData{
		AppInstUUID: anStatus.UUIDandVersion.UUID,
		Data:        kubeConfig,
		Type:        types.AppInstMetaDataTypeKubeConfig,
	}

	publishAppInstMetadata(hdl.ctx, appInstMetaData)
	return
}
