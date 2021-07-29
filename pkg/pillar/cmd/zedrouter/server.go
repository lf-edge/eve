// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A http server providing meta-data information to application instances
// at http://169.254.169.254. The source IP address is used to tell
// which app instance is sending the request

package zedrouter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"

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

func createServer4(ctx *zedrouterContext, bridgeIP string, bridgeName string) error {
	if bridgeIP == "" {
		err := fmt.Errorf("can't run server on %s: no bridgeIP", bridgeName)
		log.Error(err)
		return err
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
}

var mapToDoneChan = make(map[doneChanKey]doneChanVal)

func setDoneChan(bridgeName string, bridgeIP string, doneChan chan<- struct{},
	ackChan <-chan struct{}) {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	if _, exists := mapToDoneChan[key]; exists {
		log.Fatalf("setDoneChan: key already exists %+v", key)
	}
	mapToDoneChan[key] = doneChanVal{doneChan: doneChan, ackChan: ackChan}
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

func runServer(mux http.Handler, network string, ipaddr string,
	doneChan <-chan struct{}, ackChan chan<- struct{}) {

	// XXX no to place to specify network. Might be an issue when we
	// add IPv6?
	srv := http.Server{
		Addr:    ipaddr + ":80",
		Handler: mux,
	}
	idleConnsClosed := make(chan struct{})
	go func() {
		<-doneChan

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Noticef("server on %s shutdown failed: %s", ipaddr, err)
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			log.Noticef("server on %s closed", ipaddr)
		} else {
			log.Fatalf("server on %s failed: %s", ipaddr, err)
		}
	}
	log.Noticef("Waiting for idleConnsClosed on %s", ipaddr)
	<-idleConnsClosed
	log.Noticef("Done waiting for idleConnsClosed on %s", ipaddr)
	ackChan <- struct{}{}
	log.Noticef("Server on %s done", ipaddr)
}

// ServeHTTP for networkHandler provides a json return
func (hdl networkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
