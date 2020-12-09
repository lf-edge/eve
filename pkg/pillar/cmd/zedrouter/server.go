// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A http server providing meta-data information to application instances
// at http://169.254.169.254. The source IP address is used to tell
// which app instance is sending the request

package zedrouter

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	ifname  = "svc0"
	ipaddr4 = "169.254.169.254"
	ifaddr4 = ipaddr4 + "/32"
	ipaddr6 = "fe80::a9fe:a9fe"
	ifaddr6 = ipaddr6 + "/128"
)

// For now we run a single server. If we use network namespaces for
// each bridge aka network instance it would make sense to run a server
// per network instance
// The source IP address of the caller is used to determine the app
// instance and network instance

func createServerIntf(ctx *zedrouterContext) error {
	// ip link add name svc0 type dummy
	// ip link set dev svc0 up
	// ip addr add 169.254.169.254/32 dev svc0
	// ip addr add fe80::a9fe:a9fe/128 dev svc0
	link, err := netlink.LinkByName(ifname)
	if link != nil {
		log.Warnf("createServerIntf: %s already present",
			ifname)
		return nil
	}

	sattrs := netlink.NewLinkAttrs()
	sattrs.Name = ifname

	slink := &netlink.Dummy{LinkAttrs: sattrs}
	if err := netlink.LinkAdd(slink); err != nil {
		return fmt.Errorf("createServerIntf: LinkAdd on %s failed: %s",
			ifname, err)
	}

	if err := netlink.LinkSetUp(slink); err != nil {
		return fmt.Errorf("createServerIntf: LinkSetUp on %s failed: %s",
			ifname, err)
	}
	addr4, err := netlink.ParseAddr(ifaddr4)
	if err != nil {
		return fmt.Errorf("createServerIntf: ParseAddr %s failed: %s", ifaddr4, err)
	}
	if err := netlink.AddrAdd(slink, addr4); err != nil {
		return fmt.Errorf("createServerIntf: AddrAdd %s failed: %s", ifaddr4, err)
	}
	addr6, err := netlink.ParseAddr(ifaddr6)
	if err != nil {
		return fmt.Errorf("createServerIntf: ParseAddr %s failed: %s", ifaddr6, err)
	}
	if err := netlink.AddrAdd(slink, addr6); err != nil {
		return fmt.Errorf("createServerIntf: AddrAdd %s failed: %s", ifaddr6, err)
	}
	return nil
}

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

func createServer(ctx *zedrouterContext) error {
	mux := http.NewServeMux()
	nh := &networkHandler{ctx: ctx}
	mux.Handle("/eve/v1/network.json", nh)
	ipHandler := &externalIPHandler{ctx: ctx}
	mux.Handle("/eve/v1/external_ipv4", ipHandler)
	hostnameHandler := &hostnameHandler{ctx: ctx}
	mux.Handle("/eve/v1/hostname", hostnameHandler)

	// Need one server per local IP address
	go runServer(mux, "tcp6", "["+ipaddr6+"%"+ifname+"]")
	go runServer(mux, "tcp4", ipaddr4)
	log.Noticef("started http server")
	return nil
}

func runServer(mux http.Handler, network string, ipaddr string) {
	l, err := net.Listen(network, ipaddr+":80")
	if err != nil {
		log.Fatal(err)
	}
	if err := http.Serve(l, mux); err != nil {
		log.Fatal(err)
	}
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
