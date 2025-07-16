// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/configitems"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	"github.com/lf-edge/eve/evetest/utils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	// Port connecting SDN VM with the host
	hostPortLogicalLabel = "Host-Port"
	// File where all the logs from evetest-SDN are saved.
	logFile = "/run/sdn.log"
)

type agent struct {
	api.UnimplementedSDNServer
	sync.Mutex
	ctx       context.Context
	macLookup *maclookup.MacLookup

	// Log streaming
	logHook *logger.LogrusGrpcHook

	// Network model
	netModel parsedNetModel

	// Opened tunnels
	// key: client ID (at most one tunnel allowed per client)
	tunnels map[string]*api.SDNTunnel

	// Configuration state
	currentState  dg.Graph
	intendedState dg.Graph
	registry      reconciler.ConfiguratorRegistry
	failingItems  map[dg.ItemRef]error
	networkIndex  map[string]int // key: network logical label

	// Asynchronous operations
	resumeReconciliation <-chan string // nil if no async ops
	kickRunCh            chan struct{}
	cancelAsyncOps       reconciler.CancelFunc // nil if no async ops
	waitForAsyncOps      func()                // NOOP if no async ops

	// 802.1x port status
	pnacEvents          chan configitems.PNACEvent
	isPortAuthenticated map[string]bool // key: port/bond logical label
}

func (a *agent) init() error {
	a.ctx = context.Background()
	linkChan := a.linkSubscribe(a.ctx.Done())
	a.macLookup = &maclookup.MacLookup{}
	a.macLookup.RefreshCache()
	a.pnacEvents = make(chan configitems.PNACEvent, 10)
	registry := &reconciler.DefaultRegistry{}
	err := configitems.RegisterItems(registry, a.macLookup, a.pnacEvents)
	if err != nil {
		return err
	}
	a.registry = registry
	a.tunnels = make(map[string]*api.SDNTunnel)
	a.failingItems = make(map[dg.ItemRef]error)
	a.kickRunCh = make(chan struct{}, 1)
	a.logHook = &logger.LogrusGrpcHook{}
	log.AddHook(a.logHook)
	// Initially start with an empty network model.
	// Ever-present config items will get created.
	// (e.g. DHCP client for the interface connecting SDN with the host)
	a.netModel = parsedNetModel{NetworkModel: &api.NetworkModel{}}
	a.isPortAuthenticated = make(map[string]bool)
	a.updateCurrentState()
	a.updateIntendedState()
	a.reconcile()
	go a.run(linkChan)
	return nil
}

func (a *agent) run(linkChan chan netlink.LinkUpdate) {
	for {
		select {
		case <-a.kickRunCh:
			// a.reconcile was triggered in a separate goroutine.
			// We restart the select loop to pick up the newly set
			// a.resumeReconciliation channel.
			continue

		case <-a.resumeReconciliation:
			a.Lock()
			a.reconcile()
			a.Unlock()

		case ev := <-a.pnacEvents:
			a.Lock()
			netIf, found := a.macLookup.GetInterfaceByName(ev.InterfaceName)
			if !found {
				log.Warnf("Received PNAC event for unknown network interface %q",
					ev.InterfaceName)
				a.Unlock()
				continue
			}
			var logicalLabel string
			for _, port := range a.netModel.Ports {
				// MAC address is already validated
				mac, _ := net.ParseMAC(port.GetSdnMacAddress())
				if bytes.Equal(mac, netIf.MAC) {
					logicalLabel = port.LogicalLabel
					break
				}
			}
			if logicalLabel == "" {
				for _, bond := range a.netModel.Bonds {
					if a.bondIfName(bond.LogicalLabel) == ev.InterfaceName {
						logicalLabel = bond.LogicalLabel
						break
					}
				}
			}
			if logicalLabel == "" {
				log.Warnf("Failed to find logical label corresponding to port "+
					"or bond with interface name %q", ev.InterfaceName)
				a.Unlock()
				continue
			}
			prevState := a.isPortAuthenticated[logicalLabel]
			if prevState == ev.IsAuthenticated {
				// No change
				a.Unlock()
				continue
			}
			a.isPortAuthenticated[logicalLabel] = ev.IsAuthenticated
			log.Infof("Updated PNAC status for port %q to: authenticated=%t",
				logicalLabel, ev.IsAuthenticated)
			a.updateCurrentState()
			a.updateIntendedState()
			a.reconcile()
			a.Unlock()

		case linkUpdate, ok := <-linkChan:
			if !ok {
				log.Warn("Link subscription was closed")
				linkChan = a.linkSubscribe(a.ctx.Done())
				continue
			}
			// If interface appeared or disappeared, refresh the current
			// state graph and potentially reconcile.
			_, found := a.macLookup.GetInterfaceByIndex(int(linkUpdate.Index))
			added := !found
			deleted := linkUpdate.Header.Type == syscall.RTM_DELLINK
			if added || deleted {
				log.Debugf("Important link change: %+v", linkUpdate)
				a.Lock()
				a.macLookup.RefreshCache()
				changed := a.updateCurrentState()
				mac := linkUpdate.Attrs().HardwareAddr
				if bytes.HasPrefix(mac, constants.SDNHostPortMACPrefix) {
					// Intended state for SDN<->Host connectivity changes
					// when the "host port" (dis)appears.
					a.updateIntendedState()
					changed = true
				}
				if changed {
					a.reconcile()
				}
				a.Unlock()
			}

		case <-a.ctx.Done():
			a.Lock()
			if a.cancelAsyncOps != nil {
				a.cancelAsyncOps(nil)
				a.waitForAsyncOps()
				log.Warn("Some asynchronous operations were canceled!")
			}
			a.Unlock()
			return
		}
	}
}

func (a *agent) kickRunMethod() {
	select {
	case a.kickRunCh <- struct{}{}:
	default:
	}
}

// Called with agent in locked state.
func (a *agent) reconcile() (err error) {
	reconcileStartTime := time.Now()
	r := reconciler.New(a.registry)
	status := r.Reconcile(a.ctx, a.currentState, a.intendedState)
	a.currentState = status.NewCurrentState

	// Update variables needed to resume reconciliation
	// after async operation(s).
	if status.AsyncOpsInProgress {
		log.Debug("Some config operations continue in the background")
	}
	a.cancelAsyncOps = status.CancelAsyncOps
	a.resumeReconciliation = status.ReadyToResume
	a.waitForAsyncOps = status.WaitForAsyncOps

	dotExporter := &dg.DotExporter{CheckDeps: true}

	/* TODO: There is a bug in ExportTransition causing a nil-pointer dereference.
	         We will skip outputting combined-state.dot until the bug is fixed.
	         (it is only used for troubleshooting)
	dot, _ := dotExporter.ExportTransition(a.currentState, a.intendedState)
	if err = os.WriteFile("/run/combined-state.dot", []byte(dot), 0644); err != nil {
		log.Warnf("Failed to output combined state graph")
	}
	*/

	dot, _ := dotExporter.Export(a.currentState)
	if err = os.WriteFile("/run/current-state.dot", []byte(dot), 0644); err != nil {
		log.Warnf("Failed to output current state graph")
	}

	dot, _ = dotExporter.Export(a.intendedState)
	if err = os.WriteFile("/run/intended-state.dot", []byte(dot), 0644); err != nil {
		log.Warnf("Failed to output intended state graph")
	}

	// Log every executed operation.
	for _, opLog := range status.OperationLog {
		var withErr string
		if opLog.Err != nil {
			withErr = fmt.Sprintf(" with error: %v", opLog.Err)
		}
		var verb string
		if opLog.InProgress {
			verb = "started async execution of"
		} else {
			if opLog.StartTime.Before(reconcileStartTime) {
				verb = "finalized async execution of"
			} else {
				// synchronous operation
				verb = "executed"
			}
		}
		log.Infof("State Reconciler %s %v for %v%s, content: %s",
			verb, opLog.Operation, dg.Reference(opLog.Item),
			withErr, opLog.Item.String())
	}

	// Log transitions from no-error to error and vice-versa.
	var failed, fixed []string
	for _, opLog := range status.OperationLog {
		itemRef := dg.Reference(opLog.Item)
		if opLog.Err != nil {
			a.failingItems[itemRef] = opLog.Err
		} else {
			delete(a.failingItems, itemRef)
		}
		if opLog.PrevErr == nil && opLog.Err != nil {
			failed = append(failed, fmt.Sprintf("%v (err: %v)", itemRef, opLog.Err))
		}
		if opLog.PrevErr != nil && opLog.Err == nil {
			fixed = append(fixed, itemRef.String())
		}
	}
	if len(failed) > 0 {
		err = fmt.Errorf("failed config items: %s", strings.Join(failed, ", "))
		log.Error(err)
	}
	if len(fixed) > 0 {
		log.Infof("Fixed config items: %s", strings.Join(fixed, ", "))
	}
	return err
}

func (a *agent) linkSubscribe(doneChan <-chan struct{}) chan netlink.LinkUpdate {
	linkChan := make(chan netlink.LinkUpdate, 64)
	linkErrFunc := func(err error) {
		log.Errorf("LinkSubscribe failed %s\n", err)
	}
	linkOpts := netlink.LinkSubscribeOptions{
		ErrorCallback: linkErrFunc,
	}
	if err := netlink.LinkSubscribeWithOptions(
		linkChan, doneChan, linkOpts); err != nil {
		log.Fatal(err)
	}
	return linkChan
}

func (a *agent) allocNetworkIndexes() {
	if a.networkIndex == nil {
		a.networkIndex = make(map[string]int)
	}
	// Allocate new indexes where needed.
	for _, network := range a.netModel.Networks {
		index, hasIndex := a.networkIndex[network.LogicalLabel]
		if hasIndex {
			// Keep already allocated index.
			continue
		}
		index = 0
		for a.isNetworkIndexUsed(index) {
			index++
		}
		a.networkIndex[network.LogicalLabel] = index
	}
}

func (a *agent) isNetworkIndexUsed(index int) bool {
	for _, val := range a.networkIndex {
		if val == index {
			return true
		}
	}
	return false
}

// GetNetworkModel : get the SDN's abstract model of the topology.
func (a *agent) GetNetworkModel(
	context.Context, *api.SDNRequest) (*api.SDNGetNetworkModelResponse, error) {
	a.Lock()
	netModel := proto.CloneOf(a.netModel.NetworkModel)
	a.Unlock()
	return &api.SDNGetNetworkModelResponse{NetworkModel: netModel}, nil
}

// SetNetworkModel : apply the given abstract model of the SDN topology.
func (a *agent) SetNetworkModel(ctx context.Context,
	req *api.SDNSetNetworkModelRequest) (*api.SDNSetNetworkModelResponse, error) {
	parsedNetModel, err := a.parseNetModel(req.NetworkModel)
	if err != nil {
		err := fmt.Errorf("network model is invalid: %v", err)
		log.Error(err)
		return nil, err
	}
	log.Debugf("Parsed network model: %+v", parsedNetModel)
	a.Lock()
	a.netModel = parsedNetModel
	a.updateCurrentState()
	a.updateIntendedState()
	err = a.reconcile()
	a.kickRunMethod()
	a.Unlock()
	return &api.SDNSetNetworkModelResponse{}, err
}

// GetConfigGraph : get the SDN configuration visualized as a Graphviz dot-formatted graph.
func (a *agent) GetConfigGraph(
	context.Context, *api.SDNRequest) (*api.SDNConfigGraphResponse, error) {
	dotExporter := &dg.DotExporter{CheckDeps: true}
	a.Lock()
	defer a.Unlock()
	dot, err := dotExporter.ExportTransition(a.currentState, a.intendedState)
	return &api.SDNConfigGraphResponse{ConfigGraphviz: dot}, err
}

// GetStatus : get overall SDN (network emulator) status.
func (a *agent) GetStatus(
	context.Context, *api.SDNRequest) (*api.SDNStatusResponse, error) {
	a.Lock()
	defer a.Unlock()
	status := &api.SDNStatusResponse{
		MgmtIps: a.getMgmtIPs(),
	}
	for itemRef, err := range a.failingItems {
		status.ConfigErrors = append(status.ConfigErrors, &api.SDNConfigError{
			ItemRef:  itemRef.String(),
			ErrorMsg: err.Error(),
		})
	}
	return status, nil
}

func (a *agent) getMgmtIPs() (ips []string) {
	hostNetIf, found := a.macLookup.GetInterfaceByMAC(constants.SDNHostPortMACPrefix, true)
	if !found {
		log.Warnf("failed to find port connecting SDN with the host")
		return
	}
	ifName := hostNetIf.IfName
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		log.Warnf("Failed to get link for interface %s: %v", ifName, err)
		return
	}
	ips4, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.Warnf("Failed to get IPv4 addresses for interface %s: %v", ifName, err)
	}
	ips6, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		log.Errorf("Failed to get IPv6 addresses for interface %s: %v", ifName, err)

	}
	for _, ip := range ips4 {
		if ip.IP.IsGlobalUnicast() {
			ips = append(ips, ip.IP.String())
		}
	}
	for _, ip := range ips6 {
		if ip.IP.IsGlobalUnicast() {
			ips = append(ips, ip.IP.String())
		}
	}
	return
}

// Gateway to use to route traffic towards host OS.
func (a *agent) getHostGwIP(ipv6 bool) net.IP {
	hostPort, found := a.macLookup.GetInterfaceByMAC(constants.SDNHostPortMACPrefix, true)
	if !found {
		return nil
	}
	var fflags uint64
	filter := netlink.Route{}
	fflags |= netlink.RT_FILTER_TABLE
	filter.Table = syscall.RT_TABLE_MAIN
	fflags |= netlink.RT_FILTER_OIF
	filter.LinkIndex = hostPort.IfIndex
	family := syscall.AF_INET
	if ipv6 {
		family = syscall.AF_INET6
	}
	nlRoutes, err := netlink.RouteListFiltered(family, &filter, fflags)
	if err != nil {
		log.Warnf("netlink.RouteListFiltered failed: %v", err)
		return nil
	}
	for _, nlRoute := range nlRoutes {
		if nlRoute.Gw == nil {
			continue
		}
		if nlRoute.Dst == nil {
			// Nil destination can be used by the default route.
			return nlRoute.Gw
		}
		ones, _ := nlRoute.Dst.Mask.Size()
		if ones == 0 && nlRoute.Dst.IP.IsUnspecified() {
			// Default route matching all IPs.
			return nlRoute.Gw
		}
	}
	return nil
}

// StreamLogs streams SDN logs to the connected client.
// Only a single log stream can be active at any given time.
func (a *agent) StreamLogs(
	_ *api.SDNRequest, stream grpc.ServerStreamingServer[api.LogMessage]) error {
	if err := a.logHook.SetStream(stream); err != nil {
		return err
	}
	defer a.logHook.SetStream(nil) //nolint:errcheck

	// Send all logs collected before this stream started.
	if err := a.logHook.LoadAndStreamFromFile(logFile); err != nil {
		return fmt.Errorf("failed to send existing logs: %w", err)
	}

	// Block until the client disconnects or the context is canceled.
	<-stream.Context().Done()
	return stream.Context().Err()
}

// CheckConnectivity checks if the given hostname is reachable on the given port
// over both IPv4 and IPv6. It attempts a short TCP connection for each family.
func (a *agent) CheckConnectivity(
	ctx context.Context, req *api.SDNConnectivityRequest) (*api.SDNConnectivityResponse, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}
	if req.Hostname == "" {
		return nil, errors.New("hostname is required")
	}
	if req.Port == 0 || req.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", req.Port)
	}

	// Resolve the hostname for both address families.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", req.Hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %q: %w", req.Hostname, err)
	}

	var reachable4, reachable6 bool
	const perDialTimeout = 5 * time.Second
	dialer := &net.Dialer{}

	for _, ip := range ips {
		isV4 := ip.To4() != nil

		// Skip if we've already succeeded for this IP version.
		if (isV4 && reachable4) || (!isV4 && reachable6) {
			continue
		}

		target := net.JoinHostPort(ip.String(), strconv.Itoa(int(req.Port)))
		ctxDial, cancel := context.WithTimeout(ctx, perDialTimeout)
		conn, err := dialer.DialContext(ctxDial, "tcp", target)
		cancel()

		if err == nil {
			conn.Close()
			if isV4 {
				reachable4 = true
			} else {
				reachable6 = true
			}
			// If both already true, we can stop early.
			if reachable4 && reachable6 {
				break
			}
		}
	}

	return &api.SDNConnectivityResponse{
		ReachableOverIpv4: reachable4,
		ReachableOverIpv6: reachable6,
	}, nil
}

// ConnectTunnel establishes a bidirectional gRPC tunnel between
// the client and the SDN, carrying raw IP packets over a virtual point-to-point link.
func (a *agent) ConnectTunnel(
	stream grpc.BidiStreamingServer[api.ConnectTunnelToSDNRequest, api.ConnectTunnelToSDNResponse]) error {
	// Receive the first message from the client to extract the client ID
	// and the required tunnel parameters.
	initMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive initial tunnel request: %w", err)
	}
	tunnelReq := initMsg.GetConnect()
	if tunnelReq == nil {
		return fmt.Errorf("expected initial 'connect' request")
	}

	// Validate config.
	for _, addr := range tunnelReq.IpAddresses {
		_, _, err = net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("invalid tunnel IP address %q: %w", addr, err)
		}
	}
	for _, route := range tunnelReq.Routes {
		_, _, err = net.ParseCIDR(route.DstNetwork)
		if err != nil {
			return fmt.Errorf("invalid tunnel route destination network %q: %w",
				route.DstNetwork, err)
		}
		gw := net.ParseIP(route.Gateway)
		if gw == nil {
			return fmt.Errorf("invalid tunnel route gateway IP %q", route.Gateway)
		}
	}

	// Add tunnel specification to the internal list
	a.Lock()
	if _, hasTunnel := a.tunnels[tunnelReq.ClientId]; hasTunnel {
		a.Unlock()
		return fmt.Errorf("client %s already has a tunnel opened", tunnelReq.ClientId)
	}
	a.tunnels[tunnelReq.ClientId] = tunnelReq
	// Create the tunnel interface, add IP addresses, add routes, etc.
	a.updateCurrentState()
	a.updateIntendedState()
	err = a.reconcile()
	a.kickRunMethod()
	a.Unlock()

	// Schedule cleanup: remove the tunnel and trigger state updates when done.
	defer func() {
		a.Lock()
		defer a.Unlock()
		delete(a.tunnels, tunnelReq.ClientId)
		a.updateCurrentState()
		a.updateIntendedState()
		a.reconcile()
		a.kickRunMethod()
	}()

	if err != nil {
		return err
	}

	// Reply with tunnel properties.
	// This message is currently empty but reserved for future extensions.
	err = stream.Send(&api.ConnectTunnelToSDNResponse{
		Payload: &api.ConnectTunnelToSDNResponse_ConnectReply{
			ConnectReply: &api.SDNTunnelProperties{
				// Nothing defined for now.
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send SDN tunnel properties: %v", err)
	}

	// Run proxy between the TUN device and the gRPC stream.
	grpcPipe := utils.GrpcServerPipe[api.ConnectTunnelToSDNRequest, api.ConnectTunnelToSDNResponse]{
		MakeResponse: func(data []byte) *api.ConnectTunnelToSDNResponse {
			return &api.ConnectTunnelToSDNResponse{
				Payload: &api.ConnectTunnelToSDNResponse_Data{
					Data: data,
				},
			}
		},
		Stream: stream,
	}
	tunFile, ok := configitems.TunDescriptors.Load(tunnelReq.ClientId)
	if !ok {
		return fmt.Errorf("missing tunnel file descriptor for client %q",
			tunnelReq.ClientId)
	}
	tunPipe := utils.ReadWriterPipe{
		PipeName: "tun device",
		RW:       tunFile.(*os.File),
		Buf:      make([]byte, os.Getpagesize()),
	}

	log.Infof("SDN Tunnel established with clientID=%s", tunnelReq.GetClientId())
	logEntry := log.NewEntry(log.StandardLogger())
	utils.RunPipeProxy(stream.Context(), logEntry, "SDN tunnel", grpcPipe, tunPipe)
	return nil
}
