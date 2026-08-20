// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/cnirpc"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

const (
	rpcSocketPath     = runDirname + "/rpc.sock"
	defaultRPCTimeout = 10 * time.Second
)

type rpcRequest struct {
	signalDone chan error
	request    interface{}
}

// connectPodAtL2Request encapsulates args and retval for ConnectPodAtL2 RPC method.
type connectPodAtL2Request struct {
	args   cnirpc.ConnectPodAtL2Args
	retval *cnirpc.ConnectPodAtL2Retval
}

// connectPodAtL3Request encapsulates args and retval for ConnectPodAtL3 RPC method.
type connectPodAtL3Request struct {
	args   cnirpc.ConnectPodAtL3Args
	retval *cnirpc.ConnectPodAtL3Retval
}

// disconnectPodRequest encapsulates args and retval for DisconnectPod RPC method.
type disconnectPodRequest struct {
	args   cnirpc.DisconnectPodArgs
	retval *cnirpc.DisconnectPodRetval
}

// checkPodConnectionRequest encapsulates args and retval for CheckPodConnection RPC method.
type checkPodConnectionRequest struct {
	args   cnirpc.CheckPodConnectionArgs
	retval *cnirpc.CheckPodConnectionRetval
}

func (r *rpcRequest) submitAndWait(z *zedrouter, timeout time.Duration) error {
	r.signalDone = make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case z.cniRequests <- r:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-r.signalDone:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *rpcRequest) markDone(err error) {
	r.signalDone <- err
	close(r.signalDone)
}

// Handle RPC request from the zedrouter main event loop.
func (z *zedrouter) handleRPC(rpc *rpcRequest) {
	var err error
	switch request := rpc.request.(type) {
	case connectPodAtL2Request:
		l2Only := cnirpc.PodIPAMConfig{}
		retval := request.retval
		retval.AppUUID, retval.UseDHCP, retval.Interfaces, err =
			z.handleConnectPodRequest(request.args.Pod, request.args.PodInterface,
				request.args.NetworkInstance, l2Only)
	case connectPodAtL3Request:
		request.retval.AppUUID, _, _, err = z.handleConnectPodRequest(request.args.Pod,
			request.args.PodInterface, request.args.NetworkInstance, request.args.PodIPAMConfig)
	case disconnectPodRequest:
		err = z.handleDisconnectPodRequest(request.args, request.retval)
	case checkPodConnectionRequest:
		err = z.handleCheckPodConnectionRequest(request.args, request.retval)
	default:
		err = fmt.Errorf("unhandled RPC request %T: %v", request, request)
	}
	if err != nil {
		z.log.Error(err)
	}
	rpc.markDone(err)
}

// Used for both connectPodAtL2Request and connectPodAtL3Request.
// Will setup L3 connectivity if ipamConfig is defined, L2-only otherwise.
func (z *zedrouter) handleConnectPodRequest(pod cnirpc.AppPod,
	podInterface cnirpc.NetInterfaceWithNs, networkInstance string,
	ipamConfig cnirpc.PodIPAMConfig) (
	appUUID uuid.UUID, niWithDHCP bool, interfaces []cnirpc.NetInterfaceWithNs, err error) {
	appConfig, appStatus, err := z.resolveApp(pod, networkInstance)
	if err != nil {
		z.log.Error(err)
		return uuid.UUID{}, false, nil, err
	}
	appUUID = appStatus.UUIDandVersion.UUID
	appStatus.AppPod = pod
	adapterStatus := z.selectAdapter(appStatus, &podInterface, networkInstance)
	if adapterStatus == nil {
		if networkInstance != "" {
			err = fmt.Errorf("failed to find adapter on network instance %s for app %v",
				networkInstance, appStatus.UUIDandVersion.UUID)
		} else {
			err = fmt.Errorf("failed to find adapter with MAC %s for app %v",
				podInterface.MAC, appStatus.UUIDandVersion.UUID)
		}
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	adapterStatus.PodVif.GuestIfName = podInterface.Name
	adapterStatus.PodVif.IPAM = ipamConfig
	z.publishAppNetworkStatus(appStatus)
	// Tell CNI plugin to use dhcp IPAM unless this is an air-gapped switch NI.
	netInstStatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
	if netInstStatus == nil {
		// Should be unreachable.
		err = fmt.Errorf("missing network instance status for %s",
			adapterStatus.Network.String())
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	niWithDHCP = z.niWithDHCP(netInstStatus)
	// Try to setup pod connectivity (L2 or L3).
	vifs, err := z.prepareConfigForVIFs(*appConfig, appStatus)
	if err != nil {
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	appConnRecStatus, err := z.niReconciler.UpdateAppConn(
		z.runCtx, *appConfig, appStatus.AppPod, vifs)
	if err != nil {
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	var vifStatus *nireconciler.AppVIFReconcileStatus
	for _, vif := range appConnRecStatus.VIFs {
		if vif.NetAdapterName == adapterStatus.Name {
			vifStatus = &vif
			break
		}
	}
	if vifStatus == nil {
		err = fmt.Errorf("missing VIF status for adapter %s", adapterStatus.Name)
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	var failedItems []string
	for itemRef, itemErr := range vifStatus.FailedItems {
		failedItems = append(failedItems, fmt.Sprintf("%v (%v)", itemRef, itemErr))
	}
	if len(failedItems) > 0 {
		err = fmt.Errorf("failed config items: %s", strings.Join(failedItems, ";"))
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	if vifStatus.InProgress {
		// It is not expected that some config items are created asynchronously.
		err = fmt.Errorf("some config items related to VIF %v/%s are still in progress",
			appStatus.UUIDandVersion.UUID, adapterStatus.Name)
		z.log.Error(err)
		return appUUID, false, nil, err
	}
	interfaces = append(interfaces, cnirpc.NetInterfaceWithNs{
		Name: netInstStatus.BridgeName,
		MAC:  netInstStatus.BridgeMac,
	})
	interfaces = append(interfaces, cnirpc.NetInterfaceWithNs{
		Name: vifStatus.HostIfName,
		// MAC on the host side is not published by NI Reconciler.
		// Most likely it is not needed anyway.
	})
	interfaces = append(interfaces, podInterface)
	return appUUID, niWithDHCP, interfaces, nil
}

func (z *zedrouter) handleDisconnectPodRequest(
	args cnirpc.DisconnectPodArgs, retval *cnirpc.DisconnectPodRetval) error {
	appConfig, appStatus, err := z.resolveApp(args.Pod, args.NetworkInstance)
	if err != nil {
		// App is already removed.
		// Most likely we got a duplicate CNI DEL call, which is allowed by the CNI spec.
		// According to the spec, we should not return error in this case.
		z.log.Warn(err)
		return nil
	}
	retval.AppUUID = appStatus.UUIDandVersion.UUID
	// Guard against a race during app restart: the new pod calls ConnectPodAtL2
	// first, updating appStatus.AppPod to the new pod. Then, a few seconds later,
	// the old pod's CNI teardown fires DisconnectPod. If we let it proceed, it
	// would clear the PodVif and remove the VIF that was just created for the new
	// pod, leaving the running VMI with no network. Detect this by comparing the
	// disconnecting pod's name against the currently-connected pod in AppPod.
	if appStatus.AppPod.Name != "" && appStatus.AppPod.Name != args.Pod.Name {
		z.log.Warnf("handleDisconnectPodRequest: ignoring stale disconnect for pod %s "+
			"(app %v is already connected via pod %s)",
			args.Pod.Name, appStatus.UUIDandVersion.UUID, appStatus.AppPod.Name)
		return nil
	}
	var adapterStatus *types.AppNetAdapterStatus
	for i := range appStatus.AppNetAdapterList {
		adapterStatus = &appStatus.AppNetAdapterList[i]
		if adapterStatus.PodVif.GuestIfName == args.PodInterface.Name {
			break
		}
		adapterStatus = nil
	}
	if adapterStatus == nil {
		// VIF is already removed.
		// Most likely we got a duplicate CNI DEL call, which is allowed by the CNI spec.
		// According to the spec, we should not return error in this case.
		z.log.Warnf("failed to find adapter with pod interface %s for app %v",
			args.PodInterface.Name, appStatus.UUIDandVersion.UUID)
		return nil
	}
	// Remove pod VIF from the config.
	adapterStatus.PodVif = types.PodVIF{}
	z.publishAppNetworkStatus(appStatus)
	// Find out if DHCP was being used.
	netInstStatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
	if netInstStatus == nil {
		// Should be unreachable.
		err = fmt.Errorf("missing network instance status for %s",
			adapterStatus.Network.String())
		z.log.Error(err)
		return err
	}
	retval.UsedDHCP = z.niWithDHCP(netInstStatus)
	// Try to remove pod connectivity.
	vifs, err := z.prepareConfigForVIFs(*appConfig, appStatus)
	if err != nil {
		z.log.Error(err)
		return err
	}
	_, err = z.niReconciler.UpdateAppConn(
		z.runCtx, *appConfig, appStatus.AppPod, vifs)
	if err != nil {
		z.log.Error(err)
		return err
	}
	return nil
}

func (z *zedrouter) handleCheckPodConnectionRequest(
	args cnirpc.CheckPodConnectionArgs, retval *cnirpc.CheckPodConnectionRetval) error {
	_, appStatus, err := z.resolveApp(args.Pod, args.NetworkInstance)
	if err != nil {
		z.log.Error(err)
		return err
	}
	retval.AppUUID = appStatus.UUIDandVersion.UUID
	var adapterStatus *types.AppNetAdapterStatus
	for i := range appStatus.AppNetAdapterList {
		adapterStatus = &appStatus.AppNetAdapterList[i]
		if adapterStatus.PodVif.GuestIfName == args.PodInterface.Name {
			break
		}
		adapterStatus = nil
	}
	if adapterStatus == nil {
		err = fmt.Errorf("failed to find adapter with pod interface %s for app %v",
			args.PodInterface.Name, appStatus.UUIDandVersion.UUID)
		z.log.Error(err)
		return err
	}
	// Find out if DHCP is being used.
	netInstStatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
	if netInstStatus == nil {
		// Should be unreachable.
		err = fmt.Errorf("missing network instance status for %s",
			adapterStatus.Network.String())
		z.log.Error(err)
		return err
	}
	retval.UsesDHCP = z.niWithDHCP(netInstStatus)
	// Check the state of the connection configuration in the network stack.
	appConnRecStatus, err := z.niReconciler.GetAppConnStatus(appStatus.UUIDandVersion.UUID)
	if err != nil {
		z.log.Error(err)
		return err
	}
	var vifStatus *nireconciler.AppVIFReconcileStatus
	for _, vif := range appConnRecStatus.VIFs {
		if vif.NetAdapterName == adapterStatus.Name {
			vifStatus = &vif
			break
		}
	}
	if vifStatus == nil {
		err = fmt.Errorf("missing VIF status for adapter %s", adapterStatus.Name)
		z.log.Error(err)
		return err
	}
	var failedItems []string
	for itemRef, itemErr := range vifStatus.FailedItems {
		failedItems = append(failedItems, fmt.Sprintf("%v (%v)", itemRef, itemErr))
	}
	if len(failedItems) > 0 {
		err = fmt.Errorf("failed config items: %s", strings.Join(failedItems, ";"))
		z.log.Error(err)
		return err
	}
	if vifStatus.InProgress {
		// It is not expected that some config items are created asynchronously.
		err = fmt.Errorf("some config items related to VIF %v/%s are still in progress",
			appStatus.UUIDandVersion.UUID, adapterStatus.Name)
		z.log.Error(err)
		return err
	}
	return nil
}

func (z *zedrouter) niWithDHCP(netInstStatus *types.NetworkInstanceStatus) bool {
	airGapped := netInstStatus.PortLabel == ""
	switchNI := netInstStatus.Type == types.NetworkInstanceTypeSwitch
	return !switchNI || !airGapped
}

func (z *zedrouter) getAppByPodName(
	podName string) (*types.AppNetworkConfig, *types.AppNetworkStatus, error) {
	appKubeName := podName
	_, rsName, err := base.GetVMINameFromVirtLauncher(podName)
	if err == nil {
		appKubeName = rsName
	}
	for _, item := range z.pubAppNetworkStatus.GetAll() {
		appStatus := item.(types.AppNetworkStatus)
		appUUID := appStatus.UUIDandVersion.UUID
		repPodName, isReplicaPod := base.GetReplicaPodName(appStatus.DisplayName, podName, appUUID)
		if isReplicaPod {
			appKubeName = repPodName
		}
		if strings.HasPrefix(appKubeName, base.GetAppKubeName(appStatus.DisplayName, appUUID)) {
			appConfig := z.lookupAppNetworkConfig(appStatus.Key())
			if appConfig == nil {
				return nil, nil, fmt.Errorf("missing network config for app %v", appUUID)
			}
			return appConfig, &appStatus, nil
		}
	}
	return nil, nil, fmt.Errorf("failed to find app network status for pod %s", podName)
}

// resolveApp finds the AppNetworkConfig/Status for an inbound CNI request. A non-empty
// networkInstance means the request came from a directly-deployed Kubernetes workload (the
// per-NI NAD carried it), resolved by Kubernetes identity; otherwise it is a controller-managed
// app, resolved by the UUID prefix embedded in the pod name.
func (z *zedrouter) resolveApp(pod cnirpc.AppPod, networkInstance string) (
	*types.AppNetworkConfig, *types.AppNetworkStatus, error) {
	if networkInstance != "" {
		return z.getAppByKubeWorkload(pod.Namespace, pod.Name)
	}
	return z.getAppByPodName(pod.Name)
}

// getAppByKubeWorkload resolves a directly-deployed Kubernetes workload pod to the
// AppNetworkConfig synthesized for it by zedkube. The pod carries no controller-assigned UUID
// prefix, so it is matched by Kubernetes identity: namespace plus the bare Pod name or the bare
// ReplicaSet (owner) name embedded in the synthesized config's KubeApp field.
func (z *zedrouter) getAppByKubeWorkload(namespace, podName string) (
	*types.AppNetworkConfig, *types.AppNetworkStatus, error) {
	for _, item := range z.subKubeAppNetworkConfig.GetAll() {
		config := item.(types.AppNetworkConfig)
		if config.KubeApp == nil || config.KubeApp.Namespace != namespace {
			continue
		}
		if !base.KubePodMatchesOwner(podName, config.KubeApp.OwnerName) {
			continue
		}
		appStatus := z.lookupAppNetworkStatus(config.Key())
		if appStatus == nil {
			return nil, nil, fmt.Errorf(
				"no app network status yet for kube workload %s/%s", namespace, podName)
		}
		return &config, appStatus, nil
	}
	return nil, nil, fmt.Errorf(
		"failed to find app network config for kube workload %s/%s", namespace, podName)
}

// selectAdapter picks the AppNetAdapterStatus that an inbound CNI interface refers to.
// Controller-managed apps match by the MAC EVE pre-assigned and baked into the pod spec.
// Directly-deployed Kubernetes workloads supply no MAC, so they match by the Network Instance
// their NAD attached to; the EVE-computed MAC is then made authoritative by copying it into
// podInterface so eve-bridge surfaces it in the CNI result.
func (z *zedrouter) selectAdapter(appStatus *types.AppNetworkStatus,
	podInterface *cnirpc.NetInterfaceWithNs, networkInstance string) *types.AppNetAdapterStatus {
	for i := range appStatus.AppNetAdapterList {
		adapterStatus := &appStatus.AppNetAdapterList[i]
		if networkInstance != "" {
			if adapterStatus.Network.String() == networkInstance {
				podInterface.MAC = adapterStatus.Mac
				return adapterStatus
			}
			continue
		}
		if bytes.Equal(podInterface.MAC, adapterStatus.Mac) {
			return adapterStatus
		}
	}
	return nil
}

func (z *zedrouter) runRPCServer() error {
	server := &RPCServer{zedrouter: z}
	err := rpc.Register(server)
	if err != nil {
		return err
	}

	listener, err := net.Listen("unix", rpcSocketPath)
	if err != nil {
		return err
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				z.log.Warnf("Accept for RPC call failed: %v", err)
				continue
			}
			go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	return nil
}

// RPCServer receives RPC calls from eve-bridge CNI and dispatches them to the main
// event loop of zedrouter.
type RPCServer struct {
	zedrouter *zedrouter
}

// ConnectPodAtL2 : establish L2 connection between pod and network instance.
func (h *RPCServer) ConnectPodAtL2(
	args cnirpc.ConnectPodAtL2Args, retval *cnirpc.ConnectPodAtL2Retval) error {
	h.zedrouter.log.Noticef("RPC call: ConnectPodAtL2 (%+v)", args)
	req := &rpcRequest{request: connectPodAtL2Request{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: ConnectPodAtL2 (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: ConnectPodAtL2 (%+v) failed: %v", args, err)
	}
	return err
}

// ConnectPodAtL3 : establish L3 connection between pod and network instance.
// Typically, it is used after ConnectPodAtL2 to elevate existing L2 connection
// into L3 by applying the submitted IP settings.
func (h *RPCServer) ConnectPodAtL3(
	args cnirpc.ConnectPodAtL3Args, retval *cnirpc.ConnectPodAtL3Retval) error {
	h.zedrouter.log.Noticef("RPC call: ConnectPodAtL3 (%+v)", args)
	req := &rpcRequest{request: connectPodAtL3Request{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: ConnectPodAtL3 (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: ConnectPodAtL3 (%+v) failed: %v", args, err)
	}
	return err
}

// DisconnectPod : un-configure the given connection between pod and network instance.
func (h *RPCServer) DisconnectPod(
	args cnirpc.DisconnectPodArgs, retval *cnirpc.DisconnectPodRetval) error {
	h.zedrouter.log.Noticef("RPC call: DisconnectPod (%+v)", args)
	req := &rpcRequest{request: disconnectPodRequest{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: DisconnectPod (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: DisconnectPod (%+v) failed: %v", args, err)
	}
	return err
}

// CheckPodConnection : check if the given connection between pod and network instance
// is configured successfully.
func (h *RPCServer) CheckPodConnection(
	args cnirpc.CheckPodConnectionArgs, retval *cnirpc.CheckPodConnectionRetval) error {
	h.zedrouter.log.Noticef("RPC call: CheckPodConnection (%+v)", args)
	req := &rpcRequest{request: checkPodConnectionRequest{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: CheckPodConnection (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: CheckPodConnection (%+v) failed: %v", args, err)
	}
	return err
}
