// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	v1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/lf-edge/eve/pkg/kube/cnirpc"
)

const (
	eveKubeNamespace       = "eve-kube-app"
	zedrouterRPCSocketPath = "/run/zedrouter/rpc.sock"
	primaryIfName          = "eth0"
	clusterSvcIPRange      = "10.43.0.0/16"
	vmiPodNamePrefix       = "virt-launcher-"
)

const (
	logfileDir    = "/persist/newlog/kube/"
	logfile       = logfileDir + "eve-bridge.log"
	logMaxSize    = 100 // 100 Mbytes in size
	logMaxBackups = 3   // old log files to retain
	logMaxAge     = 30  // days to retain old log files
)

var logFile *lumberjack.Logger

// EnvArgs encapsulates CNI_ARGS used by eve-bridge plugin.
type EnvArgs struct {
	types.CommonArgs
	// Note that these variables are intentionally in the "screaming snake case".
	// They must match the syntax of the environmental variables defined by the CNI spec.
	//revive:disable:var-naming
	MAC               types.UnmarshallableString
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_NAMESPACE types.UnmarshallableString
	//revive:enable:var-naming
}

type rawJSONStruct = map[string]interface{}

func parseArgs(args *skel.CmdArgs) (stdinArgs rawJSONStruct, cniVersion,
	podName string, mac net.HardwareAddr, isVMI, isEveApp bool, err error) {
	// Parse arguments received via stdin.
	versionDecoder := &version.ConfigDecoder{}
	cniVersion, err = versionDecoder.Decode(args.StdinData)
	if err != nil {
		err = fmt.Errorf("failed to decode CNI version: %v", err)
		log.Print(err)
		return
	}
	stdinArgs = make(rawJSONStruct)
	if err = json.Unmarshal(args.StdinData, &stdinArgs); err != nil {
		err = fmt.Errorf("failed to unmarshal stdin args: %v", err)
		log.Print(err)
		return
	}
	// Parse arguments received via environment variables.
	envArgs := EnvArgs{}
	err = types.LoadArgs(args.Args, &envArgs)
	if err != nil {
		err = fmt.Errorf("failed to parse env args: %v", err)
		log.Print(err)
		return
	}
	podName = string(envArgs.K8S_POD_NAME)
	isVMI = strings.HasPrefix(podName, vmiPodNamePrefix)
	isEveApp = string(envArgs.K8S_POD_NAMESPACE) == eveKubeNamespace
	if envArgs.MAC != "" {
		mac, err = net.ParseMAC(string(envArgs.MAC))
		if err != nil {
			err = fmt.Errorf("failed to parse mac address %s: %v", envArgs.MAC, err)
			log.Print(err)
			return
		}
	}
	return
}

// Prepare stdin args for a delegate call to the original bridge plugin.
func prepareStdinForBridgeDelegate(
	stdinArgs rawJSONStruct, isEveApp bool) ([]byte, error) {
	stdinArgs["isDefaultGateway"] = !isEveApp
	stdinArgs["forceAddress"] = true
	stdinArgs["hairpinMode"] = true
	if isEveApp {
		// Even though traffic is not routed via eth0 by default in EVE apps,
		// we should still send packets destined to Kubernetes service IPs through
		// this primary interface.
		ipamArgs, ok := stdinArgs["ipam"].(rawJSONStruct)
		if !ok {
			err := fmt.Errorf("failed to cast IPAM input args (actual type: %T)",
				stdinArgs["ipam"])
			log.Print(err)
			return nil, err
		}
		routes, ok := ipamArgs["routes"].([]interface{})
		if !ok {
			err := fmt.Errorf("failed to cast IPAM routes (actual type: %T)",
				ipamArgs["routes"])
			log.Print(err)
			return nil, err
		}
		nodeIP := stdinArgs["nodeIP"]
		if nodeIP == "" {
			err := errors.New("nodeIP was not provided")
			log.Print(err)
			return nil, err
		}
		clusterSvcRoute := rawJSONStruct{"dst": clusterSvcIPRange}
		routes = append(routes, clusterSvcRoute)
		nodeIPRoute := rawJSONStruct{"dst": nodeIP}
		routes = append(routes, nodeIPRoute)
		ipamArgs["routes"] = routes
	}
	bridgeArgs, err := json.Marshal(stdinArgs)
	if err != nil {
		err = fmt.Errorf("failed to marshal input args for the bridge plugin: %v", err)
		log.Print(err)
		return nil, err
	}
	return bridgeArgs, nil
}

// Prepare stdin args for a delegate call to the dhcp IPAM plugin.
func prepareStdinForDhcpDelegate(stdinArgs rawJSONStruct) ([]byte, error) {
	stdinArgs["ipam"] = rawJSONStruct{"type": "dhcp"}
	dhcpArgs, err := json.Marshal(stdinArgs)
	if err != nil {
		err = fmt.Errorf("failed to marshal input args for the dhcp plugin: %v", err)
		log.Print(err)
		return nil, err
	}
	return dhcpArgs, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Printf("cmdAdd: stdinData: %s, env: %v",
		string(args.StdinData), os.Environ())
	stdinArgs, cniVersion, podName, mac, isVMI, isEveApp, err := parseArgs(args)
	if err != nil {
		// Error is already logged.
		return err
	}

	if args.IfName == primaryIfName {
		// Delegate creation of the eth0 interface to the original bridge plugin.
		bridgeArgs, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
		if err != nil {
			// Error is already logged.
			return err
		}
		log.Printf("Delegating cmdAdd to bridge plugin with args: %s", string(bridgeArgs))
		result, err := invoke.DelegateAdd(context.Background(), "bridge",
			bridgeArgs, nil)
		if err != nil {
			err = fmt.Errorf("bridge plugin failed to setup eth0: %v", err)
			log.Print(err)
			return err
		}
		return types.PrintResult(result, cniVersion)
	}

	// Continue here to create netX interface with the help from zedrouter microservice.

	// Ask zedrouter to connect Pod at the Layer 2 first.
	// For now the interface will be without IP address, but in the case of a local NI
	// the DHCP server will be prepared.
	conn, err := net.Dial("unix", zedrouterRPCSocketPath)
	if err != nil {
		err = fmt.Errorf("failed to dial zedrouter RPC socket: %v", err)
		log.Print(err)
		return err
	}
	defer conn.Close()
	rpcClient := jsonrpc.NewClient(conn)
	commonRPCArgs := cnirpc.CommonCNIRPCArgs{
		Pod: cnirpc.AppPod{
			Name:      podName,
			NetNsPath: args.Netns,
		},
		PodInterface: cnirpc.NetInterfaceWithNs{
			Name:      args.IfName,
			MAC:       mac,
			NetNsPath: args.Netns,
		},
	}
	connectPodAtL2Args := cnirpc.ConnectPodAtL2Args{CommonCNIRPCArgs: commonRPCArgs}
	connectPodAtL2Retval := &cnirpc.ConnectPodAtL2Retval{}
	err = rpcClient.Call("RPCServer.ConnectPodAtL2",
		connectPodAtL2Args, connectPodAtL2Retval)
	if err != nil {
		err = fmt.Errorf("RPC ConnectPodAtL2 (%+v) failed: %v", connectPodAtL2Args, err)
		log.Print(err)
		return err
	}
	log.Printf("RPC ConnectPodAtL2 (%+v) succeeded with retval: %+v",
		connectPodAtL2Args, connectPodAtL2Retval)

	podIntfIndex := -1
	result := &v1.Result{CNIVersion: v1.ImplementedSpecVersion}
	for i, netIntf := range connectPodAtL2Retval.Interfaces {
		result.Interfaces = append(result.Interfaces, &v1.Interface{
			Name:    netIntf.Name,
			Mac:     netIntf.MAC.String(),
			Sandbox: netIntf.NetNsPath,
		})
		if netIntf.Name == args.IfName {
			podIntfIndex = i
		}
	}
	if podIntfIndex == -1 {
		err = fmt.Errorf("missing interface %s in the list %v", args.IfName,
			connectPodAtL2Retval.Interfaces)
		log.Print(err)
		return err
	}

	l2Only := !connectPodAtL2Retval.UseDHCP || isVMI
	if l2Only {
		// We are done with L2-only connectivity.
		log.Printf("Returning result: %+v", result)
		return types.PrintResult(result, cniVersion)
	}

	// run the IPAM plugin and get back the IP config to apply.
	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs)
	if err != nil {
		// Error is already logged.
		return err
	}
	log.Printf("Running IPAM plugin \"dhcp\" (cmdAdd) with args: %s", string(dhcpArgs))
	r, err := ipam.ExecAdd("dhcp", dhcpArgs)
	if err != nil {
		err := fmt.Errorf("IPAM plugin failed: %v", err)
		log.Print(err)
		return err
	}

	// Convert whatever the IPAM result was into the current Result type.
	ipamResult, err := v1.NewResultFromResult(r)
	if err != nil {
		err = fmt.Errorf("conversion of IPAM results failed: %v", err)
		log.Print(err)
		return err
	}
	if len(ipamResult.IPs) == 0 {
		err = fmt.Errorf("IPAM plugin returned missing IP config: %v", ipamResult)
		log.Print(err)
		return err
	}
	for i := range ipamResult.IPs {
		ipamResult.IPs[i].Interface = &podIntfIndex
	}
	log.Printf("IPAM result: %+v", ipamResult)

	// Ask zedrouter to apply the received IP config.
	ipamConfig := cnirpc.PodIPAMConfig{
		DNS: cnirpc.PodDNS{
			Nameservers: ipamResult.DNS.Nameservers,
			Domain:      ipamResult.DNS.Domain,
			Search:      ipamResult.DNS.Search,
			Options:     ipamResult.DNS.Options,
		},
	}
	for _, ip := range ipamResult.IPs {
		ipamConfig.IPs = append(ipamConfig.IPs,
			cnirpc.PodIPAddress{Address: &ip.Address, Gateway: ip.Gateway})
	}
	for _, route := range ipamResult.Routes {
		ipamConfig.Routes = append(ipamConfig.Routes,
			cnirpc.PodRoute{Dst: &route.Dst, GW: route.GW})
	}
	connectPodAtL3Args := cnirpc.ConnectPodAtL3Args{
		CommonCNIRPCArgs: commonRPCArgs,
		PodIPAMConfig:    ipamConfig,
	}
	connectPodAtL3Retval := &cnirpc.ConnectPodAtL3Retval{}
	err = rpcClient.Call("RPCServer.ConnectPodAtL3",
		connectPodAtL3Args, connectPodAtL3Retval)
	if err != nil {
		err = fmt.Errorf("RPC ConnectPodAtL3 (%+v) failed: %v",
			connectPodAtL3Args, err)
		log.Print(err)
		return err
	}
	log.Printf("RPC ConnectPodAtL3 (%+v) succeeded with retval: %+v",
		connectPodAtL3Args, connectPodAtL3Retval)

	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes
	result.DNS = ipamResult.DNS
	log.Printf("Returning result: %+v", result)
	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	log.Printf("cmdDel: stdinData: %s, env: %v",
		string(args.StdinData), os.Environ())
	stdinArgs, _, podName, _, isVMI, isEveApp, err := parseArgs(args)
	if err != nil {
		// Error is already logged.
		return err
	}

	if args.IfName == primaryIfName {
		// Delegate deletion of the eth0 interface to the original bridge plugin.
		bridgeArgs, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
		if err != nil {
			// Error is already logged.
			return err
		}
		log.Printf("Delegating cmdDel to bridge plugin with args: %s", string(bridgeArgs))
		err = invoke.DelegateDel(context.Background(), "bridge",
			bridgeArgs, nil)
		if err != nil {
			err = fmt.Errorf("bridge plugin failed to delete eth0: %v", err)
			log.Print(err)
			return err
		}
		return nil
	}

	// Continue here to remove netX interface with the help from zedrouter microservice.

	// Ask zedrouter to disconnect Pod.
	conn, err := net.Dial("unix", zedrouterRPCSocketPath)
	if err != nil {
		err = fmt.Errorf("failed to dial zedrouter RPC socket: %v", err)
		log.Print(err)
		return err
	}
	defer conn.Close()
	rpcClient := jsonrpc.NewClient(conn)
	commonRPCArgs := cnirpc.CommonCNIRPCArgs{
		Pod: cnirpc.AppPod{
			Name:      podName,
			NetNsPath: args.Netns,
		},
		PodInterface: cnirpc.NetInterfaceWithNs{
			Name:      args.IfName,
			NetNsPath: args.Netns,
			// MAC is not passed to cmdDel
		},
	}
	disconnectPodArgs := cnirpc.DisconnectPodArgs{CommonCNIRPCArgs: commonRPCArgs}
	disconnectPodRetval := &cnirpc.DisconnectPodRetval{}
	err = rpcClient.Call("RPCServer.DisconnectPod", disconnectPodArgs, disconnectPodRetval)
	if err != nil {
		err = fmt.Errorf("RPC DisconnectPod (%+v) failed: %v", disconnectPodArgs, err)
		log.Print(err)
		return err
	}
	log.Printf("RPC DisconnectPod (%+v) succeeded with retval: %+v",
		disconnectPodArgs, disconnectPodRetval)

	l2Only := !disconnectPodRetval.UsedDHCP || isVMI
	if l2Only {
		// We are done removing L2-only connectivity.
		return nil
	}

	// Tell DHCP server to release the allocated IP address.
	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs)
	if err != nil {
		// Error is already logged.
		return err
	}
	log.Printf("Running IPAM plugin \"dhcp\" (cmdDel) with args: %s", string(dhcpArgs))
	err = ipam.ExecDel("dhcp", dhcpArgs)
	if err != nil {
		err := fmt.Errorf("IPAM plugin failed: %v", err)
		log.Print(err)
		return err
	}
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	log.Printf("cmdCheck: stdinData: %s, env: %v",
		string(args.StdinData), os.Environ())
	stdinArgs, _, podName, _, isVMI, isEveApp, err := parseArgs(args)
	if err != nil {
		// Error is already logged.
		return err
	}

	if args.IfName == primaryIfName {
		// Delegate check of the eth0 interface to the original bridge plugin.
		bridgeArgs, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
		if err != nil {
			// Error is already logged.
			return err
		}
		log.Printf("Delegating cmdCheck to bridge plugin with args: %s", string(bridgeArgs))
		err = invoke.DelegateCheck(context.Background(), "bridge",
			bridgeArgs, nil)
		if err != nil {
			err = fmt.Errorf("bridge plugin failed to check eth0: %v", err)
			log.Print(err)
			return err
		}
		return nil
	}

	// Continue here to check netX interface with the help from zedrouter microservice.

	// Ask zedrouter to check the interface.
	conn, err := net.Dial("unix", zedrouterRPCSocketPath)
	if err != nil {
		err = fmt.Errorf("failed to dial zedrouter RPC socket: %v", err)
		log.Print(err)
		return err
	}
	defer conn.Close()
	rpcClient := jsonrpc.NewClient(conn)
	commonRPCArgs := cnirpc.CommonCNIRPCArgs{
		Pod: cnirpc.AppPod{
			Name:      podName,
			NetNsPath: args.Netns,
		},
		PodInterface: cnirpc.NetInterfaceWithNs{
			Name:      args.IfName,
			NetNsPath: args.Netns,
			// MAC is not passed to cmdDel
		},
	}
	checkPodConnectionArgs := cnirpc.CheckPodConnectionArgs{CommonCNIRPCArgs: commonRPCArgs}
	checkPodConnectionRetval := &cnirpc.CheckPodConnectionRetval{}
	err = rpcClient.Call("RPCServer.CheckPodConnection", checkPodConnectionArgs,
		checkPodConnectionRetval)
	if err != nil {
		err = fmt.Errorf("RPC CheckPodConnection(%+v) failed: %v",
			checkPodConnectionArgs, err)
		log.Print(err)
		return err
	}
	log.Printf("RPC CheckPodConnection (%+v) succeeded with retval: %+v",
		checkPodConnectionArgs, checkPodConnectionRetval)

	l2Only := !checkPodConnectionRetval.UsesDHCP || isVMI
	if l2Only {
		// We are done checking L2-only connectivity.
		return nil
	}

	// Ask dhcp plugin to check pod interface from its point of view.
	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs)
	if err != nil {
		// Error is already logged.
		return err
	}
	log.Printf("Running IPAM plugin \"dhcp\" (cmdCheck) with args: %s", string(dhcpArgs))
	err = ipam.ExecCheck("dhcp", dhcpArgs)
	if err != nil {
		err := fmt.Errorf("IPAM plugin failed: %v", err)
		log.Print(err)
		return err
	}
	return nil
}

func main() {
	if _, err := os.Stat(logfileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logfileDir, 0755); err != nil {
			return
		}
	}
	logFile = &lumberjack.Logger{
		Filename:   logfile,       // Path to the log file.
		MaxSize:    logMaxSize,    // Maximum size in megabytes before rotation.
		MaxBackups: logMaxBackups, // Maximum number of old log files to retain.
		MaxAge:     logMaxAge,     // Maximum number of days to retain old log files.
		Compress:   true,          // Whether to compress rotated log files.
		LocalTime:  true,          // Use the local time zone for file names.
	}
	log.SetOutput(logFile)
	defer logFile.Close()

	log.Printf("eve-bridge main() Start")
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("eve-bridge"))
	log.Printf("eve-bridge main() exit")
}
