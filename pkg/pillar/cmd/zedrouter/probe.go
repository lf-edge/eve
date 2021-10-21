// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Probe to the local interface nexthop and remote servers

package zedrouter

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	fastping "github.com/tatsushid/go-fastping"
)

const (
	maxContFailCnt     uint32 = 4   // number of continuous failure to declare Down
	maxContSuccessCnt  uint32 = 3   // number of continuous success to declare UP
	maxPingWait        int    = 100 // wait for 100 millisecond for ping timeout
	maxRemoteProbeWait uint32 = 3   // wait for 3 seconds for remote host response
	remoteTolocalRatio uint32 = 10  // every 10 times of local ping, perform remote probing
	minProbeRatio      uint32 = 5   // user defined ratio of local/remote min will be set to 5
	// e.g. if the local ping timer is every 15 seconds, every remote httping is every 2.5 minutes
	nhProbeInterval  uint32 = 15                    // probe interval
	stayDownMinCount uint32 = 600 / nhProbeInterval // at least stay down for 10 min
	stayUPMinCount   uint32 = stayDownMinCount
)

type probeRes struct {
	isRemoteReply bool
	latency       int64 // in millisecond
}

var iteration uint32
var serverNameAndPort string
var addrChgTime time.Time // record last time intf address change time

// use probeMutex to protect the status.PInfo[] map entries. When the external
// port is configured from Management into App-Shared, this map entry of the port
// will be deleted from the status.PInfo[] array
var probeMutex sync.Mutex

// called from handleDNSModify
func deviceUpdateNIprobing(ctx *zedrouterContext, status *types.DeviceNetworkStatus) {
	var needTrigPing bool
	pub := ctx.pubNetworkInstanceStatus
	log.Tracef("deviceUpdateNIprobing: enter\n")
	for _, port := range status.Ports {
		log.Functionf("deviceUpdateNIprobing: port %s/%s, is Mgmt %v\n", port.Phylabel, port.IfName, port.IsMgmt)

		items := pub.GetAll()
		for _, st := range items {
			netstatus := st.(types.NetworkInstanceStatus)
			if !isSharedPortLabel(netstatus.Logicallabel) {
				continue
			}
			resetIsPresentFlag(&netstatus, port.IfName)
			if niProbingUpdatePort(ctx, port, &netstatus) {
				needTrigPing = true
			}
			checkNIprobeUplink(ctx, &netstatus, port.IfName)
		}
	}
	if needTrigPing {
		setProbeTimer(ctx, 1) // trigger probe timer faster (in 1 sec)
	}
}

// called from handleNetworkInstanceModify and handleNetworkInstanceCreate
func niUpdateNIprobing(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {
	pub := ctx.subDeviceNetworkStatus
	items := pub.GetAll()
	portList := getIfNameListForLLOrIfname(ctx, status.Logicallabel)
	log.Functionf("niUpdateNIprobing: enter, type %v, number of ports %d\n", status.Type, len(portList))
	for _, st := range items {
		devStatus := st.(types.DeviceNetworkStatus)

		for _, port := range portList {
			devPort := getDevPort(&devStatus, port)
			if devPort == nil {
				log.Functionf("niUpdateNIprobing: Port %s not found in DeviceNetworkStatus %+v",
					port, devStatus)
				continue
			}
			if !isSharedPortLabel(status.Logicallabel) &&
				status.Logicallabel != devPort.Logicallabel {
				continue
			}
			niProbingUpdatePort(ctx, *devPort, status)
		}
	}
	checkNIprobeUplink(ctx, status, "")
}

func getDevPort(status *types.DeviceNetworkStatus, ifName string) *types.NetworkPortStatus {
	for _, tmpport := range status.Ports {
		if strings.Compare(tmpport.IfName, ifName) == 0 {
			return &tmpport
		}
	}
	return nil
}

func niProbingUpdatePort(ctx *zedrouterContext, port types.NetworkPortStatus,
	netstatus *types.NetworkInstanceStatus) bool {
	var needTrigPing bool
	log.Tracef("niProbingUpdatePort: %s, type %v, enter\n", netstatus.BridgeName, netstatus.Type)
	if netstatus.HasError() {
		log.Errorf("niProbingUpdatePort: Network instance is in errored state: %s",
			netstatus.Error)
		return needTrigPing
	}
	// we skip the non-Mgmt port for now
	if !port.IsMgmt {
		log.Functionf("niProbingUpdatePort: %s is not mgmt, skip", port.IfName)
		if info, ok := netstatus.PInfo[port.IfName]; ok {
			log.Functionf("niProbingUpdatePort:   info intf %s is present %v\n", info.IfName, info.IsPresent)
		}
		if netstatus.CurrentUplinkIntf == "" { // assign the CurrentUplinkIntf even for non-Mgmt port
			netstatus.CurrentUplinkIntf = port.IfName
			publishNetworkInstanceStatus(ctx, netstatus)
		}
		return needTrigPing
	}

	// Pick first default router
	var dr net.IP
	if len(port.DefaultRouters) > 0 {
		dr = port.DefaultRouters[0]
	}

	if _, ok := netstatus.PInfo[port.IfName]; !ok {
		if port.IfName == "" { // no need to probe for air-gap type of NI
			return needTrigPing
		}
		info := types.ProbeInfo{
			IfName:       port.IfName,
			IsPresent:    true,
			GatewayUP:    true,
			NhAddr:       dr,
			LocalAddr:    portGetIntfAddr(port),
			Cost:         port.Cost,
			RemoteHostUP: true,
		}
		netstatus.PInfo[port.IfName] = info
		log.Functionf("niProbingUpdatePort: %s assigned new %s, info len %d, cost %d",
			netstatus.BridgeName, port.IfName, len(netstatus.PInfo), info.Cost)
		if !ipAddrIsValid(info.LocalAddr) {
			info.GatewayUP = false
			info.RemoteHostUP = false
		}
	} else {
		info := netstatus.PInfo[port.IfName]
		prevLocalAddr := info.LocalAddr
		info.IsPresent = true
		info.NhAddr = dr
		info.LocalAddr = portGetIntfAddr(port)
		info.Cost = port.Cost
		// the probe status are copied inside publish NI status
		netstatus.PInfo[port.IfName] = info
		log.Functionf("niProbingUpdatePort: %s modified %s, cost %d", netstatus.BridgeName, port.IfName, info.Cost)
		if netstatus.Logicallabel == port.Logicallabel {
			// if the intf lose ip address or gain ip address, react faster
			// XXX detect changes to LocalAddr and NHAddr in general?
			if ipAddrIsValid(prevLocalAddr) && !ipAddrIsValid(info.LocalAddr) {
				log.Functionf("niProbingUpdatePort: %s lose addr modified %s, addrlen %d, addr %v, nh %v",
					netstatus.BridgeName, port.IfName, len(port.AddrInfoList), info.LocalAddr, info.NhAddr)
				needTrigPing = true
			} else if !ipAddrIsValid(prevLocalAddr) && ipAddrIsValid(info.LocalAddr) {
				log.Functionf("niProbingUpdatePort: %s gain addr modified %s, addr %v, nh %v",
					netstatus.BridgeName, port.IfName, info.LocalAddr, info.NhAddr)
				needTrigPing = true
			}
		}
	}
	publishNetworkInstanceStatus(ctx, netstatus)
	if needTrigPing {
		elapsed := time.Since(addrChgTime).Seconds()
		// to prevent the loose cable is constantly flapping the UP/DOWN, wait at least 10 min
		if elapsed > 600 {
			addrChgTime = time.Now()
		} else {
			needTrigPing = false
		}
	}
	return needTrigPing
}

// after port or NI changes, if we don't have a current uplink,
// randomly assign one and publish, if we already do, leave it as is
// each NI may have a different good uplink
func checkNIprobeUplink(ctx *zedrouterContext, status *types.NetworkInstanceStatus, intf string) {
	// find and remove the stale info since the port has been removed
	for _, info := range status.PInfo {
		if info.IfName != intf {
			continue
		}
		log.Functionf("checkNIprobeUplink: %s, intf %s, is present %v\n", status.BridgeName, info.IfName, info.IsPresent)
		if !info.IsPresent {
			if _, ok := status.PInfo[info.IfName]; ok {
				log.Functionf("checkNIprobeUplink: %s remove intf %s from ProbeInfo\n", status.BridgeName, info.IfName)
				probeMutex.Lock()
				delete(status.PInfo, info.IfName)
				probeMutex.Unlock()
				publishNetworkInstanceStatus(ctx, status)
			}
		}
	}

	if status.CurrentUplinkIntf != "" {
		// regardless of the Curr Uplink is valid or not, it was the previous run result, let probing code to handle
		return
	}

	// if the Curr is empty, then try to fill it here
	if len(status.PInfo) > 0 {
		// Try and find an interface that has unicast IP address.
		// No link local.
		for _, info := range status.PInfo {
			// Pick uplink with atleast one usable IP address
			ifNameList := getIfNameListForLLOrIfname(ctx, info.IfName)
			if len(ifNameList) != 0 {
				for _, ifName := range ifNameList {
					_, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus, 0, ifName)
					if err != nil {
						continue
					}
					status.CurrentUplinkIntf = info.IfName
					log.Functionf("checkNIprobeUplink: bridge %s pick %s as uplink\n",
						status.BridgeName, info.IfName)
					break
				}
			}
			if status.CurrentUplinkIntf != "" {
				break
			}
		}
		if status.CurrentUplinkIntf == "" {
			// We are not able to find a port with usable unicast IP address.
			// Try and find a port that atleast has a local UP address.
			for _, info := range status.PInfo {
				ifNameList := getIfNameListForLLOrIfname(ctx, info.IfName)
				if len(ifNameList) != 0 {
					for _, ifName := range ifNameList {
						_, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus, 0, ifName)
						if err != nil {
							continue
						}
						status.CurrentUplinkIntf = info.IfName
						log.Functionf("checkNIprobeUplink: bridge %s pick %s as uplink\n",
							status.BridgeName, info.IfName)
						break
					}
				}
				if status.CurrentUplinkIntf != "" {
					break
				}
			}
		}
		// If none of the interfaces have valid unicast/local IP addresss just pick the first
		if status.CurrentUplinkIntf == "" {
			if len(status.PInfo) > 0 {
				var port string
				for port = range status.PInfo {
					break
				}
				info := status.PInfo[port]
				status.CurrentUplinkIntf = info.IfName
				log.Functionf("checkNIprobeUplink: bridge %s pick %s as uplink\n",
					status.BridgeName, info.IfName)
			}
		}
		publishNetworkInstanceStatus(ctx, status)
	}
}

func portGetIntfAddr(port types.NetworkPortStatus) net.IP {
	var localip net.IP
	for _, addrinfo := range port.AddrInfoList {
		if port.Subnet.Contains(addrinfo.Addr) {
			localip = addrinfo.Addr
		}
	}
	return localip
}

// a go routine driven by the HostProbeTimer in zedrouter, to perform the
// local and remote(less frequent) host probing
func launchHostProbe(ctx *zedrouterContext) {
	var isReachable, needSendSignal, bringIntfDown bool
	nhPing := make(map[string]bool)
	localDown := make(map[string]bool)
	remoteProbe := make(map[string]map[string]probeRes)
	log.Tracef("launchHostProbe: enter\n")
	dpub := ctx.subDeviceNetworkStatus
	ditems := dpub.GetAll()

	zcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		Timeout:      maxRemoteProbeWait,
		TLSConfig:    &tls.Config{InsecureSkipVerify: true},
		AgentMetrics: ctx.zedcloudMetrics,
		AgentName:    agentName,
	})

	remoteURL := getSystemURL()
	probeMutex.Lock()

	ctx.networkInstanceStatusMap.Range(func(key, value interface{}) bool {
		netstatus := value.(*types.NetworkInstanceStatus)
		var anyNIStateChg bool
		// XXX Revisit when we support other network instance types.
		if netstatus.Type != types.NetworkInstanceTypeLocal &&
			netstatus.Type != types.NetworkInstanceTypeCloud {
			log.Tracef("launchHostProbe: ni(%s) type %v, skip probing\n", netstatus.BridgeName, netstatus.Type)
			return true
		}
		log.Tracef("launchHostProbe: ni(%s) current uplink %s, isUP %v, prev %s, update %v\n",
			netstatus.BridgeName, netstatus.CurrentUplinkIntf, netstatus.CurrIntfUP, netstatus.PrevUplinkIntf, netstatus.NeedIntfUpdate)
		netstatus.NeedIntfUpdate = false

		for _, info := range netstatus.PInfo {
			var needToProbe bool
			var isRemoteResp probeRes
			log.Tracef("launchHostProbe: intf %s, gw %v, statusUP %v, remoteHostUP %v\n",
				info.IfName, info.NhAddr, info.GatewayUP, info.RemoteHostUP)

			// Local nexthop ping, only apply to zero cost ports
			if info.Cost == 0 {
				if _, ok := nhPing[info.IfName]; !ok {
					isReachable, bringIntfDown = probeFastPing(info)
					nhPing[info.IfName] = isReachable
					localDown[info.IfName] = bringIntfDown
				} else {
					isReachable = nhPing[info.IfName]
					bringIntfDown = localDown[info.IfName]
					log.Tracef("launchHostProbe: already got ping result on %s(%s) %v\n", info.IfName, info.NhAddr.String(), isReachable)
				}

				if bringIntfDown {
					log.Tracef("launchHostProbe: %s local address lost, bring it down/down\n", info.IfName)
					info.GatewayUP = false
					info.RemoteHostUP = false
				}
				if probeProcessReply(&info, isReachable, 0, true) {
					anyNIStateChg = true
				}
				log.Tracef("launchHostProbe(%d): gateway up %v, success count %d, failed count %d, remote success %d, remote fail %d\n",
					iteration, info.GatewayUP, info.SuccessCnt, info.FailedCnt, info.SuccessProbeCnt, info.FailedProbeCnt)
			}

			// for every X number of nexthop ping iteration, do the remote probing
			// although we could have checked if the nexthop is down, there is no need
			// to do remote probing, but just in case, local nexthop ping is filtered by
			// the gateway firewall, and since we only do X iteration, it's simpler just doing it
			if iteration%getProbeRatio(netstatus) == 0 {
				// get user specified url/ip
				remoteURL = getRemoteURL(netstatus, remoteURL)

				// probing remote host
				tmpRes := remoteProbe[info.IfName]
				if tmpRes == nil {
					tmpRes := make(map[string]probeRes)
					remoteProbe[info.IfName] = tmpRes
				}
				// if has already been done for this intf/remoteURL of this session, then
				// copy the result over to other NIs
				if _, ok := remoteProbe[info.IfName][remoteURL]; !ok {
					needToProbe = true
				} else {
					isRemoteResp = remoteProbe[info.IfName][remoteURL]

					log.Tracef("launchHostProbe: probe on %s to remote %s, resp %v\n", info.IfName, remoteURL, isRemoteResp)
				}

				if needToProbe {
					var foundport bool
					for _, st := range ditems {
						devStatus := st.(types.DeviceNetworkStatus)
						for _, port := range devStatus.Ports {
							if strings.Compare(port.IfName, info.IfName) == 0 {
								zcloudCtx.DeviceNetworkStatus = &devStatus
								foundport = true
								break
							}
						}
						if foundport {
							break
						}
					}
					if foundport {
						startTime := time.Now()
						const allowProxy = true
						const useOnboard = false
						resp, _, _, err := zedcloud.SendOnIntf(&zcloudCtx, remoteURL, info.IfName, 0, nil, allowProxy, useOnboard)
						if err != nil {
							log.Tracef("launchHostProbe: send on intf %s, err %v\n", info.IfName, err)
						}
						if resp != nil {
							log.Tracef("launchHostProbe: server %s status code %d\n", serverNameAndPort, resp.StatusCode)
							//
							// isRemoteResp.isRemoteReply = (resp.StatusCode == 200)
							// make it any reply is good
							isRemoteResp.isRemoteReply = true
						}
						isRemoteResp.latency = time.Since(startTime).Nanoseconds() / int64(time.Millisecond)
					}
					remoteProbe[info.IfName][remoteURL] = isRemoteResp
				}

				if probeProcessReply(&info, isRemoteResp.isRemoteReply, isRemoteResp.latency, false) {
					anyNIStateChg = true
				}
				log.Tracef("launchHostProbe: probe on %s to remote %s, latency %d msec, success cnt %d, failed cnt %d, need probe %v\n",
					info.IfName, remoteURL, isRemoteResp.latency, info.SuccessProbeCnt, info.FailedProbeCnt, needToProbe)
			}

			netstatus.PInfo[info.IfName] = info
		}
		probeCheckStatus(ctx, netstatus)
		// we need to trigger the change at least once at start to set the initial Uplink intf
		if netstatus.NeedIntfUpdate || netstatus.TriggerCnt == 0 {
			needSendSignal = true
			netstatus.TriggerCnt++
		}
		if anyNIStateChg || needSendSignal { // one of the uplink has local/remote state change regardless of CurrUPlinkIntf change, publish
			log.Tracef("launchHostProbe: send NI status update\n")
			probeMutex.Unlock()
			publishNetworkInstanceStatus(ctx, netstatus)
			probeMutex.Lock()
		}
		return true
	})
	iteration++
	probeMutex.Unlock()
	if needSendSignal {
		log.Tracef("launchHostProbe: send uplink signal\n")
		ctx.checkNIUplinks <- true
	}
	setProbeTimer(ctx, nhProbeInterval)
}

func probeCheckStatus(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {
	if len(status.PInfo) == 0 {
		return
	}

	prevIntf := status.CurrentUplinkIntf // the old Curr
	// Loop across all of the used port costs
	costList := types.GetPortCostList(*ctx.deviceNetworkStatus)
	// check probe stats in cost order
	for _, cost := range costList {
		var numOfUps int
		probeCheckStatusUseType(status, cost)
		currIntf := status.CurrentUplinkIntf
		if currIntf != "" {
			if currinfo, ok := status.PInfo[currIntf]; ok {
				numOfUps = infoUpCount(currinfo)
				log.Tracef("probeCheckStatus: cost %d, currintf %s, num Ups %d",
					cost, currIntf, numOfUps)
			}
		}
		if numOfUps > 0 {
			break
		}
	}
	if strings.Compare(status.CurrentUplinkIntf, prevIntf) != 0 { // the new Curr comparing to old Curr
		log.Tracef("probeCheckStatus: changing from %s to %s\n",
			status.PrevUplinkIntf, status.CurrentUplinkIntf)
		status.PrevUplinkIntf = prevIntf
		status.NeedIntfUpdate = true
		stateUP, err := getCurrIntfState(status, status.CurrentUplinkIntf)
		if err == nil {
			status.CurrIntfUP = stateUP
		}
		log.Tracef("probeCheckStatus: changing from %s to %s, intfup %v\n",
			status.PrevUplinkIntf, status.CurrentUplinkIntf, status.CurrIntfUP)
	} else { // even if the Curr intf does not change, it can transit state
		stateUP, err := getCurrIntfState(status, status.CurrentUplinkIntf)
		if err == nil {
			if status.CurrIntfUP != stateUP {
				log.Tracef("probeCheckStatus: intf %s state from %v to %v\n", prevIntf, status.CurrIntfUP, stateUP)
				status.CurrIntfUP = stateUP
				status.NeedIntfUpdate = true
			}
		}
	}
	log.Tracef("probeCheckStatus: %s current Uplink Intf %s, prev %s, need-update %v\n",
		status.BridgeName, status.CurrentUplinkIntf, status.PrevUplinkIntf, status.NeedIntfUpdate)
}

// How to determine the time to switch to another interface
// -- compare only within the same port cost
// -- Random assign one intf intially
// -- each intf has 3 types of states: both local and remote report UP, only one is UP, both are Down
// -- try to pick and switch to the one has the highest degree of UPs
// -- otherwise, don't switch
func probeCheckStatusUseType(status *types.NetworkInstanceStatus, cost uint8) {
	var numOfUps, upCnt int
	currIntf := status.CurrentUplinkIntf
	log.Tracef("probeCheckStatusUseType: from %s, cost %d, curr intf %s",
		status.BridgeName, cost, currIntf)
	// if we don't have a Curr or the Curr is removed from PInfo, get a valid one from the same cost
	if _, ok := status.PInfo[currIntf]; !ok || currIntf == "" {
		for _, info := range status.PInfo {
			if cost != info.Cost {
				continue
			}
			log.Tracef("probeCheckStatusUseType: currintf null, randomly assign %s now\n", info.IfName)
			currIntf = info.IfName
		}
	}

	if currIntf != "" {
		// if the current intf has higher cost than the current cost
		// (from the caller), then see if we can get an interface with that cost
		if status.PInfo[currIntf].Cost > cost {
			for _, info := range status.PInfo {
				if cost != info.Cost {
					continue
				}
				if infoUpCount(info) == 0 {
					continue
				}
				log.Tracef("probeCheckStatusUseType: currintf was not best cost %d, randomly assign %s now",
					cost, info.IfName)
				currIntf = info.IfName
				break
			}
		}
		currinfo := status.PInfo[currIntf]
		numOfUps = infoUpCount(currinfo)
		log.Tracef("probeCheckStatusUseType: curr intf %s, num ups %d\n", currIntf, numOfUps)
		if cost == currinfo.Cost && numOfUps == 2 { // good, no need to change
			status.CurrentUplinkIntf = currIntf
			return
		}
		log.Tracef("probeCheckStatusUseType: before loop\n")
		for _, info := range status.PInfo {
			if cost != info.Cost {
				continue
			}
			log.Tracef("probeCheckStatusUseType: compare %s, and %s\n", info.IfName, currIntf)
			if strings.Compare(info.IfName, currIntf) == 0 {
				continue
			}
			upCnt = infoUpCount(info)
			log.Tracef("probeCheckStatusUseType: upcnt %d, vs my ups %d\n", upCnt, numOfUps)
			if numOfUps < upCnt {
				currIntf = info.IfName
				numOfUps = upCnt
			}
		}
	}
	// We did not find any viable port, do not overwrite the current selected port
	if currIntf != "" {
		status.CurrentUplinkIntf = currIntf
	}
}

func getCurrIntfState(status *types.NetworkInstanceStatus, currIntf string) (types.CurrIntfStatusType, error) {
	if _, ok := status.PInfo[currIntf]; !ok {
		err := fmt.Errorf("getCurrIntfState: intf %s has no info", currIntf)
		log.Errorf("getCurrIntfState: %s, error %v\n", currIntf, err)
		return types.CurrIntfNone, err
	}
	info := status.PInfo[currIntf]
	if infoUpCount(info) > 0 {
		return types.CurrIntfUP, nil
	} else {
		return types.CurrIntfDown, nil
	}
}

func infoUpCount(info types.ProbeInfo) int {
	var upCnt int
	if info.GatewayUP && info.RemoteHostUP {
		upCnt = 2
	} else if info.GatewayUP || info.RemoteHostUP {
		upCnt = 1
	}
	return upCnt
}

func getSystemURL() string {
	var remoteURL string
	if serverNameAndPort == "" {
		server, err := ioutil.ReadFile(types.ServerFileName)
		if err == nil {
			serverNameAndPort = strings.TrimSpace(string(server))
		}
	}
	if serverNameAndPort != "" {
		remoteURL = serverNameAndPort
	} else {
		remoteURL = "www.google.com"
	}
	return "http://" + remoteURL
}

func getRemoteURL(netstatus *types.NetworkInstanceStatus, defaultURL string) string {
	remoteURL := defaultURL
	// check on User defined URL/IP address
	if netstatus.PConfig.ServerURL != "" {
		if strings.Contains(netstatus.PConfig.ServerURL, "http") {
			remoteURL = netstatus.PConfig.ServerURL
		} else {
			// use 'http' instead of 'https'
			remoteURL = "http://" + netstatus.PConfig.ServerURL
		}
	} else if ipAddrIsValid(netstatus.PConfig.ServerIP) {
		remoteURL = "http://" + netstatus.PConfig.ServerIP.String()
	}
	return remoteURL
}

func getProbeRatio(netstatus *types.NetworkInstanceStatus) uint32 {
	if netstatus.PConfig.ProbeInterval != 0 {
		ratio := netstatus.PConfig.ProbeInterval / nhProbeInterval
		if ratio < minProbeRatio {
			return minProbeRatio
		}
		return ratio
	}
	return remoteTolocalRatio
}

// base on the probe result, determine if the port should be good to use
// and record the latency data for reaching the remote host
func probeProcessReply(info *types.ProbeInfo, gotReply bool, latency int64, isLocal bool) bool {
	var stateChange bool
	if isLocal {
		log.Tracef("probeProcessReply: intf %s, gw up %v, sucess count %d, down count %d, got reply %v\n",
			info.IfName, info.GatewayUP, info.SuccessCnt, info.FailedCnt, gotReply)
		if gotReply {
			// fast convergence treatment for local ping, if the intf has stayed down for a while
			// and not a flapping case, when on this first ping success, bring the local GatewayUP to 'UP'
			if !info.GatewayUP && info.SuccessCnt == 0 && info.FailedCnt > stayDownMinCount {
				info.GatewayUP = true
				stateChange = true
				log.Tracef("probeProcessReply: intf %s, down count %d, ping success, bring it up\n",
					info.IfName, info.FailedCnt)
			}
			info.SuccessCnt++
			info.FailedCnt = 0
			info.TransDown = false
		} else {
			if info.GatewayUP && info.FailedCnt == 0 && info.SuccessCnt > stayUPMinCount {
				info.TransDown = true
			}
			info.FailedCnt++
			info.SuccessCnt = 0
		}
		if info.FailedCnt > maxContFailCnt && info.GatewayUP {
			info.GatewayUP = false
			stateChange = true
		} else if info.SuccessCnt > maxContSuccessCnt && !info.GatewayUP {
			info.GatewayUP = true
			stateChange = true
		}
	} else {
		log.Tracef("probeProcessReply: intf %s, remote probing got reply %v, success count %d, fail count %d\n",
			info.IfName, gotReply, info.SuccessProbeCnt, info.FailedProbeCnt)
		if gotReply {
			totalLatency := info.AveLatency * int64(info.SuccessProbeCnt)
			info.SuccessProbeCnt++
			info.AveLatency = (totalLatency + latency) / int64(info.SuccessProbeCnt)
			info.FailedProbeCnt = 0
		} else {
			// if remote probe success for a while, and local ping transition from up->down,
			// bring the remote down now
			// it can happen the first remote probe fails, but local ping has not bright down the Gateway,
			//
			if info.TransDown && !info.GatewayUP && info.RemoteHostUP && info.FailedProbeCnt < 2 {
				info.RemoteHostUP = false
				stateChange = true
				info.TransDown = false
			}
			info.FailedProbeCnt++
			info.SuccessProbeCnt = 0
			info.AveLatency = 0
		}
		if info.FailedProbeCnt > maxContFailCnt && info.RemoteHostUP {
			info.RemoteHostUP = false
			stateChange = true
		} else if info.SuccessProbeCnt > maxContSuccessCnt && !info.RemoteHostUP {
			info.RemoteHostUP = true
			stateChange = true
		}
	}
	return stateChange
}

func probeFastPing(info types.ProbeInfo) (bool, bool) {
	var dstaddress, srcaddress net.IPAddr
	var pingSuccess bool
	p := fastping.NewPinger()

	if !ipAddrIsValid(info.LocalAddr) {
		if info.GatewayUP || info.RemoteHostUP {
			return false, true
		}
		return false, false
	}

	// if we don't have a gateway address or local intf address, no need to ping
	if !ipAddrIsValid(info.NhAddr) {
		return false, false
	}

	dstaddress.IP = info.NhAddr
	p.AddIPAddr(&dstaddress)

	srcaddress.IP = info.LocalAddr
	p.Source(srcaddress.String())
	if srcaddress.String() == "" || dstaddress.String() == "" {
		return false, false
	}
	p.MaxRTT = time.Millisecond * time.Duration(maxPingWait)
	log.Tracef("probeFastPing: add to ping, address %s with source %s, maxrtt %v\n",
		dstaddress.String(), srcaddress.String(), p.MaxRTT)
	p.OnRecv = func(ip *net.IPAddr, d time.Duration) {
		if strings.Compare(ip.String(), dstaddress.String()) == 0 {
			pingSuccess = true
			log.Tracef("probeFastPing: got reply from %s, duration %d nanosec or rtt %v\n",
				dstaddress.String(), int64(d.Nanoseconds()), d)
		}
	}
	p.OnIdle = func() {
		log.Tracef("probeFastPing: run finish\n")
	}
	err := p.Run()
	if err != nil {
		log.Tracef("probeFastPing: run error, %v\n", err)
	}
	return pingSuccess, false
}

func setProbeTimer(ctx *zedrouterContext, probeIntv uint32) {
	interval := time.Duration(probeIntv)
	log.Tracef("setProbeTimer: interval %d sec\n", interval)
	ctx.hostProbeTimer = time.NewTimer(interval * time.Second)
}

// copy probing stats from the NI status ListMap into status
func copyProbeStats(ctx *zedrouterContext, netstatus *types.NetworkInstanceStatus) {
	mapst, ok := ctx.networkInstanceStatusMap.Load(netstatus.UUID)
	if !ok {
		return
	}
	mapstatus := mapst.(*types.NetworkInstanceStatus)
	if mapstatus != nil {
		probeMutex.Lock()
		for _, infom := range mapstatus.PInfo {
			if info, ok := netstatus.PInfo[infom.IfName]; ok {
				log.Tracef("copyProbeStats: (%s) on %s, info/map success %d/%d, fail %d/%d\n",
					netstatus.BridgeName, info.IfName, info.SuccessCnt, infom.SuccessCnt, info.FailedCnt, infom.FailedCnt)
				info.SuccessCnt = infom.SuccessCnt
				info.FailedCnt = infom.FailedCnt
				info.SuccessProbeCnt = infom.SuccessProbeCnt
				info.FailedProbeCnt = infom.FailedProbeCnt
				info.TransDown = infom.TransDown
				netstatus.PInfo[info.IfName] = info
			}
		}
		probeMutex.Unlock()
	}
}

func resetIsPresentFlag(netstatus *types.NetworkInstanceStatus, intf string) {
	for _, info := range netstatus.PInfo {
		if info.IfName != intf {
			continue
		}
		log.Functionf("resetIsPresentFlag: was %v\n", info.IsPresent)
		info.IsPresent = false
		if _, ok := netstatus.PInfo[info.IfName]; ok {
			netstatus.PInfo[info.IfName] = info
		}
	}
}

func ipAddrIsValid(ipAddr net.IP) bool {
	if ipAddr == nil || ipAddr.IsUnspecified() {
		return false
	}
	return true
}

func getNIProbeMetric(ctx *zedrouterContext, netstatus *types.NetworkInstanceStatus) types.ProbeMetrics {
	var metrics types.ProbeMetrics
	remoteURL := getSystemURL()
	probeMutex.Lock()
	defer probeMutex.Unlock()
	mapst, ok := ctx.networkInstanceStatusMap.Load(netstatus.UUID)
	if !ok {
		return metrics
	}
	mapstatus := mapst.(*types.NetworkInstanceStatus)
	if mapstatus != nil {
		metrics.CurrUplinkIntf = mapstatus.CurrentUplinkIntf
		metrics.RemoteEndpoint = getRemoteURL(mapstatus, remoteURL)
		metrics.LocalPingIntvl = nhProbeInterval // need to change if user can configure this later
		metrics.RemotePingIntvl = getProbeRatio(mapstatus) * nhProbeInterval
		metrics.UplinkNumber = uint32(len(mapstatus.PInfo))
		for _, infom := range mapstatus.PInfo {
			intfstats := types.ProbeIntfMetrics{
				IntfName:        infom.IfName,
				NexthopGw:       infom.NhAddr,
				GatewayUP:       infom.GatewayUP,
				RmoteStatusUP:   infom.RemoteHostUP,
				GatewayUPCnt:    infom.SuccessCnt,
				GatewayDownCnt:  infom.FailedCnt,
				RemoteUPCnt:     infom.SuccessProbeCnt,
				RemoteDownCnt:   infom.FailedProbeCnt,
				LatencyToRemote: uint32(infom.AveLatency),
			}
			metrics.IntfProbeStats = append(metrics.IntfProbeStats, intfstats)
		}
	}
	log.Tracef("getNIProbeMetric: %s, %v\n", netstatus.BridgeName, metrics)
	return metrics
}
