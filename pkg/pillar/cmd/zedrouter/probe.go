// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Probe to the local interface nexthop and remote servers

package zedrouter

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
	fastping "github.com/tatsushid/go-fastping"
)

const (
	maxContFailCnt     uint32 = 6   // number of continuous failure to declare Donw
	maxContSuccessCnt  uint32 = 3   // number of continuous success to declare UP
	maxPingWait        int    = 100 // wait for 100 millisecond for ping timeout
	maxRemoteProbeWait uint32 = 3   // wait for 3 seconds for remote host respond
	remoteTolocalRatio uint32 = 20  // every 20 times of local ping, perform remote probing
	// e.g. if the local ping timer is every 15 seconds, every remote httping is every 5 minutes
	serverFileName string = "/config/server"
)

type probeRes struct {
	isRemoteReply bool
	latency       int64 // in millisecond
}

var iteration uint32
var serverNameAndPort string
var zcloudCtx = zedcloud.ZedCloudContext{
	FailureFunc:        zedcloud.ZedCloudFailure,
	SuccessFunc:        zedcloud.ZedCloudSuccess,
	TlsConfig:          &tls.Config{InsecureSkipVerify: true},
	NetworkSendTimeout: maxRemoteProbeWait,
}

// called from handleDNSModify
func deviceUpdateNIprobing(ctx *zedrouterContext, status *types.DeviceNetworkStatus) {
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	log.Infof("deviceUpdateNIprobing: enter\n")
	for _, port := range status.Ports {
		log.Infof("deviceUpdateNIprobing: port %s\n", port.Name)
		if !port.IsMgmt { // for now, only probing the uplink
			continue
		}

		for _, ipinfo := range port.AddrInfoList {
			log.Infof("deviceUpdateNIprobing: port %s, free %v, addr %v, Gw %v\n",
				port.IfName, port.Free, ipinfo.Addr, port.Gateway)
			break
		}

		for _, st := range items {
			netstatus := cast.CastNetworkInstanceStatus(st)
			niProbingUpdatePort(ctx, port, &netstatus)
			checkNIprobeUplink(ctx, &netstatus)
		}
	}
}

// called from handleNetworkInstanceModify and handleNetworkInstanceCreate
func niUpdateNIprobing(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {
	pub := ctx.subDeviceNetworkStatus
	items := pub.GetAll()
	log.Infof("niUpdateNIprobing: enter\n")
	for _, st := range items {
		devStatus := cast.CastDeviceNetworkStatus(st)
		for _, port := range devStatus.Ports {
			for _, ipinfo := range port.AddrInfoList {
				log.Infof("niUpdateNIprobing: port %s, free %v, addr %v, Gw %v\n",
					port.IfName, port.Free, ipinfo.Addr, port.Gateway)
			}
			niProbingUpdatePort(ctx, port, status)
		}
	}
	checkNIprobeUplink(ctx, status)
}

func niProbingUpdatePort(ctx *zedrouterContext, port types.NetworkPortStatus,
	netstatus *types.NetworkInstanceStatus) {
	log.Infof("niProbingUpdatePort: enter\n")
	if _, ok := netstatus.PInfo[port.IfName]; !ok {
		if port.IfName == "" { // no need to probe for air-gap type of NI
			return
		}
		info := types.ProbeInfo{
			IfName:       port.IfName,
			GatewayUP:    true,
			NhAddr:       port.Gateway,
			LocalAddr:    portGetIntfAddr(port),
			Class:        getIntfClassByIOBundle(ctx, port),
			RemoteHostUP: true,
		}
		netstatus.PInfo[port.IfName] = info
		log.Infof("niProbingUpdatePort: %s assigned new %s, info len %d, class %v\n",
			netstatus.BridgeName, port.IfName, len(netstatus.PInfo), info.Class)
	} else {
		info := netstatus.PInfo[port.IfName]
		if !port.Gateway.Equal(info.NhAddr) {
			info.NhAddr = port.Gateway
			info.LocalAddr = portGetIntfAddr(port)
			info.FailedCnt = 0
			info.SuccessCnt = 0
			netstatus.PInfo[port.IfName] = info
			log.Infof("niProbingUpdatePort: %s modified %s", netstatus.BridgeName, port.IfName)
		} else {
			log.Infof("niProbingUpdatePort: %s gw matches %s", netstatus.BridgeName, port.IfName)
		}
	}
}

func getIntfClassByIOBundle(ctx *zedrouterContext, port types.NetworkPortStatus) types.IntfClass {
	aa := ctx.assignableAdapters
	if aa == nil { // no information
		log.Infof("getIntfClassIOBundle: aa is nil")
		return types.Class_ETHER
	}
	ioBundle := aa.LookupIoBundleNet(port.IfName)
	if ioBundle == nil {
		log.Infof("getIntfClassIOBundle: iobundle is nil")
		return types.Class_ETHER
	}
	switch ioBundle.Type {
	case types.IoNetEth, types.IoNetWLAN:
		// satellite can also use ethernet type, need special label on the port from user
		return types.Class_ETHER
	case types.IoNetWWAN:
		return types.Class_LTE
	}
	// catch for all
	return types.Class_ETHER
}

// after port or NI changes, if we don't have a current uplink,
// randomly assign one and publish, if we already do, leave it as is
// each NI may have a different good uplink
func checkNIprobeUplink(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {
	if status.CurrentUplinkIntf != "" {
		if _, ok := status.PInfo[status.CurrentUplinkIntf]; ok {
			if strings.Compare(status.PInfo[status.CurrentUplinkIntf].IfName, status.CurrentUplinkIntf) == 0 {
				return
			}
		}
		// if the Current Uplink intf does not have an info entry, re-pick one below
		status.CurrentUplinkIntf = ""
	}

	if len(status.PInfo) > 0 {
		for _, info := range status.PInfo {
			status.CurrentUplinkIntf = info.IfName
			break
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
	var isReachable, needSendSignal bool
	var remoteURL string
	nhPing := make(map[string]bool)
	remoteProbe := make(map[string]map[string]probeRes)
	log.Infof("launchHostProbe: enter\n")
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	dpub := ctx.subDeviceNetworkStatus
	ditems := dpub.GetAll()

	if serverNameAndPort == "" {
		server, err := ioutil.ReadFile(serverFileName)
		if err == nil {
			serverNameAndPort = strings.TrimSpace(string(server))
		}
	}
	if serverNameAndPort != "" {
		remoteURL = serverNameAndPort
	} else {
		remoteURL = "www.google.com"
	}

	for _, st := range items {
		netstatus := cast.CastNetworkInstanceStatus(st)
		log.Infof("launchHostProbe: status on ni(%s) current uplink %s\n", netstatus.BridgeName, netstatus.CurrentUplinkIntf)
		for _, info := range netstatus.PInfo {
			var needToProbe bool
			var isRemoteResp probeRes
			log.Infof("launchHostProbe: intf %s, gw %v, statusUP %v, remoteHostUP %v\n",
				info.IfName, info.NhAddr, info.GatewayUP, info.RemoteHostUP)

			// Local nexthop ping, only apply to Ethernet type of interface
			if info.Class == types.Class_ETHER {
				if _, ok := nhPing[info.IfName]; !ok {
					isReachable = probeFastPing(info)
					nhPing[info.IfName] = isReachable
				} else {
					isReachable = nhPing[info.IfName]
					log.Infof("launchHostProbe: already got ping result on %s(%s) %v\n", info.IfName, info.NhAddr.String(), isReachable)
				}

				probeProcessReply(&info, isReachable, 0, true)
				log.Infof("launchHostProbe(%d): gateway up %v, success count %d, failed count %d, remote success %d, remote fail %d\n",
					iteration, info.GatewayUP, info.SuccessCnt, info.FailedCnt, info.SuccessProbeCnt, info.FailedProbeCnt)
			}

			// for every X number of nexthop ping iteration, do the remote probing
			// although we could have checked if the nexthop is down, there is no need
			// to do remote probing, but just in case, local nexthop ping is filtered by
			// the gateway firewall, and since we only do X iteration, it's simpler just doing it
			if iteration%remoteTolocalRatio == 0 {
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

					log.Infof("launchHostProbe: probe on %s to remote %s, resp %v\n", info.IfName, remoteURL, isRemoteResp)
				}

				if needToProbe {
					var foundport bool
					for _, st := range ditems {
						devStatus := cast.CastDeviceNetworkStatus(st)
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
						resp, _, rtf, err := zedcloud.SendOnIntf(zcloudCtx, remoteURL, info.IfName, 0, nil, true)
						if err != nil {
							log.Infof("launchHostProbe: send on intf err %v\n", err)
						}
						if rtf {
							log.Infof("launchHostProbe: remote temp failure\n")
						}
						if resp != nil {
							log.Infof("launchHostProbe: server %s status code %d\n", serverNameAndPort, resp.StatusCode)
							//
							// isRemoteResp.isRemoteReply = (resp.StatusCode == 200)
							// make it any reply is good
							isRemoteResp.isRemoteReply = true
						}
						isRemoteResp.latency = time.Since(startTime).Nanoseconds() / int64(time.Millisecond)
					}
					remoteProbe[info.IfName][remoteURL] = isRemoteResp
				}

				probeProcessReply(&info, isRemoteResp.isRemoteReply, isRemoteResp.latency, false)
				log.Infof("launchHostProbe: probe on %s to remote %s, latency %d msec, success cnt %d, failed cnt %d, need probe %v\n",
					info.IfName, remoteURL, isRemoteResp.latency, info.SuccessProbeCnt, info.FailedProbeCnt, needToProbe)
			}

			netstatus.PInfo[info.IfName] = info
		}
		probeCheckStatus(&netstatus)
		if netstatus.NeedIntfUpdate {
			needSendSignal = true
		}
		publishNetworkInstanceStatus(ctx, &netstatus)
	}
	if needSendSignal {
		ctx.checkNIUplinks <- true
	}
	iteration++
}

func probeCheckStatus(status *types.NetworkInstanceStatus) {
	if len(status.PInfo) == 0 {
		return
	}

	// check probe stats from lower intf class to higher class
	// continue to the next class only if there is no usable outbound intf within the lower class
	for c := types.Class_ETHER; c <= types.Class_LAST; c++ {
		var numOfUps int
		probeCheckStatusUseClass(status, c)
		currIntf := status.CurrentUplinkIntf
		if currIntf != "" {
			if currinfo, ok := status.PInfo[currIntf]; ok {
				numOfUps = infoUpCount(currinfo)
			}
		}
		if numOfUps > 0 {
			break
		}
	}
	log.Infof("probeCheckStatus: %s current Uplink Intf %s, prev %s\n", status.BridgeName, status.CurrentUplinkIntf, status.PrevUplinkIntf)
}

// How to determine the time to switch to another interface
// -- compare only within the same interface class: ether, lte, sat
// -- Random assign one intf intially
// -- each intf has 3 types of states: both local and remote report UP, only one is UP, both are Down
// -- try to pick and switch to the one has the highest degree of UPs
// -- otherwise, don't switch
func probeCheckStatusUseClass(status *types.NetworkInstanceStatus, class types.IntfClass) {
	var numOfUps, upCnt int
	currIntf := status.CurrentUplinkIntf
	prevIntf := currIntf
	if currIntf == "" {
		for _, info := range status.PInfo {
			if class != info.Class {
				continue
			}
			upCnt = infoUpCount(info)
			if currIntf == "" { // assign any intf for now
				currIntf = info.IfName
				numOfUps = upCnt
				continue
			} else {
				if numOfUps < upCnt {
					currIntf = info.IfName
					numOfUps = upCnt
				}
			}
		}
	} else {
		if _, ok := status.PInfo[currIntf]; !ok {
			// should not happen, zero it out, come next time to process
			log.Errorf("probeCheckStatus: current Uplink Intf %s error", currIntf)
			status.CurrentUplinkIntf = ""
			return
		}
		currinfo := status.PInfo[currIntf]
		numOfUps = infoUpCount(currinfo)
		if class == currinfo.Class && numOfUps == 2 { // good, no need to change
			return
		}
		if class != currinfo.Class { // from a lower intf class, start over again
			currIntf = ""
		}
		for _, info := range status.PInfo {
			if class != info.Class {
				continue
			}
			if strings.Compare(info.IfName, currIntf) == 0 {
				continue
			}
			upCnt = infoUpCount(info)
			if numOfUps < upCnt {
				currIntf = info.IfName
				numOfUps = upCnt
			}
		}
	}
	if strings.Compare(status.CurrentUplinkIntf, currIntf) != 0 {
		log.Infof("probeCheckStatusUseClass: changing from %s to %s\n",
			status.CurrentUplinkIntf, currIntf)
		status.CurrentUplinkIntf = currIntf
		status.PrevUplinkIntf = prevIntf
		status.NeedIntfUpdate = true
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

// base on the probe result, determine if the port should be good to use
// and record the latency data for reaching the remote host
func probeProcessReply(info *types.ProbeInfo, gotReply bool, latency int64, isLocal bool) {
	if isLocal {
		if gotReply {
			info.SuccessCnt++
			info.FailedCnt = 0
		} else {
			info.FailedCnt++
			info.SuccessCnt = 0
		}
		if info.FailedCnt > maxContFailCnt && info.GatewayUP {
			info.GatewayUP = false
		} else if info.SuccessCnt > maxContSuccessCnt && !info.GatewayUP {
			info.GatewayUP = true
		}
	} else {
		if gotReply {
			totalLatency := info.AveLatency * int64(info.SuccessProbeCnt)
			info.SuccessProbeCnt++
			info.AveLatency = (totalLatency + latency) / int64(info.SuccessProbeCnt)
			info.FailedProbeCnt = 0
		} else {
			info.FailedProbeCnt++
			info.SuccessProbeCnt = 0
			info.AveLatency = 0
		}
		if info.FailedProbeCnt > maxContFailCnt && info.RemoteHostUP {
			info.RemoteHostUP = false
		} else if info.SuccessProbeCnt > maxContSuccessCnt && !info.RemoteHostUP {
			info.RemoteHostUP = true
		}
	}
}

func probeFastPing(info types.ProbeInfo) bool {
	var dstaddress, srcaddress net.IPAddr
	var pingSuccess bool
	p := fastping.NewPinger()

	zeroIP := net.ParseIP("0.0.0.0")
	// if we don't have a gateway address or local intf address, no need to ping
	if zeroIP.Equal(info.NhAddr) || zeroIP.Equal(info.LocalAddr) {
		return false
	}

	dstaddress.IP = info.NhAddr
	p.AddIPAddr(&dstaddress)

	srcaddress.IP = info.LocalAddr
	p.Source(srcaddress.String())
	p.MaxRTT = time.Millisecond * time.Duration(maxPingWait)
	log.Infof("probeFastPing: add to ping, address %s with source %s, maxrtt %v\n",
		dstaddress.String(), srcaddress.String(), p.MaxRTT)
	p.OnRecv = func(ip *net.IPAddr, d time.Duration) {
		if strings.Compare(ip.String(), dstaddress.String()) == 0 {
			pingSuccess = true
			log.Infof("probeFastPing: got reply from %s, duration %d nanosec or rtt %v\n",
				dstaddress.String(), int64(d.Nanoseconds()), d)
		}
	}
	p.OnIdle = func() {
		log.Infof("probeFastPing: run finish\n")
	}
	err := p.Run()
	if err != nil {
		log.Infof("probeFastPing: run error, %v\n", err)
	}
	return pingSuccess
}
