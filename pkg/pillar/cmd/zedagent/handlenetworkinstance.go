// Copyright (c) 2018,2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkInstanceStatus from zedrouter

package zedagent

import (
	"bytes"
	"fmt"
	"time"

	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/flowlog"
	zinfo "github.com/lf-edge/eve-api/go/info"   // XXX need to stop using
	zmet "github.com/lf-edge/eve-api/go/metrics" // zinfo and zmet here
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func handleNetworkInstanceCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNetworkInstanceImpl(ctxArg, key, statusArg)
}

func handleNetworkInstanceModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNetworkInstanceImpl(ctxArg, key, statusArg)
}

func handleNetworkInstanceImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNetworkInstanceStatusImpl(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.NetworkInstanceStatus)
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkInstance error %s",
			status.Error)
	}
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, false, AllDest)
	log.Functionf("handleNetworkInstanceImpl(%s) done", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNetworkInstanceDelete(%s)", key)
	status := statusArg.(types.NetworkInstanceStatus)
	ctx := ctxArg.(*zedagentContext)
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, true, AllDest)
	log.Functionf("handleNetworkInstanceDelete(%s) done", key)
}

// prepareAndPublishNetworkInstanceInfoMsg sends a message
// which is mostly empty if deleted is set as a delete indication.
// XXX When a network instance is deleted it is ideal to
// send a flag such as deleted/gone inside
// ZInfoNetworkInstance message. Having a separate flag
// (indicating deletion) would make is explicit
// and easy for the cloud process.
func prepareAndPublishNetworkInstanceInfoMsg(ctx *zedagentContext,
	status types.NetworkInstanceStatus, deleted bool, dest destinationBitset) {

	infoMsg := &zinfo.ZInfoMsg{}
	infoType := new(zinfo.ZInfoTypes)
	*infoType = zinfo.ZInfoTypes_ZiNetworkInstance
	infoMsg.DevId = *proto.String(devUUID.String())
	infoMsg.Ztype = *infoType
	infoMsg.AtTimeStamp = timestamppb.Now()

	uuid := status.Key()
	info := new(zinfo.ZInfoNetworkInstance)
	info.NetworkID = uuid
	info.NetworkVersion = status.UUIDandVersion.Version
	if !deleted {
		info.Displayname = status.DisplayName
		info.InstType = uint32(status.Type)
		// info.Ports is set for new controllers (that support NI with multiple ports),
		// while we also continue to set info.CurrentUplinkIntf for backward-compatibility
		// with older controllers.
		info.Ports = status.Ports
		if len(status.Ports) > 0 {
			// Just report the first port from the list.
			// Typically, there will be at most one port anyway.
			info.CurrentUplinkIntf = status.Ports[0]
		}
		info.Mtu = uint32(status.MTU)
		for _, route := range status.CurrentRoutes {
			// Gateway and GatewayApp can be each empty (for e.g. connected route).
			// Avoid returning "<nil>" and UUID with all zeroes.
			var gwIP, gwApp string
			if route.Gateway != nil {
				gwIP = route.Gateway.String()
			}
			if route.GatewayApp != nilUUID {
				gwApp = route.GatewayApp.String()
			}
			info.IpRoutes = append(info.IpRoutes, &zinfo.IPRoute{
				DestinationNetwork: route.DstNetwork.String(),
				Gateway:            gwIP,
				Port:               route.OutputPort,
				GatewayApp:         gwApp,
			})
		}
		if !status.ErrorTime.IsZero() {
			errInfo := new(zinfo.ErrorInfo)
			errInfo.Description = status.Error
			errInfo.Timestamp = timestamppb.New(status.ErrorTime)
			errInfo.Severity = zinfo.Severity(status.ErrorSeverity)
			info.NetworkErr = append(info.NetworkErr, errInfo)
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_ERROR
		} else if status.ChangeInProgress != types.ChangeInProgressTypeNone {
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_INIT
		} else if status.Activated {
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		} else {
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}
		info.Activated = status.Activated

		info.BridgeNum = uint32(status.BridgeNum)
		info.BridgeName = status.BridgeName
		if len(status.BridgeIPAddr) > 0 {
			info.BridgeIPAddr = status.BridgeIPAddr.String()
		}

		for mac, addrs := range status.IPAssignments {
			assignment := new(zinfo.ZmetIPAssignmentEntry)
			assignment.MacAddress = mac
			for _, assignedIP := range addrs.IPv4Addrs {
				assignment.IpAddress = append(assignment.IpAddress,
					assignedIP.Address.String())
			}
			for _, assignedIP := range addrs.IPv6Addrs {
				assignment.IpAddress = append(assignment.IpAddress,
					assignedIP.Address.String())
			}
			info.IpAssignments = append(info.IpAssignments, assignment)
		}
		for _, v := range status.Vifs {
			vi := new(zinfo.ZmetVifInfo)
			vi.VifName = v.Name
			vi.MacAddress = v.MacAddr.String()
			vi.AppID = v.AppID.String()
			info.Vifs = append(info.Vifs, vi)
		}
		for _, port := range info.Ports {
			ia := ctx.assignableAdapters.LookupIoBundleLogicallabel(port)
			if ia == nil {
				log.Warnf("Missing IoBundle for port %s", port)
			} else {
				reportAA := new(zinfo.ZioBundle)
				reportAA.Type = zcommon.PhyIoType(ia.Type)
				reportAA.Name = ia.Logicallabel
				// XXX Add Phylabel in protobuf message?
				reportAA.UsedByAppUUID = devUUID.String()
				list := ctx.assignableAdapters.LookupIoBundleAny(ia.Phylabel)
				for _, ib := range list {
					if ib == nil {
						continue
					}
					reportAA.Members = append(reportAA.Members, ib.Logicallabel)
					if ib.MacAddr != "" {
						reportMac := new(zinfo.IoAddresses)
						reportMac.MacAddress = ib.MacAddr
						reportAA.IoAddressList = append(reportAA.IoAddressList,
							reportMac)
					}
					log.Tracef("AssignableAdapters for %s macs %v",
						reportAA.Name, reportAA.IoAddressList)
				}
				info.AssignedAdapters = append(info.AssignedAdapters,
					reportAA)
			}
		}
	}

	infoMsg.InfoContent = new(zinfo.ZInfoMsg_Niinfo)
	if x, ok := infoMsg.GetInfoContent().(*zinfo.ZInfoMsg_Niinfo); ok {
		x.Niinfo = info
	}
	log.Tracef("Publish NetworkInstance Info message to zedcloud: %v",
		infoMsg)

	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("Publish NetworkInstance proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, true, false, false,
		zinfo.ZInfoTypes_ZiNetworkInstance)
}

func protoEncodeGenericInstanceMetric(status types.NetworkInstanceMetrics,
	metric *zmet.ZMetricNetworkInstance) {
	networkStats := new(zmet.ZMetricNetworkStats)
	rxStats := new(zmet.NetworkStats)
	txStats := new(zmet.NetworkStats)
	for _, netMetrics := range status.NetworkMetrics.MetricList {
		// Tx/Rx of NI is equal to the total of Tx/Rx on all member
		// virtual interfaces excluding the bridge itself.
		if netMetrics.IfName != status.BridgeName {
			rxStats.TotalBytes += netMetrics.RxBytes
			rxStats.TotalPackets += netMetrics.RxPkts
			txStats.TotalBytes += netMetrics.TxBytes
			txStats.TotalPackets += netMetrics.TxPkts
		}
		// Drops and errors are collected both from VIFs and the bridge.
		rxStats.Errors += netMetrics.RxErrors
		rxStats.Drops += netMetrics.RxDrops
		rxStats.Drops += netMetrics.RxAclDrops
		rxStats.Drops += netMetrics.RxAclRateLimitDrops
		txStats.Errors += netMetrics.TxErrors
		txStats.Drops += netMetrics.TxDrops
		txStats.Drops += netMetrics.TxAclDrops
		txStats.Drops += netMetrics.TxAclRateLimitDrops
	}
	networkStats.Rx = rxStats
	networkStats.Tx = txStats
	metric.NetworkStats = networkStats
}

func handleAppFlowMonitorCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppFlowMonitorImpl(ctxArg, key, statusArg)
}

func handleAppFlowMonitorModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppFlowMonitorImpl(ctxArg, key, statusArg)
}

func handleAppFlowMonitorImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAppFlowMonitorImpl(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	flows := statusArg.(types.IPFlow)

	// encoding the flows with protobuf format
	pflows := protoEncodeAppFlowMonitorProto(flows)

	// publish protobuf-encoded flowlog to zedcloud
	select {
	case ctx.flowlogQueue <- pflows:
	default:
		log.Errorf("Flowlog queue is full, dropping flowlog entry: %+v", pflows.Scope)
		ctx.flowLogMetrics.Lock()
		ctx.flowLogMetrics.Messages.Drops++
		ctx.flowLogMetrics.Flows.Drops += uint64(len(pflows.Flows))
		ctx.flowLogMetrics.DNSReqs.Drops += uint64(len(pflows.DnsReqs))
		ctx.flowLogMetrics.Unlock()
	}
}

func handleAppFlowMonitorDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAppFlowMonitorDelete(%s)", key)
}

func aclActionToProtoAction(action types.ACLActionType) flowlog.ACLAction {
	switch action {
	case types.ACLActionAccept:
		return flowlog.ACLAction_ActionAccept
	case types.ACLActionDrop:
		return flowlog.ACLAction_ActionDrop
	default:
		return flowlog.ACLAction_ActionUnknown
	}
}

func protoEncodeAppFlowMonitorProto(ipflow types.IPFlow) *flowlog.FlowMessage {

	pflows := new(flowlog.FlowMessage)
	pflows.DevId = *proto.String(devUUID.String())

	// ScopeInfo fill in
	pScope := new(flowlog.ScopeInfo)
	pScope.Uuid = ipflow.Scope.AppUUID.String()
	pScope.Intf = ipflow.Scope.NetAdapterName
	pScope.LocalIntf = ipflow.Scope.BrIfName
	pScope.NetInstUUID = ipflow.Scope.NetUUID.String()
	pflows.Scope = pScope

	// get the ip flows from the input
	for _, rec := range ipflow.Flows {
		prec := new(flowlog.FlowRecord)

		// IpFlow fill in
		pIpflow := new(flowlog.IpFlow)
		pIpflow.Src = rec.Flow.Src.String()
		pIpflow.Dest = rec.Flow.Dst.String()
		pIpflow.SrcPort = int32(rec.Flow.SrcPort)
		pIpflow.DestPort = int32(rec.Flow.DstPort)
		pIpflow.Protocol = int32(rec.Flow.Proto)
		prec.Flow = pIpflow

		prec.Inbound = rec.Inbound
		prec.AclId = rec.ACLID
		prec.Action = aclActionToProtoAction(rec.Action)
		// prec.AclName =
		prec.StartTime = timestamppb.New(time.Unix(0, rec.StartTime))
		prec.EndTime = timestamppb.New(time.Unix(0, rec.StopTime))
		prec.TxBytes = rec.TxBytes
		prec.TxPkts = rec.TxPkts
		prec.RxBytes = rec.RxBytes
		prec.RxPkts = rec.RxPkts
		pflows.Flows = append(pflows.Flows, prec)
	}

	// get the ip DNS records from the input
	for _, dns := range ipflow.DNSReqs {
		pdns := new(flowlog.DnsRequest)
		pdns.HostName = dns.HostName
		for _, address := range dns.Addrs {
			pdns.Addrs = append(pdns.Addrs, address.String())
		}
		pdns.RequestTime = timestamppb.New(time.Unix(0, dns.RequestTime))
		pdns.AclNum = dns.ACLNum
		pflows.DnsReqs = append(pflows.DnsReqs, pdns)
	}

	return pflows
}

func flowlogTask(ctx *zedagentContext, flowlogQueue <-chan *flowlog.FlowMessage) {
	wdName := agentName + "flowlog"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	var (
		iteration    int
		retryMsg     *flowlog.FlowMessage
		retryAttempt int
		retryTimer   *time.Timer
	)
	publish := func(msg *flowlog.FlowMessage) {
		start := time.Now()
		log.Function("flowlogTask got message")
		var retry bool
		err := publishFlowMessage(msg, iteration)
		if err == nil {
			iteration++
			ctx.flowLogMetrics.Lock()
			ctx.flowLogMetrics.Messages.Success++
			ctx.flowLogMetrics.Flows.Success += uint64(len(msg.Flows))
			ctx.flowLogMetrics.DNSReqs.Success += uint64(len(msg.DnsReqs))
			ctx.flowLogMetrics.Unlock()
		} else {
			log.Error(err)
			ctx.flowLogMetrics.Lock()
			ctx.flowLogMetrics.Messages.FailedAttempts++
			ctx.flowLogMetrics.Flows.FailedAttempts += uint64(len(msg.Flows))
			ctx.flowLogMetrics.DNSReqs.FailedAttempts += uint64(len(msg.DnsReqs))
			ctx.flowLogMetrics.Unlock()
			if (100*len(flowlogQueue))/cap(flowlogQueue) > 90 {
				// More than 90% of the queue is used, start dropping instead of retrying.
				log.Warnf("flowlogTask: dropped flow message: %+v", msg.Scope)
				ctx.flowLogMetrics.Lock()
				ctx.flowLogMetrics.Messages.Drops++
				ctx.flowLogMetrics.Flows.Drops += uint64(len(msg.Flows))
				ctx.flowLogMetrics.DNSReqs.Drops += uint64(len(msg.DnsReqs))
				ctx.flowLogMetrics.Unlock()
			} else {
				retry = true
			}
		}
		if retry {
			// Keep retrying with a truncated exponential backoff.
			retryMsg = msg
			exp := retryAttempt
			const maxExp = 7 // 128 (2^7) seconds is the maximum delay
			if exp > maxExp {
				exp = maxExp
			}
			retryTimer = time.NewTimer((1 << exp) * time.Second)
			retryAttempt++
		} else {
			retryMsg = nil
			retryAttempt = 0
			if retryTimer != nil {
				retryTimer.Stop()
				retryTimer = nil
			}
		}
		log.Function("flowlogTask is done with the message")
		ctx.ps.CheckMaxTimeTopic(wdName, "PublishFlowMessage", start,
			warningTime, errorTime)
	}

	for {
		if retryMsg != nil {
			select {
			case <-retryTimer.C:
				publish(retryMsg)
			case <-stillRunning.C:
			}
		} else {
			select {
			case flowMsg := <-flowlogQueue:
				publish(flowMsg)
			case <-stillRunning.C:
			}
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func publishFlowMessage(flowMsg *flowlog.FlowMessage, iteration int) error {
	data, err := proto.Marshal(flowMsg)
	if err != nil {
		err = fmt.Errorf("publishFlowMessage: proto marshaling error %w", err)
		return err
	}
	buf := bytes.NewBuffer(data)

	flowlogURL := controllerconn.URLPathString(
		serverNameAndPort, ctrlClient.UsingV2API(), devUUID, "flowlog")
	ctxWork, cancel := ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	rv, err := ctrlClient.SendOnAllIntf(ctxWork, flowlogURL, buf,
		controllerconn.RequestOptions{
			WithNetTracing: false,
			BailOnHTTPErr:  false,
			Iteration:      iteration,
		})
	if err != nil {
		err = fmt.Errorf("publishFlowMessage: SendOnAllIntf failed with %d: %s",
			rv.Status, err)
		return err
	}
	saveSentFlowProtoMessage(data)
	return nil
}

func saveSentFlowProtoMessage(contents []byte) {
	saveConfig("lastflowlog", contents)
}

func handleAppContainerMetricsCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppContainerMetricsImpl(ctxArg, key, statusArg)
}

func handleAppContainerMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppContainerMetricsImpl(ctxArg, key, statusArg)
}

func handleAppContainerMetricsImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	acMetrics := statusArg.(types.AppContainerMetrics)
	log.Tracef("handleAppContainerMetricsImpl(%s), num containers %d",
		key, len(acMetrics.StatsList))
}
