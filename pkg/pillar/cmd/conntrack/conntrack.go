// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntrack

import (
	"flag"
	"fmt"
	"net"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	filters "github.com/lf-edge/eve/pkg/pillar/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const agentName = "conntrack"

var logger *logrus.Logger
var log *base.LogObject

type connTrackAgentState struct {
	agentbase.AgentBase
	// cli options
	delFlow   *bool
	delSrcIP  *string
	delProto  *int
	delFamily *string
	delPort   *int
	delMark   *int
	markMask  *int
}

// AddAgentSpecificCLIFlags adds CLI options
func (state *connTrackAgentState) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	state.delFlow = flagSet.Bool("D", false, "Delete flow")
	state.delSrcIP = flagSet.String("s", "", "Delete flow with source IP")
	state.delProto = flagSet.Int("p", 0, "Delete flow with protocol ID")
	state.delFamily = flagSet.String("f", "", "Delete flow with ipv6")
	state.delPort = flagSet.Int("P", 0, "Delete flow with port number")
	state.delMark = flagSet.Int("m", 0, "Delete flow with Mark number")
	state.markMask = flagSet.Int("mask", 0, "Delete flow with Mark mask")
}

func Run(_ *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	ctx := connTrackAgentState{}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	// conntrack [-D <-s address> [-p proto][-P port][-m Mark]]
	if *ctx.delFlow {
		if *ctx.delSrcIP != "" {
			var proto uint8
			var src net.IP
			var port uint16
			var family netlink.InetFamily
			var mark, mask uint32

			family = syscall.AF_INET
			src = net.ParseIP(*ctx.delSrcIP)
			if *ctx.delProto != 0 {
				proto = uint8(*ctx.delProto)
			}
			if *ctx.delFamily == "ipv6" {
				family = syscall.AF_INET6
			}
			if *ctx.delPort != 0 {
				port = uint16(*ctx.delPort)
			}
			if *ctx.delMark != 0 {
				mark = uint32(*ctx.delMark)
			}
			mask = 0xFFFFFFFF
			if *ctx.markMask != 0 {
				mask = uint32(*ctx.markMask)
			}

			number, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, family,
				filters.SrcIPFilter{
					Log:       log,
					SrcIP:     src,
					Proto:     proto,
					SrcPort:   port,
					Mark:      mark,
					MarkMask:  mask,
					DebugShow: true})
			if err != nil {
				logger.Println("ConntrackDeleteFilter error:", err)
			} else {
				fmt.Printf("ConntrackDeleteFilter: deleted %d flow\n", number)
			}
			return 0
		}
		fmt.Println("Usage: Conntrack -D <-s IP-Address> [-p Protocol][-P port][-m Mark][-mask MarkMask][-f ipv6]")
		return 1
	}
	// XXX args := flag.Args()
	res, err := netlink.ConntrackTableList(netlink.ConntrackTable, syscall.AF_INET)
	if err != nil {
		logger.Println("ContrackTableList", err)
	} else {
		for i, entry := range res {
			fmt.Printf("[%d]: %s\n", i, entry.String())
			fmt.Printf("[%d]: forward packets %d bytes %d\n", i,
				entry.Forward.Packets, entry.Forward.Bytes)
			fmt.Printf("[%d]: reverse packets %d bytes %d\n", i,
				entry.Reverse.Packets, entry.Reverse.Bytes)
		}
	}
	res, err = netlink.ConntrackTableList(netlink.ConntrackTable, syscall.AF_INET6)
	if err != nil {
		logger.Println("ContrackTableList", err)
	} else {
		for i, entry := range res {
			fmt.Printf("[%d]: %s\n", i, entry.String())
			fmt.Printf("[%d]: forward packets %d bytes %d\n", i,
				entry.Forward.Packets, entry.Forward.Bytes)
			fmt.Printf("[%d]: reverse packets %d bytes %d\n", i,
				entry.Reverse.Packets, entry.Reverse.Bytes)
		}
	}
	return 0
}
