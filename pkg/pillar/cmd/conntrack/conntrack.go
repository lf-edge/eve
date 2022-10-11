// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntrack

import (
	"flag"
	"fmt"
	"net"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	filters "github.com/lf-edge/eve/pkg/pillar/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const agentName = "conntrack"

var logger *logrus.Logger
var log *base.LogObject

func Run(_ *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg
	flagSet := flag.NewFlagSet(agentName, flag.ExitOnError)
	delFlow := flagSet.Bool("D", false, "Delete flow")
	delSrcIP := flagSet.String("s", "", "Delete flow with source IP")
	delProto := flagSet.Int("p", 0, "Delete flow with protocol ID")
	delFamily := flagSet.String("f", "", "Delete flow with ipv6")
	delPort := flagSet.Int("P", 0, "Delete flow with port number")
	delMark := flagSet.Int("m", 0, "Delete flow with Mark number")
	markMask := flagSet.Int("mask", 0, "Delete flow with Mark mask")
	if err := flagSet.Parse(arguments); err != nil {
		log.Fatal(err)
	}

	// conntrack [-D <-s address> [-p proto][-P port][-m Mark]]
	if *delFlow {
		if *delSrcIP != "" {
			var proto uint8
			var src net.IP
			var port uint16
			var family netlink.InetFamily
			var mark, mask uint32

			family = syscall.AF_INET
			src = net.ParseIP(*delSrcIP)
			if *delProto != 0 {
				proto = uint8(*delProto)
			}
			if *delFamily == "ipv6" {
				family = syscall.AF_INET6
			}
			if *delPort != 0 {
				port = uint16(*delPort)
			}
			if *delMark != 0 {
				mark = uint32(*delMark)
			}
			mask = 0xFFFFFFFF
			if *markMask != 0 {
				mask = uint32(*markMask)
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
