// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// ipsec tunnel info/stats routines

package zedrouter

import (
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type ipSecCmdOut struct {
	version            string
	activeTunCount     uint32
	connectingTunCount uint32
	upTime             time.Time
	ipAddrs            string
}

type readBlock struct {
	startLine   int
	endLine     int
	childCount  uint32
	childBlocks []*readBlock
}

func ipSecStatusCmdGet(vpnStatus *types.ServiceVpnStatus) error {
	cmd := exec.Command("ipsec", "statusall")
	bytes, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s statusall\n", err.Error(), "ipsec")
		return err
	}
	ipSecCmdOut := ipSecCmdParse(string(bytes))
	vpnStatus.IpAddrs = ipSecCmdOut.ipAddrs
	vpnStatus.UpTime = ipSecCmdOut.upTime
	vpnStatus.Version = ipSecCmdOut.version
	vpnStatus.ActiveTunCount = ipSecCmdOut.activeTunCount
	vpnStatus.ConnectingTunCount = ipSecCmdOut.connectingTunCount
	return nil
}

func swanCtlCmdGet(vpnStatus *types.ServiceVpnStatus) error {
	cmd := exec.Command("swanctl", "-l")
	bytes, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s -l\n", err.Error(), "swanctl")
		return err
	}
	tunCount := swanCtlCmdParse(vpnStatus, string(bytes))
	if vpnStatus.ActiveTunCount != tunCount {
		log.Printf("Tunnel count mismatch (%d, %d)\n",
			vpnStatus.ActiveTunCount, tunCount)
		return errors.New("active tunnel count mismatch")
	}
	return nil
}

func ipSecCmdParse(outStr string) ipSecCmdOut {
	ipSecCmdOut := ipSecCmdOut{}
	if len(outStr) == 0 {
		return ipSecCmdOut
	}

	saStr := "Security Associations"
	connStr := "Connections:"
	upTimeStr := "uptime:"
	sinceStr := "since"
	statusStr := "Status of IKE charon daemon"
	listeningStr := "Listening IP addresses:"

	outLines := strings.Split(outStr, "\n")
	// get Listening IpAddresses
	for idx, line := range outLines {
		if len(line) == 0 {
			continue
		}
		// check for version
		if strings.Contains(line, statusStr) {
			versionStr := strings.Split(line, "(")[1]
			versionStr = strings.Split(versionStr, ")")[0]
			ipSecCmdOut.version = versionStr
		}
		// check for "uptime:"
		if strings.Contains(line, upTimeStr) {
			upTimeStr := strings.Split(line, sinceStr)
			len := len(upTimeStr)
			if len > 1 {
				layout := "Jan 2 15:04:05 2006"
				timeStr := strings.TrimSpace(upTimeStr[len-1])
				if upTime, err := time.Parse(layout, timeStr); err == nil {
					ipSecCmdOut.upTime = upTime
				}
			}
		}

		// contains "Listening IP Addresses"
		if strings.Contains(line, listeningStr) {
			addrIdx := idx + 1
			// until Connections:
			for addrIdx < len(outLines) &&
				!strings.Contains(outLines[addrIdx], connStr) {
				outArr := strings.Fields(outLines[addrIdx])
				for _, field := range outArr {
					if ip := net.ParseIP(field); ip != nil {
						if ipSecCmdOut.ipAddrs == "" {
							ipSecCmdOut.ipAddrs = field
						} else {
							ipSecCmdOut.ipAddrs = ipSecCmdOut.ipAddrs + " " + field
						}
					}
				}
				addrIdx++
			}
		}
		// check for connecting and up tunnels
		if strings.Contains(line, saStr) {
			outArr := strings.Fields(line)
			for fidx, field := range outArr {
				if field == "up," {
					countStr := strings.Split(outArr[fidx-1], "(")[1]
					if count, err := strconv.ParseUint(countStr, 10, 32); err == nil {
						ipSecCmdOut.activeTunCount = uint32(count)
					}
				}
				if field == "connecting):" {
					countStr := outArr[fidx-1]
					if count, err := strconv.ParseUint(countStr, 10, 32); err == nil {
						ipSecCmdOut.connectingTunCount = uint32(count)
					}
				}
			}
		}
	}
	if debug {
		log.Printf("ipSecCmdParse:%v\n", ipSecCmdOut)
	}
	return ipSecCmdOut
}

func swanCtlCmdParse(vpnStatus *types.ServiceVpnStatus, outStr string) uint32 {
	if len(outStr) == 0 {
		return 0
	}
	cmdOut := new(readBlock)
	outLines := strings.Split(outStr, "\n")

	// make the block partition for the command output
	swanCtlCmdGetBlockInfo(cmdOut, outLines)
	if cmdOut.childCount == 0 {
		return cmdOut.childCount
	}

	vpnStatus.ActiveVpnConns = make([]*types.VpnConnStatus, cmdOut.childCount)
	// fill in the structure, with values
	for idx, cblock := range cmdOut.childBlocks {
		connInfo := populateConnInfo(cblock, outLines)
		vpnStatus.ActiveVpnConns[idx] = connInfo
	}
	if debug {
		if bytes, err := json.Marshal(vpnStatus); err != nil {
			log.Printf("swanCtlCmdParse(): %s\n", bytes)
		}
	}
	return cmdOut.childCount
}

func swanCtlCmdGetBlockInfo(cmdOut *readBlock, outLines []string) {
	cmdOut.startLine = 0
	cmdOut.endLine = len(outLines)
	// get active connection count
	for _, line := range outLines {
		if len(line) == 0 {
			cmdOut.endLine--
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			cmdOut.childCount++
		}
	}
	if cmdOut.childCount == 0 {
		return
	}

	cmdOut.childBlocks = make([]*readBlock, cmdOut.childCount)
	bidx := 0
	// get active connection count
	// and figureout start line/end line for connection blocks
	for idx, line := range outLines {
		if len(line) != 0 &&
			line[0] != ' ' && line[0] != '\t' {
			childBlock := new(readBlock)
			childBlock.startLine = idx
			cmdOut.childBlocks[bidx] = childBlock
			if bidx != 0 {
				cmdOut.childBlocks[bidx-1].endLine = idx - 1
			}
			bidx++
		}
	}
	if bidx != 0 {
		cmdOut.childBlocks[bidx-1].endLine = cmdOut.endLine
	}

	// get start line/end line for the link blocks
	for _, cblock := range cmdOut.childBlocks {
		for idx, line := range outLines {
			if idx < cblock.startLine ||
				idx >= cblock.endLine {
				continue
			}
			if len(line) != 0 &&
				line[2] != ' ' && line[2] != '\t' {
				line0 := outLines[idx+1]
				if len(line0) != 0 &&
					(line0[2] == ' ' || line0[2] == '\t') {
					cblock.childCount++
				}
			}
		}
		if cblock.childCount == 0 {
			continue
		}
		cblock.childBlocks = make([]*readBlock, cblock.childCount)
		lidx := 0
		for idx, line := range outLines {
			if idx < cblock.startLine ||
				idx >= cblock.endLine {
				continue
			}
			if len(line) != 0 &&
				line[2] != ' ' && line[2] != '\t' {
				line0 := outLines[idx+1]
				if len(line0) != 0 &&
					(line0[2] == ' ' || line0[2] == '\t') {
					childBlock := new(readBlock)
					childBlock.startLine = idx
					cblock.childBlocks[lidx] = childBlock
					if lidx != 0 {
						cblock.childBlocks[lidx-1].endLine = idx - 1
					}
					lidx++
				}
			}
		}
		if lidx != 0 {
			cblock.childBlocks[lidx-1].endLine = cblock.endLine
		}
	}
	if debug {
		swanCtlCmdOutPrint(cmdOut, 0)
	}
}

func swanCtlCmdOutPrint(cb *readBlock, depth int) {
	if cb == nil {
		return
	}
	log.Printf("%d-%d:%d,%d\n", depth, cb.childCount, cb.startLine, cb.endLine)
	for _, childBlock := range cb.childBlocks {
		swanCtlCmdOutPrint(childBlock, depth+1)
	}
}

func populateConnInfo(cblock *readBlock, outLines []string) *types.VpnConnStatus {
	connInfo := new(types.VpnConnStatus)
	// get tunnel name, identifier, state, version
	lidx := cblock.startLine
	line := outLines[lidx]
	if lidx <= cblock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		tunnelName := strings.Split(outArr[0], ":")[0]
		tunnelId := strings.Split(outArr[1], "#")[1]
		tunnelId = strings.Split(tunnelId, ",")[0]
		connInfo.Name = tunnelName
		connInfo.Id = tunnelId
		if strings.Contains(line, "ESTABLISHED") {
			connInfo.State = types.VPN_ESTABLISHED
		}
		if strings.Contains(line, "IKEv1") {
			connInfo.Version = "IKEv1"
		}
		if strings.Contains(line, "IKEv2") {
			connInfo.Version = "IKEv2"
		}
	}

	// tunnel local ip address
	lidx++
	line = outLines[lidx]
	if lidx <= cblock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		if outArr[0] == "local" {
			idStr := strings.Split(outArr[1], "'")[1]
			connInfo.LInfo.Id = idStr
			ipAddrStr := strings.Split(outArr[3], "[")[0]
			connInfo.LInfo.IpAddr = ipAddrStr
			portStr := strings.Split(outArr[3], "[")[1]
			portStr = strings.Split(portStr, "]")[0]
			if udpPort, err := strconv.ParseUint(portStr, 10, 32); err == nil {
				connInfo.LInfo.Port = uint32(udpPort)
			}
		}
	}

	// tunnel remote ip address
	lidx++
	line = outLines[lidx]
	if lidx <= cblock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		if outArr[0] == "remote" {
			idStr := strings.Split(outArr[1], "'")[1]
			connInfo.RInfo.Id = idStr
			ipAddrStr := strings.Split(outArr[3], "[")[0]
			connInfo.RInfo.IpAddr = ipAddrStr
			portStr := strings.Split(outArr[3], "[")[1]
			portStr = strings.Split(portStr, "]")[0]
			if udpPort, err := strconv.ParseUint(portStr, 10, 32); err == nil {
				connInfo.RInfo.Port = uint32(udpPort)
			}
		}
	}

	// tunnel ike
	lidx++
	line = outLines[lidx]
	if lidx <= cblock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		connInfo.Ikes = outArr[0]
	}

	// tunnel up time
	lidx++
	line = outLines[lidx]
	if lidx <= cblock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		for fidx, field := range outArr {
			if field == "established" {
				timeStr := strings.Split(outArr[fidx+1], "s")[0]
				if estTime, err := strconv.ParseUint(timeStr, 10, 64); err == nil {
					connInfo.EstTime = estTime
				}
			}
			if field == "reauth" {
				timeStr := strings.Split(outArr[fidx+2], "s")[0]
				if reauthTime, err := strconv.ParseUint(timeStr, 10, 64); err == nil {
					connInfo.ReauthTime = reauthTime
				}
			}
		}
	}

	if cblock.childCount == 0 {
		return connInfo
	}
	connInfo.Links = make([]*types.VpnLinkStatus, cblock.childCount)
	idx := 0
	for _, linkBlock := range cblock.childBlocks {
		if linkBlock == nil {
			continue
		}
		linkInfo := populateLinkInfo(linkBlock, outLines)
		connInfo.Links[idx] = linkInfo
		idx++
	}
	return connInfo
}

func populateLinkInfo(linkBlock *readBlock, outLines []string) *types.VpnLinkStatus {
	lidx := linkBlock.startLine
	line := outLines[lidx]
	linkInfo := new(types.VpnLinkStatus)
	// get tunnel state, reqId
	if lidx <= linkBlock.endLine && len(outLines[lidx]) != 0 {
		if strings.Contains(line, "INSTALLED") {
			linkInfo.State = types.VPN_INSTALLED
		}
		if strings.Contains(line, "REKEYED") {
			linkInfo.State = types.VPN_REKEYED
		}
		outArr := strings.Fields(line)
		for fidx, field := range outArr {
			if field == "reqid" {
				reqId := strings.Split(outArr[fidx+1], ",")[0]
				linkInfo.ReqId = reqId
				id := strings.Split(outArr[fidx-1], ",")[0]
				linkInfo.Id = strings.Split(id, "#")[1]
			}
			if strings.Contains(field, "ESP:") {
				linkInfo.EspInfo = strings.Split(field, "ESP:")[1]
			}
		}
	}

	// installed time and other timing details
	lidx++
	line = outLines[lidx]
	if lidx <= linkBlock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		for fidx, field := range outArr {
			switch field {
			case "installed":
				timeStr := strings.Split(outArr[fidx+1], "s")[0]
				if instTime, err := strconv.ParseUint(timeStr, 10, 64); err == nil {
					linkInfo.InstTime = instTime
				}
			case "rekeying":
				timeStr := strings.Split(outArr[fidx+2], "s")[0]
				if rekeyTime, err := strconv.ParseUint(timeStr, 10, 64); err == nil {
					linkInfo.RekeyTime = rekeyTime
				}
			case "expires":
				timeStr := strings.Split(outArr[fidx+2], "s")[0]
				if expTime, err := strconv.ParseUint(timeStr, 10, 64); err == nil {
					linkInfo.ExpTime = expTime
				}
			}
		}
	}

	// local ESP-SPI, packet/byte count
	lidx++
	line = outLines[lidx]
	if lidx <= linkBlock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		if outArr[0] == "in" {
			spiId := strings.Split(outArr[1], ",")[0]
			linkInfo.LInfo.SpiId = spiId
			countStr := outArr[2]
			if count, err := strconv.ParseUint(countStr, 10, 64); err == nil {
				linkInfo.LInfo.BytesCount = count
			}
			countStr = outArr[4]
			if count, err := strconv.ParseUint(countStr, 10, 64); err == nil {
				linkInfo.LInfo.PktsCount = count
			}
		}
	}

	// remote ESP-SPI, packet/byte count
	lidx++
	line = outLines[lidx]
	if lidx <= linkBlock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		if outArr[0] == "out" {
			spiId := strings.Split(outArr[1], ",")[0]
			linkInfo.RInfo.SpiId = spiId
			countStr := outArr[2]
			if count, err := strconv.ParseUint(countStr, 10, 64); err == nil {
				linkInfo.RInfo.BytesCount = count
			}
			countStr = outArr[4]
			if count, err := strconv.ParseUint(countStr, 10, 64); err == nil {
				linkInfo.RInfo.PktsCount = count
			}
		}
	}

	// local subnet
	lidx++
	line = outLines[lidx]
	if lidx <= linkBlock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		if outArr[0] == "local" {
			linkInfo.LInfo.SubNet = outArr[1]
		}
	}

	// remote subnet
	lidx++
	line = outLines[lidx]
	if lidx <= linkBlock.endLine && len(outLines[lidx]) != 0 {
		outArr := strings.Fields(line)
		if outArr[0] == "remote" {
			linkInfo.RInfo.SubNet = outArr[1]
		}
	}

	// set the direction flags
	linkInfo.LInfo.Direction = false
	linkInfo.RInfo.Direction = true
	return linkInfo
}
