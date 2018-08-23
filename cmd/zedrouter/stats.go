// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// ipsec tunnel info/stats routines

package zedrouter

import (
	"github.com/zededa/go-provision/types"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type ipSecCmdOut struct {
	version            string
	upTime             time.Time
	ipAddrs            string
	activeTunCount     uint32
	connectingTunCount uint32
}

type swanCtlCmdOut struct {
	tunnelCount uint32
	tunnelList  []tunnelStatus
}

type tunnelStatus struct {
	id         string
	name       string
	reqId      string
	state      types.VpnState
	ikes       string
	Esp        string
	estTime    string
	reauthTime string
	instTime   string
	expTime    string
	rekeyTime  string
	localLink  types.VpnLinkStatus
	remoteLink types.VpnLinkStatus
	startLine  int
	endLine    int
}

func ipSecStatusCmdGet(vpnStatus *types.ServiceVpnStatus) {
	cmd := exec.Command("ipsec", "statusall")
	bytes, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s statusall\n", err.Error(), "ipsec")
		return
	}
	ipSecCmdOut := ipSecCmdParse(string(bytes))
	vpnStatus.IpAddrs = ipSecCmdOut.ipAddrs
	vpnStatus.UpTime = ipSecCmdOut.upTime
	vpnStatus.Version = ipSecCmdOut.version
	vpnStatus.ActiveTunCount = ipSecCmdOut.activeTunCount
	vpnStatus.ConnectingTunCount = ipSecCmdOut.connectingTunCount
	return
}

func swanCtlCmdGet(vpnStatus *types.ServiceVpnStatus) {

	if vpnStatus.ActiveTunCount == 0 {
		return
	}
	cmd := exec.Command("swanctl", "-l")
	bytes, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s -l\n", err.Error(), "swanctl")
		return
	}
	swanCtlCmdOut := swanCtlCmdParse(string(bytes))
	if swanCtlCmdOut.tunnelCount != vpnStatus.ActiveTunCount {
		log.Printf("Tunnel count mismatch (%d, %d)\n",
			swanCtlCmdOut.tunnelCount, vpnStatus.ActiveTunCount)
		return
	}

	vpnStatus.ConnStatus = make([]types.VpnConnStatus, vpnStatus.ActiveTunCount)
	for idx, _ := range vpnStatus.ConnStatus {
		connStatus := types.VpnConnStatus{}
		connStatus.Id = swanCtlCmdOut.tunnelList[idx].id
		connStatus.Name = swanCtlCmdOut.tunnelList[idx].name
		connStatus.Ikes = swanCtlCmdOut.tunnelList[idx].ikes
		connStatus.ReqId = swanCtlCmdOut.tunnelList[idx].reqId
		connStatus.State = swanCtlCmdOut.tunnelList[idx].state
		connStatus.LocalLink = swanCtlCmdOut.tunnelList[idx].localLink
		connStatus.LocalLink.Direction = false
		connStatus.RemoteLink = swanCtlCmdOut.tunnelList[idx].remoteLink
		vpnStatus.ConnStatus[idx] = connStatus
	}
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
				upTime, err := time.Parse(time.RFC3339, upTimeStr[len-1])
				if err != nil {
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
					countStr := outArr[fidx-1]
					if count, err := strconv.ParseUint(countStr, 10, 32); err != nil {
						ipSecCmdOut.activeTunCount = uint32(count)
					}
				}
				if field == "connecting)" {
					countStr := outArr[fidx-1]
					if count, err := strconv.ParseUint(countStr, 10, 32); err != nil {
						ipSecCmdOut.connectingTunCount = uint32(count)
					}
				}
			}
		}
	}
	return ipSecCmdOut
}

func swanCtlCmdParse(outStr string) swanCtlCmdOut {
	swanCtlCmdOut := swanCtlCmdOut{}
	if len(outStr) == 0 {
		return swanCtlCmdOut
	}
	outLines := strings.Split(outStr, "\n")

	// get active connection count
	for _, line := range outLines {
		if line[0] != ' ' &&
			line[0] != '\t' && line[0] != '\n' {
			swanCtlCmdOut.tunnelCount++
		}
	}
	if swanCtlCmdOut.tunnelCount == 0 {
		return swanCtlCmdOut
	}
	swanCtlCmdOut.tunnelList = make([]tunnelStatus, swanCtlCmdOut.tunnelCount)

	// fill up the tunnel details
	cidx := 0
	tunIdx := 0
	// get active connection count
	for idx, line := range outLines {
		if line[0] != ' ' && line[0] != '\t' && line[0] != '\n' {
			swanCtlCmdOut.tunnelList[tunIdx].startLine = idx
			if tunIdx != 0 {
				swanCtlCmdOut.tunnelList[tunIdx-1].endLine = cidx
			}
			if idx != 0 {
				cidx = idx - 1
			}
			tunIdx++
		}
	}
	swanCtlCmdOut.tunnelList[tunIdx].endLine = cidx

	// fill in the structure, with values
	for idx, tunnel := range swanCtlCmdOut.tunnelList {
		tunnelInfo := tunnelStatus{}

		// get tunnel name, identifier
		lidx := tunnel.startLine
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			tunnelName := strings.Split(outArr[0], ":")[0]
			tunnelId := strings.Split(outArr[1], "#")[1]
			tunnelId = strings.Split(tunnelId, ",")[0]
			tunnelInfo.name = tunnelName
			tunnelInfo.id = tunnelId
		}

		// tunnel local ip address
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			if outArr[0] == "local" {
				tunnelInfo.localLink.IpAddr = outArr[1]
			}
		}

		// tunnel remote ip address
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			if outArr[0] == "remote" {
				tunnelInfo.remoteLink.IpAddr = outArr[1]
			}
		}

		// tunnel ike
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			tunnelInfo.ikes = outArr[0]
		}

		// tunnel up time
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			for fidx, field := range outArr {
				if field == "established" {
					estTime := strings.Split(outArr[fidx+1], "s")[0]
					tunnelInfo.estTime = estTime
				}
				if field == "reauth" {
					reauthTime := strings.Split(outArr[fidx+2], "s")[0]
					tunnelInfo.reauthTime = reauthTime
				}
			}
		}

		// get tunnel state, reqId
		lidx++
		tunnelInfo.state = types.VPN_ESTABLISHED
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			if strings.Contains(line, tunnelInfo.name) &&
				strings.Contains(line, "INSTALLED") {
				tunnelInfo.state = types.VPN_INSTALLED
				outArr := strings.Fields(line)
				for fidx, field := range outArr {
					if field == "reqid" {
						reqId := strings.Split(outArr[fidx+1], ",")[0]
						tunnelInfo.reqId = reqId
					}
				}
			}
		}

		// installed time and other timing details
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			for fidx, field := range outArr {
				switch field {
				case "installed":
					instTime := strings.Split(outArr[fidx+1], "s")[0]
					tunnelInfo.instTime = instTime
				case "rekeying":
					rekeyTime := strings.Split(outArr[fidx+2], "s")[0]
					tunnelInfo.rekeyTime = rekeyTime
				case "expires":
					expTime := strings.Split(outArr[fidx+2], "s")[0]
					tunnelInfo.expTime = expTime
				}
			}
		}

		// local ESP-SPI, packet/byte count
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			if outArr[0] == "in" {
				tunnelInfo.localLink.SpiId = outArr[1]
				countStr := outArr[1]
				if count, err := strconv.ParseUint(countStr, 10, 64); err != nil {
					tunnelInfo.localLink.BytesCount = count
				}
				countStr = outArr[3]
				if count, err := strconv.ParseUint(countStr, 10, 64); err != nil {
					tunnelInfo.localLink.PktsCount = count
				}
			}
		}

		// remote ESP-SPI, packet/byte count
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			if outArr[0] == "out" {
				tunnelInfo.remoteLink.SpiId = outArr[1]
				countStr := outArr[1]
				if count, err := strconv.ParseUint(countStr, 10, 64); err != nil {
					tunnelInfo.remoteLink.BytesCount = count
				}
				countStr = outArr[3]
				if count, err := strconv.ParseUint(countStr, 10, 64); err != nil {
					tunnelInfo.remoteLink.PktsCount = count
				}
			}
		}

		// local subnet
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			if outArr[0] == "local" {
				tunnelInfo.localLink.SubNet = outArr[1]
			}
		}

		// remote subnet
		lidx++
		if lidx <= tunnelInfo.endLine {
			line := outLines[lidx]
			outArr := strings.Fields(line)
			if outArr[0] == "remote" {
				tunnelInfo.remoteLink.SubNet = outArr[1]
			}
		}

		// set the direction flags
		tunnelInfo.localLink.Direction = false
		tunnelInfo.remoteLink.Direction = true
		swanCtlCmdOut.tunnelList[idx] = tunnelInfo
	}
	return swanCtlCmdOut
}
