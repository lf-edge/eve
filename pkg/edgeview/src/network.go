// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/grandcat/zeroconf"
	"github.com/lf-edge/eve/pkg/pillar/types"
	snet "github.com/shirou/gopsutil/net"
	"github.com/tatsushid/go-fastping"
	"github.com/vishvananda/netlink"
)

type urlStats struct {
	recvBytes  int64
	sentBytes  int64
	sentNumber int64
}

type appIPvnc struct {
	ipAddr    string
	appName   string
	vncEnable bool
	vncPort   int
}

type intfIP struct {
	intfName    string
	ipAddr      string
	hwAddr      string
	iFlag       net.Flags
	arpComplete bool
	sentBytes   int64
	recvBytes   int64
}

func runNetwork(netw string) {
	opts, err := checkOpts(netw, netopts)
	if err != nil {
		fmt.Println("runNetwork:", err)
	}

	for _, opt := range opts {
		printTitle("\n === Network: <"+opt+"> ===\n\n", colorPURPLE, false)
		var substring string
		if strings.Contains(opt, "/") {
			items := strings.SplitN(opt, "/", 2)
			if len(items) != 2 {
				continue
			}
			opt = items[0]
			substring = items[1]
		}
		if !rePattern.MatchString(opt) || !rePattern.MatchString(substring) {
			fmt.Println("network options invalid")
			continue
		}

		var server string
		var intfStat []intfIP
		if opt == "if" || opt == "ping" || opt == "trace" || opt == "tcpdump" {
			intfStat = getAllIntfs()
		}
		if opt == "ping" || opt == "trace" {
			retbytes, err := os.ReadFile("/config/server")
			if err != nil {
				continue
			}
			server = string(retbytes)
			server = strings.TrimSuffix(server, "\n")
		}
		if opt == "url" {
			getURL()
		} else if opt == "route" {
			runRoute()
		} else if opt == "socket" {
			showSockets()
		} else if opt == "nslookup" {
			getDNS(substring)
		} else if opt == "arp" {
			getARP(substring)
		} else if opt == "acl" {
			runACLs(false, substring)
			runACLs(true, substring)
		} else if opt == "connectivity" {
			printColor(" - Connectivity: ", colorBLUE)
			getConnectivity()
		} else if opt == "if" {
			showIntf(substring, intfStat)
		} else if opt == "app" {
			showAppDetail(substring)
		} else if opt == "trace" {
			runTrace(substring, server)
		} else if opt == "ping" {
			runPing(intfStat, server, substring)
		} else if opt == "tcpdump" {
			runTCPDump(intfStat, substring)
		} else if opt == "wireless" {
			runWireless()
		} else if opt == "speed" {
			runSpeedTest(substring)
		} else if opt == "flow" {
			getFlow(substring)
		} else if opt == "mdns" {
			runmDNS(substring)
		} else if opt == "tcp" { // tcp and proxy are special
			setAndStartProxyTCP(substring)
		} else if opt == "showcerts" {
			getPeerCerts(substring)
		} else if opt == "addhost" {
			addEctHostEntry(substring)
		} else {
			fmt.Printf("\n not supported yet\n")
		}
		if isTechSupport {
			closePipe(true)
		}
	}
}

// doAppNet
func doAppNet(status, appstr string, isSummary bool) string {
	var appStatus types.AppNetworkStatus
	_ = json.Unmarshal([]byte(status), &appStatus)
	niType := map[types.NetworkInstanceType]string{
		types.NetworkInstanceTypeSwitch:      "switch",
		types.NetworkInstanceTypeLocal:       "local",
		types.NetworkInstanceTypeCloud:       "cloud",
		types.NetworkInstanceTypeHoneyPot:    "honeypot",
		types.NetworkInstanceTypeTransparent: "transparent",
	}

	name := appStatus.DisplayName
	nameLower := strings.ToLower(name)
	appStrLower := strings.ToLower(appstr)
	if appstr != "" && !strings.Contains(nameLower, appStrLower) {
		return ""
	}
	printColor("\n - app: "+name+", appNum: "+strconv.Itoa(appStatus.AppNum)+"\n", colorBLUE)
	fmt.Printf("   app uuid %s\n", appStatus.UUIDandVersion.UUID.String())

	if appStatus.GetStatsIPAddr != nil {
		fmt.Printf("\n - App Container Stats Collect IP %v\n", appStatus.GetStatsIPAddr)
	}

	for _, item := range appStatus.UnderlayNetworkList {
		niUUID := item.Network.String()
		retbytes, err := os.ReadFile("/run/zedrouter/NetworkInstanceStatus/" + niUUID + ".json")
		if err != nil {
			continue
		}
		var niStatus types.NetworkInstanceStatus
		_ = json.Unmarshal(retbytes, &niStatus)
		var ifname string
		var ipaddr net.IP
		for _, p := range item.ACLDependList {
			if ifname != p.Ifname || !ipaddr.Equal(p.IPAddr) {
				fmt.Printf("\n  - uplink port: %s, %v\n", p.Ifname, p.IPAddr)
				ifname = p.Ifname
				ipaddr = p.IPAddr
			}
		}
		fmt.Printf("\n == bridge: %s, %s, %v, %s\n", item.Bridge, item.Vif, item.AllocatedIPv4Addr, item.Mac)

		if isSummary {
			continue
		}

		ipStr := item.AllocatedIPv4Addr
		printColor("\n - ping app ip address: "+ipStr, colorRED)

		pingIPHost(ipStr, "")

		if niStatus.Type != types.NetworkInstanceTypeSwitch {
			printColor("\n - check open ports for "+ipStr, colorRED)
			// nmap package

			files, err := listRecursiveFiles("/run/zedrouter", ".inet")
			if err == nil {
				printColor("\n - dhcp host file:\n", colorGREEN)
				for _, l := range files {
					if !strings.HasPrefix(l, "dhcp-hosts.") {
						continue
					}
					retbytes, err := os.ReadFile(l)
					if err == nil {
						if strings.Contains(string(retbytes), item.Mac) {
							fmt.Printf("%s\n", l)
							break
						}
					}
				}
			}

			retbytes, err := os.ReadFile("/run/zedrouter/dnsmasq.leases/" + item.Bridge)
			if err == nil {
				printColor("\n - dnsmasq lease files\n", colorGREEN)
				lines := strings.Split(string(retbytes), "\n")
				for _, l := range lines {
					if strings.Contains(l, item.Mac) {
						fmt.Printf("%ss\n", l)
						items := strings.Split(l, " ")
						unixtime, _ := strconv.Atoi(items[0])
						fmt.Printf(" lease up to: %v\n", time.Unix(int64(unixtime), 0))
						break
					}
				}
			}

			runAppACLs(item.AllocatedIPv4Addr)

			getVifStats(item.Vif)

			getAppNetTable(item.AllocatedIPv4Addr, &niStatus)

			// NI
			printColor("\n - network instance: ", colorGREEN)
			fmt.Printf(" %s, type %s, logical label: %s\n\n", niStatus.DisplayName,
				niType[niStatus.Type], niStatus.Logicallabel)
			fmt.Printf(" DHCP range start: %v, end: %v\n", niStatus.DhcpRange.Start, niStatus.DhcpRange.End)
			fmt.Printf(" Current Uplink: %s\n", niStatus.CurrentUplinkIntf)
			fmt.Printf(" Probe Status:\n")
			for k, p := range niStatus.PInfo {
				fmt.Printf(" Uplink Intfname: %s\n", k)
				upStatus := "Down"
				if p.SuccessCnt != 0 || p.SuccessProbeCnt != 0 {
					upStatus = "UP"
				}
				fmt.Printf("   Probe status: %s, Cost: %d, local success: %d, remote success: %d\n",
					upStatus, p.Cost, p.SuccessCnt, p.SuccessProbeCnt)
			}
			fmt.Printf("\n")
		}
		closePipe(true)
	}

	appUUIDStr := appStatus.UUIDandVersion.UUID.String()
	retbytes, err := os.ReadFile("/run/domainmgr/DomainStatus/" + appUUIDStr + ".json")
	if err == nil {
		printColor("\n  - domain status:", colorGREEN)
		var domainS types.DomainStatus
		_ = json.Unmarshal(retbytes, &domainS)
		fmt.Printf("    state: %d, boot time: %v, tried count %d\n",
			domainS.State, domainS.BootTime, domainS.TriedCount)
		if domainS.Error != "" {
			fmt.Printf("    error: %s, error time: %v, boot failed: %v",
				domainS.Error, domainS.ErrorTime, domainS.BootFailed)
		}
	}
	return appUUIDStr
}

// getAppNetTable - in 'doAppNet'
func getAppNetTable(ipaddr string, niStatus *types.NetworkInstanceStatus) {
	gateway := niStatus.Gateway
	allIntfs := allUPIntfIPv4()
	var foundintfName string
	for _, i := range allIntfs {
		if i.ipAddr == gateway.String() {
			foundintfName = i.intfName
			break
		}
	}
	if foundintfName == "" {
		fmt.Printf("App ipaddr %s, gateway %v, can't find intf\n", ipaddr, gateway)
		return
	}

	link, err := netlink.LinkByName(foundintfName)
	if err != nil {
		fmt.Printf("App link get err %v\n", err)
		return
	}
	printColor("\n - ip route tables related to: "+ipaddr, colorGREEN)

	routes := getAllIPv4Routes(link.Attrs().Index)
	for _, r := range routes {
		fmt.Printf("%s\n", r.String())
	}
}

// getVifStats - in 'doAppNet'
func getVifStats(vifStr string) {
	retbytes, err := os.ReadFile("/run/zedrouter/NetworkMetrics/global.json")
	if err != nil {
		return
	}
	printColor("\n - bridge Tx/Rx packets on: "+vifStr, colorGREEN)
	var ntMetric types.NetworkMetrics
	_ = json.Unmarshal(retbytes, &ntMetric)
	for _, m := range ntMetric.MetricList {
		if vifStr == m.IfName {
			fmt.Printf(" TxBytes: %d, RxBytes: %d, TxPkts: %d, RxPkts: %d\n",
				m.TxBytes, m.RxBytes, m.TxPkts, m.RxPkts)
			break
		}
	}
}

// runAppACLs - in 'doAppNet'
func runAppACLs(ipStr string) {
	printColor("\n - check for ACLs on: "+ipStr+"\n", colorGREEN)
	runAppACLTblAddr("-S", "filter", ipStr)
	runAppACLTblAddr("-nvL", "filter", ipStr)
	runAppACLTblAddr("-S", "nat", ipStr)
	runAppACLTblAddr("-nvL", "nat", ipStr)
}

func runAppACLTblAddr(op, tbl, ipaddr string) {
	prog := "iptables"
	args := []string{op, "-t", tbl}
	retStr, err := runCmd(prog, args, false)
	fmt.Printf(" iptable " + tbl + "op" + " rules: \n")
	if err == nil && len(retStr) > 0 {
		lines := strings.Split(retStr, "\n")
		for _, l := range lines {
			if !strings.Contains(l, ipaddr) {
				continue
			}
			fmt.Printf("%s\n", l)
		}
	}
}

func getURL() {
	var totalStats urlStats
	getMetricsMap("/run/zedclient/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/zedagent/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/downloader/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/loguploader/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/zedrouter/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/nim/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/diag/MetricsMap/", &totalStats, true)

	printTitle(" - Total Send/Receive stats:\n", colorCYAN, false)
	fmt.Printf("  send bytes %d, recv bytes %d, send messages %d\n",
		totalStats.sentBytes, totalStats.recvBytes, totalStats.sentNumber)

	trafficStats := getTraffic()
	mgmtports := getPortCfg("", false)

	var intfRx, intfTx int
	for _, mgmt := range mgmtports {
		tx, rx := getTxRx(mgmt, trafficStats)
		intfTx += tx
		intfRx += rx
	}
	printTitle(" - Total Mgmt intf Send/Receive stats:\n", colorCYAN, false)
	fmt.Printf("  %v\n", mgmtports)
	fmt.Printf("  send bytes %d, recv bytes %d\n", intfTx, intfRx)

	ifp := allUPIntfIPv4()
	var bridgeports []string
	for _, i := range ifp {
		if strings.HasPrefix(i.intfName, "bn") {
			bridgeports = append(bridgeports, i.intfName)
		}
	}
	if len(bridgeports) > 0 {
		printTitle(" - Total Bridge intf Send/Receive stats:\n", colorCYAN, false)
	}
	intfRx = 0
	intfTx = 0
	for _, bridge := range bridgeports {
		tx, rx := getTxRx(bridge, trafficStats)
		intfTx += tx
		intfRx += rx
	}
	fmt.Printf("  %v\n", bridgeports)
	fmt.Printf("  send bytes %d, recv bytes %d\n", intfTx, intfRx)
}

func getTxRx(intf string, stats []intfIP) (int, int) {
	for _, s := range stats {
		if intf == s.intfName {
			return int(s.sentBytes), int(s.recvBytes)
		}
	}
	return 0, 0
}

// getPortCfg
func getPortCfg(opt string, isPrint bool) []string {
	var mgmtIntf []string
	if isPrint {
		fmt.Printf("\n - device port configure:\n")
	}
	outbytes, err := os.ReadFile("/run/zedagent/DevicePortConfig/zedagent.json")
	if err != nil {
		return mgmtIntf
	}
	if isPrint {
		fmt.Printf("%s\n", string(outbytes))
	}

	var portcfg types.DevicePortConfig
	_ = json.Unmarshal(outbytes, &portcfg)

	dhcpStr := map[types.DhcpType]string{1: "Static", 2: "None", 4: "Client"}
	for _, p := range portcfg.Ports {
		if opt != "" && !strings.Contains(p.IfName, opt) {
			continue
		}
		if isPrint {
			fmt.Printf(" Intf Name: %s\n", p.IfName)
			fmt.Printf("   Is Mgmt %v, Cost %d, dhcp type %v\n", p.IsMgmt, p.Cost, dhcpStr[p.Dhcp])
		}
		if p.IsMgmt {
			mgmtIntf = append(mgmtIntf, p.IfName)
		}
	}
	return mgmtIntf
}

// get all local intf ips
func getLocalIPs() []string {
	var localIPs []string
	intfStr := allUPIntfIPv4()
	for _, l := range intfStr {
		localIPs = append(localIPs, l.ipAddr)
	}
	return localIPs
}

// get all app intf ips
func getAllAppIPs() []appIPvnc {
	jfiles, err := listJSONFiles("/run/zedrouter/AppNetworkStatus")
	if err != nil {
		return nil
	}

	var allAppIPs []appIPvnc
	for _, s := range jfiles {
		retbytes1, err := os.ReadFile(s)
		if err != nil {
			continue
		}
		status := strings.TrimSuffix(string(retbytes1), "\n")
		appIPs, appUUID := getAppIPs(status)
		var oneAppIPs []appIPvnc
		if len(appIPs) > 0 {
			retbytes1, err := os.ReadFile("/run/zedagent/AppInstanceConfig/" + appUUID.String() + ".json")
			if err != nil {
				log.Errorf("getAllAppIPs: run appinstcfg %v", err)
				continue
			}
			var appInstCfg types.AppInstanceConfig
			err = json.Unmarshal(retbytes1, &appInstCfg)
			if err != nil {
				log.Errorf("getAllAppIPs: unmarshal %v", err)
				continue
			}

			enableVNC := appInstCfg.FixedResources.EnableVnc
			for _, ipaddr := range appIPs {
				ipVNC := appIPvnc{
					ipAddr:    ipaddr,
					vncEnable: enableVNC,
					appName:   appInstCfg.DisplayName,
					vncPort:   int(appInstCfg.FixedResources.VncDisplay),
				}
				oneAppIPs = append(oneAppIPs, ipVNC)
			}
		}
		allAppIPs = append(allAppIPs, oneAppIPs...)
	}
	return allAppIPs
}

func getAppIPs(status string) ([]string, uuid.UUID) {
	var appStatus types.AppNetworkStatus
	_ = json.Unmarshal([]byte(status), &appStatus)
	var appIPs []string
	appUUID := appStatus.UUIDandVersion.UUID
	for _, item := range appStatus.UnderlayNetworkList {
		appIPs = append(appIPs, item.AllocatedIPv4Addr)
	}
	return appIPs, appUUID
}

// getConnectivity
func getConnectivity() {
	jfiles, err := listJSONFiles("/run/global/DevicePortConfig")
	if err == nil {
		if len(jfiles) > 0 {
			fmt.Printf("  override.json:\n")
		}
		for _, f := range jfiles {
			retbytes1, err := os.ReadFile(f)
			if err != nil {
				fmt.Printf("error: %v\n", err)
			} else {
				fmt.Println(retbytes1)
			}
		}
	}

	retbytes, err := os.ReadFile("/persist/status/nim/DevicePortConfigList/global.json")
	if err != nil {
		return
	}

	printColor(" - port config list", colorBLUE)
	var portlist types.DevicePortConfigList
	_ = json.Unmarshal(retbytes, &portlist)
	printColor(" Current Index "+strconv.Itoa(portlist.CurrentIndex), colorGREEN)

	i := 0
	for _, pls := range portlist.PortConfigList {
		str1 := fmt.Sprintf("Key: %s, Last Succeeded: %v, Last Failed: %v\n",
			pls.Key, pls.LastSucceeded, pls.LastFailed)
		if i == portlist.CurrentIndex {
			printColor(str1, colorRED)
		} else {
			fmt.Printf("%s", str1)
		}
		for _, p := range pls.Ports {
			str2 := fmt.Sprintf("   Ifname: %s, Label: %s, Mgmt: %v\n",
				p.IfName, p.Logicallabel, p.IsMgmt)
			if i == portlist.CurrentIndex {
				printColor(str2, colorRED)
			} else {
				fmt.Printf("%s", str2)
			}
		}
		i++
	}
}

// getARP
func getARP(opt string) {
	prog := "arp"
	args := []string{"-av"}
	retStr, err := runCmd(prog, args, false)
	if err != nil {
		fmt.Printf("arp table error: %v\n", err)
		return
	}
	lines := strings.SplitAfter(retStr, "\n")
	for _, l := range lines {
		if opt != "" && !strings.Contains(l, opt) {
			continue
		}
		fmt.Printf("%s", l)
	}
}

// runACLs
func runACLs(isRunningACL bool, filter string) {
	acltables := []string{"raw", "filter", "nat", "mangle"}
	for _, tbl := range acltables {
		if filter != "" && filter != tbl {
			continue
		}
		var op string
		if isRunningACL {
			printColor(" Configured iptables: "+tbl, colorCYAN)
			op = "-S"
		} else {
			printColor(" Installed iptables: "+tbl, colorCYAN)
			op = "-nvL"
		}
		prog := "iptables"
		args := []string{op, "-t", tbl}
		_, _ = runCmd(prog, args, true)
	}
}

// runRoute
func runRoute() {
	rules, err := netlink.RuleList(syscall.AF_INET)
	if err != nil {
		fmt.Printf("runRoute: rule error %v", err)
		return
	}

	printColor(" - ip rule:", colorRED)
	tables := make(map[int]bool)
	for _, rule := range rules {
		fmt.Printf("\n%d: table %d, %s\n", rule.Priority, rule.Table, rule.String())
		// show routes under table
		if rule.Table < 1 {
			continue
		}
		if _, ok := tables[rule.Table]; !ok {
			tables[rule.Table] = true
		} else {
			continue
		}
		routes := getTableIPv4Routes(rule.Table)
		var tStr string
		switch rule.Table {
		case 253:
			tStr = "(default)"
		case 254:
			tStr = "(main)"
		case 255:
			tStr = "(local)"
		}
		tableStr := fmt.Sprintf("\n routes in table: %d%s", rule.Table, tStr)
		printColor(tableStr, colorCYAN)
		for _, r := range routes {
			fmt.Printf("   %s\n", r.String())
		}
	}

	upIntfs := allUPIntfIPv4()
	for _, i := range upIntfs {
		link, err := netlink.LinkByName(i.intfName)
		if err != nil {
			continue
		}
		routes := getAllIPv4Routes(link.Attrs().Index)

		printColor("\nshow route in interfaces: "+i.intfName, colorBLUE)
		for _, r := range routes {
			fmt.Printf("%s\n", r.String())
		}
	}
}

func getTables(rules string) []string {
	rulelines := strings.Split(rules, "\n")
	var t []string
	n := len(rulelines)
	for _, rule := range rulelines[:n-1] {
		table := strings.Split(rule, "lookup ")
		if len(table) > 0 {
			if !strings.Contains(table[1], "default") {
				t = append(t, table[1])
			}
		}
	}
	return t
}

func getMetricsMap(path string, stats *urlStats, isPrint bool) {
	retbytes, err := os.ReadFile(path + "global.json")
	if err != nil {
		return
	}
	pathname := ""
	paths := strings.Split(path, "/")
	if len(paths) < 3 {
		fmt.Printf("path len %d for MetrticsMap is invalid: %v\n", len(paths), paths)
		return
	}
	pathname = paths[2] + " stats"

	printColor(" - "+pathname, colorCYAN)
	var mmap types.MetricsMap
	_ = json.Unmarshal(retbytes, &mmap)
	for k, m := range mmap {
		fmt.Printf(" interface: %s\n", k)
		fmt.Printf(" Success: %d  Last Success: %v\n", m.SuccessCount, m.LastSuccess)
		if m.FailureCount > 0 {
			fmt.Printf(" Failure: %d  Last Failure: %v\n", m.FailureCount, m.LastFailure)
		}
		urlm := m.URLCounters
		for k1, m1 := range urlm {
			fmt.Printf("   %s\n", k1)
			fmt.Printf("     Recv (KBytes): %d, Sent %d, SentMsg: %d, TLS resume: %d, Total Time(sec): %d\n\n",
				m1.RecvByteCount/1000, m1.SentByteCount, m1.SentMsgCount, m1.SessionResume, m1.TotalTimeSpent/1000)
			if stats != nil {
				stats.recvBytes += m1.RecvByteCount
				stats.sentBytes += m1.SentByteCount
				stats.sentNumber += m1.SentMsgCount
			}
		}
	}
}

func getDNS(domain string) {
	if domain == "" {
		domain = "zedcloud.zededa.net"
	}
	printColor(" - net.LookupIP: "+domain, colorCYAN)
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf("could not get IPs: %v\n", err)
		return
	}
	for _, ip := range ips {
		fmt.Printf(" IN A %s\n", ip.String())
	}

	printColor("\n - Canonical Name: ", colorCYAN)
	cname, _ := net.LookupCNAME(domain)
	fmt.Printf("%s\n", cname)

	printColor("\n - Name Server: ", colorCYAN)
	nss, _ := net.LookupNS(domain)
	for _, ns := range nss {
		fmt.Printf("%v\n", ns)
	}
}

func showSockets() {
	printColor(" listening socket ports: ", colorBLUE)
	prog := "ss"
	args := []string{"-tunlp4"}
	_, _ = runCmd(prog, args, true)
	printColor(" socket established: ", colorBLUE)
	args = []string{"-t", "state", "established"}
	_, _ = runCmd(prog, args, true)
}

func showIntf(substring string, intfip []intfIP) {
	for _, i := range intfip {
		fmt.Printf("%s: %s %v\n", i.intfName, i.ipAddr, i.iFlag)
	}
	fmt.Printf("\n")
	printTitle(" ip link info:", colorCYAN, false)

	getARP("")

	getPortCfg(substring, true)
	printTitle(" proxy:", colorCYAN, false)
	getProxy(true)
}

func showAppDetail(substring string) {
	if !rePattern.MatchString(substring) {
		fmt.Printf("app substring invalid\n")
		return
	}
	jfiles, err := listJSONFiles("/run/zedrouter/AppNetworkStatus")
	if err != nil {
		return
	}
	for _, s := range jfiles {
		retbytes1, err := os.ReadFile(s)
		if err != nil {
			continue
		}
		status := strings.TrimSuffix(string(retbytes1), "\n")
		doAppNet(status, substring, false)
	}
}

func runTrace(substring, server string) {
	prog := "traceroute"
	var args []string
	if substring != "" {
		baseargs := []string{"-4", "-m", "10", "-q", "2", substring}
		args = baseargs
		if cmdTimeout != "" {
			prog = "timeout"
			args = []string{cmdTimeout, "traceroute"}
			args = append(args, baseargs...)
		}
		printTitle(" traceroute to "+substring, colorCYAN, true)
		retStr, _ := runCmd(prog, args, false) // timeout will generate error
		fmt.Printf("%s\n", retStr)
	} else {
		printTitle(" traceroute to google", colorCYAN, true)

		args = []string{"-4", "-m", "10", "-q", "2", "www.google.com"}
		_, _ = runCmd(prog, args, true)
		if server != "" {
			args = []string{"-4", "-m", "10", "-q", "2", server}
			printTitle(" traceroute to "+server, colorCYAN, true)
			_, _ = runCmd(prog, args, true)
		}
	}
}

func runPing(intfStat []intfIP, server string, opt string) {
	if opt != "" {
		if strings.Contains(opt, "/") {
			opts := strings.Split(opt, "/")
			intf := opts[0]
			ipaddr := opts[1]

			var src string
			for _, l := range intfStat {
				if l.intfName == intf {
					src = l.ipAddr
					break
				}
			}
			if src == "" {
				fmt.Printf("can not find ip address on %s\n", intf)
			}
			printColor("\n - ping "+ipaddr+" through intf: "+intf, colorCYAN)
			pingIPHost(ipaddr, src)
		} else {
			printColor("\n - ping "+opt, colorCYAN)
			pingIPHost(opt, "")
		}
		return
	}
	if len(intfStat) == 0 {
		fmt.Printf(" can not find intf to ping\n")
		return
	}

	for _, iip := range intfStat {
		if strings.HasPrefix(iip.intfName, "bn") || strings.HasPrefix(iip.intfName, "lo") {
			continue
		}
		ipaddr := "8.8.8.8"
		printColor("\n - ping "+ipaddr+" through intf: "+iip.intfName, colorCYAN)
		pingIPHost(ipaddr, iip.ipAddr)

		// to zedcloud
		if server != "" {
			printColor("\n - ping to "+server+", source "+iip.ipAddr, colorCYAN)
			ipa := net.ParseIP(iip.ipAddr)
			httpsclient(server, ipa)
		}

		closePipe(true)
	}
}

func getProxy(needPrint bool) (string, int, [][]byte) {
	proxyIP := ""
	proxyPort := 0
	proxyPEM := [][]byte{}
	retbytes, err := os.ReadFile("/run/zedagent/DevicePortConfig/zedagent.json")
	if err != nil {
		return proxyIP, proxyPort, proxyPEM
	}
	var portcfg types.DevicePortConfig
	_ = json.Unmarshal(retbytes, &portcfg)

	for _, p := range portcfg.Ports {
		if !p.IsMgmt {
			continue
		}
		if len(p.Proxies) > 0 && needPrint {
			fmt.Printf("  ifname %s:\n", p.IfName)
		}
		for _, pp := range p.Proxies {
			if pp.Type == 1 { // https
				proxyIP = pp.Server
				proxyPort = int(pp.Port)

			}
			if needPrint {
				fmt.Printf("    type %d, server %s, port %d\n", pp.Type, pp.Server, pp.Port)
			}
		}
		for _, pem := range p.ProxyCertPEM {
			proxyPEM = append(proxyPEM, pem)
			if needPrint {
				fmt.Printf("    has proxy cert\n")
			}
		}
	}
	return proxyIP, proxyPort, proxyPEM
}

func httpsclient(server string, ipaddr net.IP) {

	localTCPAddr, _ := net.ResolveTCPAddr("tcp", ipaddr.String())
	transport := &http.Transport{
		Dial: (&net.Dialer{Timeout: 30 * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: localTCPAddr}).Dial, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://" + server + ":/api/v1/cloud/ping")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer resp.Body.Close()

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf("%s", string(htmlData))
}

func getFlow(subStr string) {
	afs := [2]netlink.InetFamily{syscall.AF_INET, syscall.AF_INET6}
	for _, af := range afs {
		connT, err := netlink.ConntrackTableList(netlink.ConntrackTable, af)
		if err != nil {
			fmt.Printf("can not get flow: %v\n", err)
			continue
		}
		if af == syscall.AF_INET {
			printColor("\nflow for IPv4\n", colorGREEN)
		} else {
			printColor("\nflow for IPv6\n", colorGREEN)
		}
		i := 0
		for _, entry := range connT {
			connStr := entry.String()
			oline := connStr
			if subStr != "" {
				if !strings.Contains(connStr, subStr) {
					continue
				}
				colorPattern := getColorStr(subStr, colorYELLOW)
				oline = strings.ReplaceAll(oline, subStr, colorPattern)
			}
			fmt.Printf("%v\n", oline)
			i++
			if i%20 == 0 {
				closePipe(true)
			}
		}
	}
}

func runmDNS(subStr string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("get interface error: %v\n", err)
		return
	}

	var intfname, serv, serviceStr string
	if strings.Contains(subStr, "/") {
		substrings := strings.Split(subStr, "/")
		if len(substrings) != 2 {
			fmt.Printf("mdns parameter is in the form interface/service\n")
			return
		}
		intfname = substrings[0]
		serv = substrings[1]
	} else {
		intfname = subStr
	}
	var ifs []net.Interface
	for _, intf := range ifaces {
		if intfname == "" {
			if strings.HasPrefix(intf.Flags.String(), "up|") {
				ifs = append(ifs, intf)
			}
		} else if intf.Name == intfname {
			ifs = append(ifs, intf)
			break
		}
	}

	if serv == "" {
		serviceStr = "_workstation._tcp"
	} else {
		serviceStr = "_" + serv + "._tcp"
	}

	var port []string
	for _, p := range ifs {
		port = append(port, p.Name)
	}
	printTitle(fmt.Sprintf("query mDNS service %s, on intfs %v\n", serviceStr, port), colorCYAN, true)

	ifOption := zeroconf.SelectIfaces(ifs)
	ipOption := zeroconf.SelectIPTraffic(zeroconf.IPv4)
	resolver, err := zeroconf.NewResolver(ipOption, ifOption)
	if err != nil {
		fmt.Printf("queryService: Failed to initialize resolver: %v", err)
		return
	}

	mctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			fmt.Printf("  - %+v\n", entry)
		}
	}(entries)

	err = resolver.Browse(mctx, serviceStr, "local", entries)
	if err != nil {
		fmt.Printf("mdns resolver error %v", err)
		return
	}
	<-mctx.Done()
}

func getPeerCerts(subStr string) {
	if subStr == "" {
		if basics.server != "" {
			subStr = basics.server
			if basics.proxy != "" {
				subStr = subStr + "/" + basics.proxy
			}
		}
		if subStr == "" {
			return
		}
		fmt.Printf("url: %s\n", subStr)
	}
	serverURL := subStr
	proxyStr1 := ""
	if strings.Contains(subStr, "/") {
		strs := strings.SplitN(subStr, "/", 2)
		if len(strs) != 2 {
			return
		}
		serverURL = strs[0]
		proxyStr1 = strs[1]
	}
	var client http.Client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if proxyStr1 != "" {
		proxyURL, err := url.Parse("http://" + proxyStr1)
		if err != nil {
			fmt.Printf("proxy url error %v\n", err)
			return
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client = http.Client{
		Transport: &transport,
	}
	resp, err := client.Get(fmt.Sprintf("https://%s", serverURL))
	if err != nil {
		fmt.Printf("client get error %v\n", err)
	}
	if resp != nil {
		if resp.TLS != nil {
			for i, cert := range resp.TLS.PeerCertificates {
				fmt.Printf("(%d) Certificate:\n", i)
				fmt.Printf("\tData:\n")
				fmt.Printf("\t\tVersion: %d\n", cert.Version)
				fmt.Printf("\t\tSerial Number:\n\t\t\t%s\n", cert.SerialNumber)
				fmt.Printf("\tSignature Algorithm: %v\n", cert.SignatureAlgorithm.String())
				fmt.Printf("\t\tIssuer:%s\n", cert.Issuer)
				fmt.Printf("\t\tValidity:\n")
				fmt.Printf("\t\t\tNot Before: %v\n", cert.NotBefore)
				fmt.Printf("\t\t\tNot After: %v\n", cert.NotAfter)
				fmt.Printf("\t\tSubject: %v\n", cert.Subject)
			}
		} else {
			fmt.Printf("resp.TLS nil\n")
		}
		if resp.Body != nil {
			resp.Body.Close()
		}
	} else {
		fmt.Printf("resp nil\n")
	}
}

func addEctHostEntry(subStr string) {
	if !strings.Contains(subStr, "/") {
		fmt.Printf("need to have host name and IP separated by slash\n")
		return
	}

	subs := strings.SplitN(subStr, "/", 2)
	if len(subs) != 2 {
		fmt.Printf("need to have host name and IP separated by slash\n")
		return
	}
	hostname := subs[0]
	hostIP := subs[1]
	if net.ParseIP(hostIP) == nil {
		fmt.Printf("IP address is invalid\n")
		return
	}

	f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("open file error %v\n", err)
		return
	}
	defer f.Close()
	entry := fmt.Sprintf("%s  %s\n", hostIP, hostname)
	if _, err := f.WriteString(entry); err != nil {
		fmt.Printf("write file error %v\n", err)
		return
	}
	// display the /etc/hosts file
	readAFile("/etc/hosts", 0)
}

func runTCPDump(intfStat []intfIP, subStr string) {
	if !strings.Contains(subStr, "/") {
		fmt.Printf("need to have intf name separated by slash\n")
		return
	}
	err := addPackage("/usr/bin/tcpdump", "tcpdump")
	if err != nil {
		return
	}

	subs := strings.SplitN(subStr, "/", 2)
	if len(subs) != 2 {
		fmt.Printf("need to have intf name separated by slash\n")
		return
	}
	intf := subs[0]
	var timeValue string
	if cmdTimeout != "" {
		timeSec, err := strconv.Atoi(cmdTimeout)
		if err != nil {
			fmt.Printf("time option has to be seconds: %v\n", err)
			return
		}
		if timeSec > 120 {
			timeValue = "120"
			fmt.Printf("time value for tcpdump maximum is 120 seconds\n\n")
		} else {
			timeValue = cmdTimeout
		}
	} else {
		timeValue = "60"
	}

	// sanity checks
	if intf != "" {
		var found bool
		var upintfs []string
		for _, iip := range intfStat {
			upintfs = append(upintfs, iip.intfName)
			if iip.intfName == intf {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("interface name %s, does not match any 'UP' interfaces on device: %v\n", intf, upintfs)
			return
		}
	}
	if !rePattern.MatchString(subs[1]) {
		fmt.Printf("tcpdump command has invalid option\n")
		return
	}

	prog := "timeout"
	args := []string{timeValue, "tcpdump", "-i", intf, subs[1], "-c", "100"}
	title := fmt.Sprintf("tcpdump with %s: %v", prog, args)
	printTitle(title, colorGREEN, true)
	retStr, err := runCmd(prog, args, false)
	if err != nil {
		fmt.Printf("err %v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func runWireless() {
	err := addPackage("/usr/sbin/iwconfig", "wireless-tools")
	if err != nil {
		return
	}

	printTitle("\n iwconfig wlan0", colorCYAN, false)
	prog := "iwconfig"
	args := []string{"wlan0"}
	_, _ = runCmd(prog, args, true)

	retbytes, err := os.ReadFile("/run/wlan/wpa_supplicant.conf")
	if err == nil {
		printTitle(" wpa_supplicant.conf:", colorCYAN, false)
		lines := strings.Split(string(retbytes), "\n")
		if len(lines) < 1 {
			return
		}
		for _, l := range lines[:len(lines)-1] {
			if strings.Contains(l, "psk=") {
				pos := strings.Split(l, "psk=")
				n := len(pos[1])
				pos2 := pos[0] + "psk=" + pos[1][:3] + "..." + pos[1][n-3:]
				fmt.Printf("%s\n", pos2)
			} else {
				fmt.Printf("%s\n", l)
			}
		}
	}

	printTitle("\n wwan config", colorCYAN, false)
	retbytes, err = os.ReadFile("/run/wwan/config.json")
	if err != nil {
		return
	}
	var wwancfg types.WwanConfig
	err = json.Unmarshal(retbytes, &wwancfg)
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", wwancfg)

	printTitle("\n wwan metrics", colorCYAN, false)
	retbytes, err = os.ReadFile("/run/wwan/metrics.json")
	if err == nil {
		prettyJSON, err := formatJSON(retbytes)
		if err == nil {
			fmt.Println(string(prettyJSON))
		}
	}

	printTitle("\n wwan status", colorCYAN, false)
	retbytes, err = os.ReadFile("/run/wwan/status.json")
	if err == nil {
		prettyJSON, err := formatJSON(retbytes)
		if err == nil {
			fmt.Println(string(prettyJSON))
		}
	}
}

func runSpeedTest(intf string) {
	err := addPackage("/usr/bin/speedtest", "speedtest-cli")
	if err != nil {
		return
	}
	var opt string
	var args []string
	if intf != "" {
		retintfs := allUPIntfIPv4()
		for _, i := range retintfs {
			if strings.Contains(i.intfName, intf) {
				opt = " --source " + i.ipAddr
				args = []string{"--source", i.ipAddr}
				break
			}
		}
	}
	printTitle("\n speed test: on "+intf+", "+opt, colorCYAN, true)
	prog := "/usr/bin/speedtest"
	_, _ = runCmd(prog, args, true)
}

func getAllIntfs() []intfIP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ifs []intfIP
	for _, i := range ifaces {
		foo, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, v := range foo {
			ip, _, err := net.ParseCIDR(v.String())
			if err != nil {
				continue
			}
			if ip.To4() == nil {
				continue
			}
			ifp := intfIP{
				intfName: i.Name,
				ipAddr:   ip.String(),
				iFlag:    i.Flags,
			}
			ifs = append(ifs, ifp)
		}
	}
	return ifs
}

func allUPIntfIPv4() []intfIP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ifs []intfIP
	for _, i := range ifaces {
		foo, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, v := range foo {
			ip, _, err := net.ParseCIDR(v.String())
			if err != nil {
				continue
			}
			if ip.To4() == nil {
				continue
			}
			if (i.Flags&net.FlagUp) != 0 && (i.Flags&net.FlagLoopback) == 0 {
				ifp := intfIP{
					intfName: i.Name,
					ipAddr:   ip.String(),
				}
				ifs = append(ifs, ifp)
			}
		}
	}
	return ifs
}

func getTraffic() []intfIP {
	ifTxRx := []intfIP{}
	stats, err := snet.IOCounters(true)
	if err != nil {
		fmt.Printf("%v\n", err)
		return ifTxRx
	}
	for _, s := range stats {
		var tr intfIP
		tr.intfName = s.Name
		tr.recvBytes = int64(s.BytesRecv)
		tr.sentBytes = int64(s.BytesSent)
		ifTxRx = append(ifTxRx, tr)
	}

	return ifTxRx
}

func pingIPHost(remote, local string) {
	var dstaddress, srcaddress net.IPAddr
	var pingSuccess bool
	p := fastping.NewPinger()

	ra, err := net.ResolveIPAddr("ip4:icmp", remote)
	if err != nil {
		fmt.Printf("resolve error: %v\n", err)
		return
	}
	dstaddress.IP = net.ParseIP(ra.String())
	p.AddIPAddr(&dstaddress)

	srcaddress.IP = net.ParseIP(local)
	p.Source(srcaddress.String())
	if dstaddress.String() == "" {
		return
	}

	p.MaxRTT = time.Millisecond * 200
	p.OnRecv = func(ip *net.IPAddr, d time.Duration) {
		if strings.Compare(ip.String(), dstaddress.String()) == 0 {
			pingSuccess = true
			fmt.Printf("Ping: got reply from %s, duration %d nanosec or rtt %v\n",
				dstaddress.String(), int64(d.Nanoseconds()), d)
		}
	}
	p.OnIdle = func() {
		fmt.Printf("Ping: run finish\n")
	}
	err = p.Run()
	if err != nil {
		fmt.Printf("Ping: run error, %v\n", err)
	}
	fmt.Printf("ping: success %v\n", pingSuccess)
}

func getAllIPv4Routes(ifindex int) []netlink.Route {
	table := syscall.RT_TABLE_MAIN
	filter := netlink.Route{Table: table, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	routes, err := netlink.RouteListFiltered(syscall.AF_INET,
		&filter, fflags)
	if err != nil {
		fmt.Printf("getAllIPv4Routes: ifindex %d failed, error %v", ifindex, err)
		return nil
	}
	return routes
}

func getTableIPv4Routes(table int) []netlink.Route {
	filter := netlink.Route{Table: table}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_TABLE
	routes, err := netlink.RouteListFiltered(syscall.AF_INET,
		&filter, fflags)
	if err != nil {
		fmt.Printf("getAllIPv4RoutesTable: table %d failed, error %v", table, err)
		return nil
	}
	return routes
}
