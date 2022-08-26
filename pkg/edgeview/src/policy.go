// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	devIntfIPs []string
	appIntfIPs []appIPvnc
	devPolicy  types.EvDevPolicy
	appPolicy  types.EvAppPolicy
	extPolicy  types.EvExtPolicy
)

func initPolicy() error {
	_, err := os.Stat(types.EdgeviewCfgFile)
	if err == nil {
		data, err := ioutil.ReadFile(types.EdgeviewCfgFile)
		if err != nil {
			log.Errorf("can not read policy file: %v", err)
			return err
		}
		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines {
			if bytes.Contains(line, []byte(types.EdgeViewDevPolicyPrefix)) {
				data1 := bytes.SplitN(line, []byte(types.EdgeViewDevPolicyPrefix), 2)
				if len(data1) != 2 {
					return fmt.Errorf("can not find dev policy in file")
				}
				err = json.Unmarshal(data1[1], &devPolicy)
				if err != nil {
					return err
				}
			} else if bytes.Contains(line, []byte(types.EdgeViewAppPolicyPrefix)) {
				data1 := bytes.SplitN(line, []byte(types.EdgeViewAppPolicyPrefix), 2)
				if len(data1) != 2 {
					return fmt.Errorf("can not find app policy in file")
				}
				err = json.Unmarshal(data1[1], &appPolicy)
				if err != nil {
					return err
				}
			} else if bytes.Contains(line, []byte(types.EdgeViewExtPolicyPrefix)) {
				data1 := bytes.SplitN(line, []byte(types.EdgeViewExtPolicyPrefix), 2)
				if len(data1) != 2 {
					return fmt.Errorf("can not find ext policy in file")
				}
				err = json.Unmarshal(data1[1], &extPolicy)
				if err != nil {
					return err
				}
			} else {
				continue
			}
		}
	} else {
		log.Errorf("can not stat edgeview config file: %v", err)
		return err
	}

	return nil
}

func getAllLocalAddr() []string {
	var localIPs []string
	localIPs = getLocalIPs()
	localIPs = append(localIPs, "0.0.0.0")
	localIPs = append(localIPs, "localhost")
	return localIPs
}

func getCMDString(cmds cmdOpt) string {
	if cmds.Network != "" {
		return cmds.Network
	} else if cmds.System != "" {
		return cmds.System
	} else if cmds.Pubsub != "" {
		return "pub/" + cmds.Pubsub
	} else if cmds.Logopt != "" {
		logopt := "log/" + cmds.Logopt
		if cmds.Timerange != "" {
			logopt = logopt + " -time " + cmds.Timerange
		}
		return logopt
	}
	return ""
}

func checkCmdPolicy(cmds cmdOpt, evStatus *types.EdgeviewStatus) bool {
	// log the incoming edge-view command from client
	var instStr string
	if edgeviewInstID > 0 {
		instStr = fmt.Sprintf("-inst-%d", edgeviewInstID)
	}

	if cmds.Logopt != "" || cmds.Pubsub != "" || cmds.System != "" ||
		(cmds.Network != "" && !strings.HasPrefix(cmds.Network, "tcp/")) {
		if !devPolicy.Enabled {
			log.Noticef("device cmds: %v, not allowed by policy", getCMDString(cmds))
			return false
		}
		evStatus.CmdCountDev++
	}

	var appNames string
	if cmds.Network != "" && strings.HasPrefix(cmds.Network, "tcp/") {
		opts := strings.SplitN(cmds.Network, "tcp/", 2)
		if len(opts) != 2 {
			return false
		}
		ok, names := checkTCPPolicy(opts[1], evStatus)
		if !ok {
			log.Noticef("TCP option %s, not allowed by policy", opts[1])
			return false
		}
		appNames = names
	}

	if appNames != "" {
		appNames = " (" + appNames + ")"
	}
	// add object-type and object-name for controller easier identifying
	logObj := log.CloneAndAddField("obj_type", "newlog-gen-event").
		AddField("obj_name", "edgeview-cmd")
	logObj.Noticef("recv[ep%s:%s] cmd: %v%s", instStr, cmds.ClientEPAddr, getCMDString(cmds), appNames)
	return true
}

func checkTCPPolicy(tcpOpts string, evStatus *types.EdgeviewStatus) (bool, string) {
	devIntfIPs = getAllLocalAddr()
	appIntfIPs = getAllAppIPs()
	appName := ""
	if strings.Contains(tcpOpts, "/") {
		params := strings.Split(tcpOpts, "/")
		for _, ipport := range params {
			ok, name := checkIPportPolicy(ipport, evStatus)
			if !ok {
				log.Noticef("tcp cmds: %s, not allowed by policy", ipport)
				return false, ""
			}
			if appName == "" {
				appName = name
			} else {
				appName = appName + ", " + name
			}
		}
	} else {
		ok, name := checkIPportPolicy(tcpOpts, evStatus)
		if !ok {
			log.Noticef("tcp cmds: %s, not allowed by policy", tcpOpts)
			return false, ""
		}
		appName = name
	}
	return true, appName
}

// checkIPportPolicy - check for individual tcp param
// if the IP address belongs to the device, count for device
// otherwise, count for app, including the console vnc ports
// proxy endpoint will be determined at connection time
// One TCP cmd with multiple address:port, count for multiple access
// E.g. tcp/proxy/localhost:22/10.1.0.102:5901 count access for device 1, and app 2
func checkIPportPolicy(tcpOpt string, evStatus *types.EdgeviewStatus) (bool, string) {
	if strings.HasPrefix(tcpOpt, "proxy") {
		// 'proxy' sessions will be check at connect time
		return true, ""
	}
	var appName string
	if strings.Contains(tcpOpt, ":") {
		opts := strings.Split(tcpOpt, ":")
		if len(opts) != 2 {
			return false, ""
		}
		ipaddr := opts[0]
		ipport := opts[1]
		isAddrDevice := checkAddrLocal(ipaddr)
		// check console access for apps first
		isAppConsole, allowVNC, name := checkAppConsole(ipaddr, ipport)
		if isAppConsole {
			if !allowVNC || !appPolicy.Enabled {
				return false, ""
			}
			evStatus.CmdCountApp++
			appName = name
		} else if isAddrDevice { // device side of IP
			if !devPolicy.Enabled {
				return false, ""
			} else {
				evStatus.CmdCountDev++
			}
		} else { // App Interface IP
			isAddrApps, vncEnable, name := checkAddrApps(ipaddr)
			if isAddrApps {
				if !appPolicy.Enabled {
					return false, ""
				} else {
					if !vncEnable {
						log.Noticef("checkIPportPolicy: vnc not enabled")
						return false, ""
					}
					evStatus.CmdCountApp++
					appName = name
				}
			} else { // external to the device and app
				if !extPolicy.Enabled {
					return false, ""
				} else {
					evStatus.CmdCountExt++
				}
				log.Tracef("checkIPportPolicy: IP is off device")
			}
		}
	} else {
		return false, ""
	}

	return true, appName
}

func checkAddrLocal(addr string) bool {
	for _, a := range devIntfIPs {
		if a == addr {
			return true
		}
	}
	return false
}

func checkAppConsole(addr, port string) (bool, bool, string) {
	if addr != "127.0.0.1" && addr != "localhost" {
		return false, false, ""
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return false, false, ""
	}
	if portnum < 5900 || portnum > 5915 {
		return false, false, ""
	}

	var allowVNC bool
	var appName string

	for _, a := range appIntfIPs {
		if a.vncPort+5900 == portnum {
			allowVNC = a.vncEnable
			appName = a.appName
			break
		}
	}

	return true, allowVNC, appName
}

func checkAddrApps(addr string) (bool, bool, string) {
	for _, a := range appIntfIPs {
		if a.ipAddr == addr {
			if a.vncEnable {
				return true, true, a.appName
			} else {
				return true, false, a.appName
			}
		}
	}
	return false, false, ""
}

func checkAndLogProxySession(host string) bool {
	hostIP := host
	if strings.Contains(host, ":") {
		items := strings.SplitN(host, ":", 2)
		if len(items) == 2 {
			hostIP = items[0]
		}
	}

	content := host
	isAddrApps, vncEnable, appName := checkAddrApps(hostIP)
	if isAddrApps {
		if !appPolicy.Enabled || !vncEnable {
			return false
		}
		content = content + "(app)"
		evStatus.CmdCountApp++
	} else {
		if !extPolicy.Enabled {
			return false
		}
		content = content + "(ext)"
		evStatus.CmdCountExt++
	}

	var instStr string
	if edgeviewInstID > 0 {
		instStr = fmt.Sprintf("[inst-%d]", edgeviewInstID)
	}

	if appName != "" {
		appName = " (" + appName + ")"
	}
	// add object-type and object-name for controller easier identifying
	logObj := log.CloneAndAddField("obj_type", "newlog-gen-event").
		AddField("obj_name", "edgeview-cmd")
	logObj.Noticef("recv%s: proxy connection to %s %s", instStr, content, appName)

	return true
}
