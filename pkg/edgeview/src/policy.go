// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	devIntfIPs []string
	appIntfIPs []appIPvnc
	devPolicy  types.EvDevPolicy
	appPolicy  types.EvAppPolicy
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

	if cmds.Network != "" && strings.HasPrefix(cmds.Network, "tcp/") {
		opts := strings.SplitN(cmds.Network, "tcp/", 2)
		if len(opts) != 2 {
			return false
		}
		ok := checkTCPPolicy(opts[1], evStatus)
		if !ok {
			log.Noticef("TCP option %s, not allowed by policy", opts[1])
			return false
		}
	}

	// add object-type and object-name for controller easier identifying
	logObj := log.CloneAndAddField("obj_type", "newlog-gen-event").
		AddField("obj_name", "edgeview-cmd")
	logObj.Noticef("recv[ep%s:%s] cmd: %v", instStr, cmds.ClientEPAddr, getCMDString(cmds))
	return true
}

func checkTCPPolicy(tcpOpts string, evStatus *types.EdgeviewStatus) bool {
	devIntfIPs = getAllLocalAddr()
	appIntfIPs = getAllAppIPs()
	if strings.Contains(tcpOpts, "/") {
		params := strings.Split(tcpOpts, "/")
		for _, ipport := range params {
			if !checkIPportPolicy(ipport, evStatus) {
				log.Noticef("tcp cmds: %s, not allowed by policy", ipport)
				return false
			}
		}
	} else {
		if !checkIPportPolicy(tcpOpts, evStatus) {
			log.Noticef("tcp cmds: %s, not allowed by policy", tcpOpts)
			return false
		}
	}
	return true
}

// checkIPportPolicy - check for individual tcp param
// proxy is count for app
// if the IP address belongs to the device, count for device
// otherwise, count for app
// One TCP cmd with multiple address:port, count for multiple access
// E.g. tcp/proxy/localhost:22/10.1.0.102:5901 count access for device 1, and app 2
func checkIPportPolicy(tcpOpt string, evStatus *types.EdgeviewStatus) bool {
	if strings.HasPrefix(tcpOpt, "proxy") {
		// 'proxy' count for app only
		if !appPolicy.Enabled {
			return false
		} else {
			evStatus.CmdCountApp++
			return true
		}
	}

	if strings.Contains(tcpOpt, ":") {
		opts := strings.Split(tcpOpt, ":")
		if len(opts) != 2 {
			return false
		}

		isAddrDevice := checkAddrLocal(opts[0])
		if isAddrDevice {
			if !devPolicy.Enabled {
				return false
			} else {
				evStatus.CmdCountDev++
			}
		} else {
			isAddrApps, vncEnable := checkAddrApps(opts[0])
			if isAddrApps {
				if !appPolicy.Enabled {
					return false
				} else {
					if !vncEnable {
						log.Noticef("checkIPportPolicy: vnc not enabled")
						return false
					}
					evStatus.CmdCountApp++
				}
			} else { // external to the device and app
				// later
				log.Tracef("checkIPportPolicy: IP is off device")
			}
		}
	} else {
		return false
	}

	return true
}

func checkAddrLocal(addr string) bool {
	for _, a := range devIntfIPs {
		if a == addr {
			return true
		}
	}
	return false
}

func checkAddrApps(addr string) (bool, bool) {
	for _, a := range appIntfIPs {
		if a.ipAddr == addr {
			if a.vncEnable {
				return true, true
			} else {
				return true, false
			}
		}
	}
	return false, false
}
