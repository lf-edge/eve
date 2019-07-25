// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Also blocks the VNC ports (5900...) if ssh is blocked
// Always blocks 4822
// Also always blocks port 8080

package iptables

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

func UpdateSshAccess(enable bool, first bool) {

	log.Infof("updateSshAccess(enable %v first %v)\n",
		enable, first)

	if first {
		// Always blocked
		dropPortRange(8080, 8080)
		allowLocalPortRange(4822, 4822)
		allowLocalPortRange(5900, 5999)
		markControlFlows()
	}
	if enable {
		allowPortRange(22, 22)
	} else {
		dropPortRange(22, 22)
	}
}

func UpdateVncAccess(enable bool) {

	log.Infof("updateVncAccess(enable %v\n", enable)

	if enable {
		allowPortRange(5900, 5999)
	} else {
		dropPortRange(5900, 5999)
	}
}

func allowPortRange(startPort int, endPort int) {
	log.Infof("allowPortRange(%d, %d)\n", startPort, endPort)
	// Delete these rules
	// iptables -D INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	// ip6tables -D INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	var portStr string
	if startPort == endPort {
		portStr = fmt.Sprintf("%d", startPort)
	} else {
		portStr = fmt.Sprintf("%d:%d", startPort, endPort)
	}
	IptableCmd("-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
	Ip6tableCmd("-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
}

// Like above but allow for 127.0.0.1 to 127.0.0.1 and block for other IPs
func allowLocalPortRange(startPort int, endPort int) {
	log.Infof("allowLocalPortRange(%d, %d)\n", startPort, endPort)
	// Add these rules
	// iptables -A INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 --dport 22 -j ACCEPT
	// iptables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	// iptables -A INPUT -p tcp -s ::1 -d ::1 --dport 22 -j ACCEPT
	// ip6tables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	var portStr string
	if startPort == endPort {
		portStr = fmt.Sprintf("%d", startPort)
	} else {
		portStr = fmt.Sprintf("%d:%d", startPort, endPort)
	}
	IptableCmd("-A", "INPUT", "-p", "tcp", "--dport", portStr,
		"-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT")
	IptableCmd("-A", "INPUT", "-p", "tcp", "--dport", portStr,
		"-j", "REJECT", "--reject-with", "tcp-reset")
	Ip6tableCmd("-A", "INPUT", "-p", "tcp", "--dport", portStr,
		"-s", "::1", "-d", "::1", "-j", "ACCEPT")
	Ip6tableCmd("-A", "INPUT", "-p", "tcp", "--dport", portStr,
		"-j", "REJECT", "--reject-with", "tcp-reset")
}

func dropPortRange(startPort int, endPort int) {
	log.Infof("dropPortRange(%d, %d)\n", startPort, endPort)
	// Add these rules
	// iptables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	// ip6tables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	var portStr string
	if startPort == endPort {
		portStr = fmt.Sprintf("%d", startPort)
	} else {
		portStr = fmt.Sprintf("%d:%d", startPort, endPort)
	}
	IptableCmd("-A", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
	Ip6tableCmd("-A", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
}

// With flow monitoring happening, any unmarked connections:
// 1) Not matching any of the INPUT ACL in PREROUTING chain
// 2) Not initiated by applications
// will be dropped (sent out of dummy interface). But, we still
// want some control protocols running on dom0 to run. We mark such
// connections with markings from reserved space and let the ACLs
// in INPUT chain make the ACCEPT/DROP/REJECT decisions.
func markControlFlows() {
	// Mark HTTP, ssh and guacamole packets
	// Pick flow marking values 1, 2, 3 from the reserved space.
	portStr := "8080,22,4822"
	IptableCmd("-t", "mangle", "-I", "PREROUTING", "1", "-p", "tcp",
		"--match", "multiport", "--dports", portStr,
		"-j", "CONNMARK", "--set-mark", "1")

	Ip6tableCmd("-t", "mangle", "-I", "PREROUTING", "1", "-p", "tcp",
		"--match", "multiport", "--dports", portStr,
		"-j", "CONNMARK", "--set-mark", "1")

	// Mark VNC packets
	portStr = "5900:5999"
	IptableCmd("-t", "mangle", "-I", "PREROUTING", "2", "-p", "tcp",
		"--match", "multiport", "--dports", portStr,
		"-j", "CONNMARK", "--set-mark", "2")

	Ip6tableCmd("-t", "mangle", "-I", "PREROUTING", "2", "-p", "tcp",
		"--match", "multiport", "--dports", portStr,
		"-j", "CONNMARK", "--set-mark", "2")

	// Mark Lisp control/data packets
	portStr = "4341,4342"
	IptableCmd("-t", "mangle", "-I", "PREROUTING", "3", "-p", "udp",
		"--match", "multiport", "--dports", portStr,
		"-j", "CONNMARK", "--set-mark", "3")

	Ip6tableCmd("-t", "mangle", "-I", "PREROUTING", "3", "-p", "udp",
		"--match", "multiport", "--dports", portStr,
		"-j", "CONNMARK", "--set-mark", "3")

	IptableCmd("-t", "mangle", "-I", "PREROUTING", "4", "-p", "udp",
		"--match", "multiport", "--sports", portStr,
		"-j", "CONNMARK", "--set-mark", "4")

	Ip6tableCmd("-t", "mangle", "-I", "PREROUTING", "4", "-p", "udp",
		"--match", "multiport", "--sports", portStr,
		"-j", "CONNMARK", "--set-mark", "4")

	// Mark all un-marked local traffic generated by local services.
	IptableCmd("-t", "mangle", "-I", "OUTPUT",
		"-j", "CONNMARK", "--restore-mark")
	IptableCmd("-t", "mangle", "-A", "OUTPUT", "-m", "mark", "!", "--mark", "0",
		"-j", "ACCEPT")
	IptableCmd("-t", "mangle", "-A", "OUTPUT",
		"-j", "MARK", "--set-mark", "5")
	IptableCmd("-t", "mangle", "-A", "OUTPUT",
		"-j", "CONNMARK", "--save-mark")
	IptableCmd("-t", "mangle", "-A", "OUTPUT",
		"-j", "CONNMARK", "--set-mark", "5")

	Ip6tableCmd("-t", "mangle", "-I", "OUTPUT", "1",
		"-j", "CONNMARK", "--set-mark", "5")

}
