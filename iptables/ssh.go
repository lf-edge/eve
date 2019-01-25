// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Also blocks the VNC ports (5900...) if ssh is blocked
// Always blocks 4822
// Also always blocks port 8080

package iptables

import (
	"fmt"
	log "github.com/sirupsen/logrus"
)

func UpdateSshAccess(enable bool, initial bool) {

	log.Infof("updateSshAccess(enable %v initial %v)\n",
		enable, initial)
	if enable {
		enableSsh(initial)
	} else {
		disableSsh(initial)
	}
	if initial {
		// Always blocked
		dropPortRange(initial, 8080, 8080)
		dropPortRange(initial, 4822, 4822)
	}
}

func enableSsh(initial bool) {
	allowPortRange(initial, 22, 22)
	allowPortRange(initial, 5900, 5999)
}

func disableSsh(initial bool) {
	dropPortRange(initial, 22, 22)
	dropPortRange(initial, 5900, 5999)
}

// Avoid logging errors if initial
func allowPortRange(initial bool, startPort int, endPort int) {
	// Delete these rules
	// iptables -D OUTPUT -p tcp --sport 22 -j DROP
	// iptables -D INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	// ip6tables -D OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -D INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	var portStr string
	if startPort == endPort {
		portStr = fmt.Sprintf("%d", startPort)
	} else {
		portStr = fmt.Sprintf("%d:%d", startPort, endPort)
	}
	IptableCmdOut(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", portStr, "-j", "DROP")
	IptableCmdOut(!initial, "-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
	Ip6tableCmdOut(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", portStr, "-j", "DROP")
	Ip6tableCmdOut(!initial, "-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
}

// Avoid logging errors if initial
func dropPortRange(initial bool, startPort int, endPort int) {
	// Add these rules
	// iptables -A OUTPUT -p tcp --sport 22 -j DROP
	// iptables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	// ip6tables -A OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
	var portStr string
	if startPort == endPort {
		portStr = fmt.Sprintf("%d", startPort)
	} else {
		portStr = fmt.Sprintf("%d:%d", startPort, endPort)
	}
	IptableCmdOut(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", portStr, "-j", "DROP")
	IptableCmdOut(!initial, "-A", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
	Ip6tableCmdOut(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", portStr, "-j", "DROP")
	Ip6tableCmdOut(!initial, "-A", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "REJECT", "--reject-with", "tcp-reset")
}
