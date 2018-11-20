// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// XXX also blocks port 8080 since that is used by lispers.net

package zedrouter

import ()

func updateSshAccess(enable bool, initial bool) {
	if enable {
		enableSsh(initial)
	} else {
		disableSsh(initial)
	}
}

// Avoid logging errors if initial
func enableSsh(initial bool) {
	// Delete these rules
	// iptables -D OUTPUT -p tcp --sport 22 -j DROP
	// iptables -D INPUT -p tcp --dport 22 -j DROP
	// ip6tables -D OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -D INPUT -p tcp --dport 22 -j DROP
	iptableCmdOut(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	iptableCmdOut(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	ip6tableCmdOut(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	ip6tableCmdOut(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	iptableCmdOut(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	iptableCmdOut(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	ip6tableCmdOut(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	ip6tableCmdOut(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
}

// Avoid logging errors if initial
func disableSsh(initial bool) {
	// Add these rules
	// iptables -A OUTPUT -p tcp --sport 22 -j DROP
	// iptables -A INPUT -p tcp --dport 22 -j DROP
	// ip6tables -A OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -A INPUT -p tcp --dport 22 -j DROP
	iptableCmdOut(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	iptableCmdOut(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	ip6tableCmdOut(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	ip6tableCmdOut(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	iptableCmdOut(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	iptableCmdOut(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	ip6tableCmdOut(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	ip6tableCmdOut(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
}
