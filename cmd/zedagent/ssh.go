// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// XXX this should really live in zedrouter but we'll remove ssh before
// we disaggregate
// XXX also blocks port 8080

package zedagent

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/wrap"
	"os/exec"
)

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
	iptableCmd(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	iptableCmd(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	ip6tableCmd(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	ip6tableCmd(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	iptableCmd(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	iptableCmd(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	ip6tableCmd(!initial, "-D", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	ip6tableCmd(!initial, "-D", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
}

// Avoid logging errors if initial
func disableSsh(initial bool) {
	// Add these rules
	// iptables -A OUTPUT -p tcp --sport 22 -j DROP
	// iptables -A INPUT -p tcp --dport 22 -j DROP
	// ip6tables -A OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -A INPUT -p tcp --dport 22 -j DROP
	iptableCmd(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	iptableCmd(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	ip6tableCmd(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	ip6tableCmd(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	iptableCmd(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	iptableCmd(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	ip6tableCmd(!initial, "-A", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	ip6tableCmd(!initial, "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
}

func iptableCmdOut(dolog bool, args ...string) (string, error) {
	cmd := "iptables"
	var out []byte
	var err error
	if dolog {
		out, err = wrap.Command(cmd, args...).Output()
	} else {
		out, err = exec.Command(cmd, args...).Output()
	}
	if err != nil {
		if dolog {
			log.Errorln("iptables command failed: ", args, err)
		} else {
			log.Debugln("initial iptables command failed: ",
				args, err)
		}
		return "", err
	}
	return string(out), nil
}

func iptableCmd(dolog bool, args ...string) error {
	_, err := iptableCmdOut(dolog, args...)
	return err
}

func ip6tableCmdOut(dolog bool, args ...string) (string, error) {
	cmd := "ip6tables"
	var out []byte
	var err error
	if dolog {
		out, err = wrap.Command(cmd, args...).Output()
	} else {
		out, err = exec.Command(cmd, args...).Output()
	}
	if err != nil {
		if dolog {
			log.Errorln("ip6tables command failed: ", args, err)
		} else {
			log.Errorln("initial ip6tables command failed: ",
				args, err)
		}
		return "", err
	}
	return string(out), nil
}

func ip6tableCmd(dolog bool, args ...string) error {
	_, err := ip6tableCmdOut(dolog, args...)
	return err
}
