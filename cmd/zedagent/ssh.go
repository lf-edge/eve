// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// XXX this should really live in zedrouter but we'll remove ssh before
// we disaggregate
// XXX also blocks port 8080

package main

import (
	"github.com/zededa/go-provision/wrap"
	"log"
	"os/exec"
)

func updateSshAccess(enable bool) {
	if enable {
		enableSsh()
	} else {
		disableSsh()
	}
}

func enableSsh() {
	// Delete these rules
	// iptables -D OUTPUT -p tcp --sport 22 -j DROP
	// iptables -D INPUT -p tcp --dport 22 -j DROP
	// ip6tables -D OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -D INPUT -p tcp --dport 22 -j DROP
	iptableCmd("-D", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	iptableCmd("-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	ip6tableCmd("-D", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	ip6tableCmd("-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	iptableCmd("-D", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	iptableCmd("-D", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	ip6tableCmd("-D", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	ip6tableCmd("-D", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
}

func disableSsh() {
	// Add these rules
	// iptables -A OUTPUT -p tcp --sport 22 -j DROP
	// iptables -A INPUT -p tcp --dport 22 -j DROP
	// ip6tables -A OUTPUT -p tcp --sport 22 -j DROP
	// ip6tables -A INPUT -p tcp --dport 22 -j DROP
	iptableCmd("-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	iptableCmd("-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	ip6tableCmd("-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "DROP")
	ip6tableCmd("-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP")
	iptableCmd("-A", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	iptableCmd("-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	ip6tableCmd("-A", "OUTPUT", "-p", "tcp", "--sport", "8080", "-j", "DROP")
	ip6tableCmd("-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
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
		log.Println("iptables command failed: ", args, err)
		return "", err
	}
	return string(out), nil
}

func iptableCmd(args ...string) error {
	_, err := iptableCmdOut(true, args...)
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
		log.Println("ip6tables command failed: ", args, err)
		return "", err
	}
	return string(out), nil
}

func ip6tableCmd(args ...string) error {
	_, err := ip6tableCmdOut(true, args...)
	return err
}
