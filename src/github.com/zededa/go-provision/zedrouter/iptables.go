// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// iptables support code

package main

import (
	"log"
	"os/exec"
)

func iptableCmd(args... string) error {
	cmd := "iptables"
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("iptables command failed: ", args, err)
		return err
	}
	return nil
}

func ip6tableCmd(args... string) error {
	cmd := "ip6tables"
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("ip6tables command failed: ", args, err)
		return err
	}
	return nil
}

// XXX should we add one MASQ per bu interface? Being used before domU's are
// started. By who?
func iptablesInit() {
	// XXX Avoid adding multiple times as we restart
	iptableCmd("-t", "nat", "-F", "POSTROUTING")
	iptableCmd("-t", "nat", "-A", "POSTROUTING", "-o", globalConfig.Uplink,
		"-j", "MASQUERADE")
}

