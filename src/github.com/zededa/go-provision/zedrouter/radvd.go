// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// radvd configlet for overlay interface towards domU

package main

import (
	"fmt"       
	"log"
	"os"
	"os/exec"
)

// Need to fill in the overlay inteface name
const radvdTemplate=`
interface %s {
	IgnoreIfMissing on;
	AdvSendAdvert on;
	MaxRtrAdvInterval 1800;
	AdvManagedFlag on;
};
`

// XXX would be more polite to return an error then to Fatal
func createRadvdConfigLet(cfgPathname string, olIfname string) {
	file, err := os.Create(cfgPathname)
	if err != nil {
		log.Fatal("os.Create for ", cfgPathname, err)
	}
	defer file.Close()
	file.WriteString(fmt.Sprintf(radvdTemplate, olIfname))
}

func deleteRadvdConfigLet(cfgPathname string) {
	cmd := "rm"
	args := []string{
		"-f",
		cfgPathname,
	}
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		// XXX should this be log?
		fmt.Printf("Command %v %v failed: %s\n", cmd, args, err)
	}
}

// Run this:
//    radvd -u radvd -C /etc/radvd.${OLIFNAME}.conf -p /var/run/radvd.${OLIFNAME}.pid
func startRadvd(cfgPathname string, pidPathname string) {
	cmd := "nohup"
	args := []string{
		"radvd",
		"-u",
		"radvd",
		"-C",
		cfgPathname,
		"-p",
		pidPathname,
	}
	go exec.Command(cmd, args...).Output()
}

