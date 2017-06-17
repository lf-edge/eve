// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// ACL configlet for overlay and underlay interface towards domU

package main

import (
	"fmt"       
//	"log"
//	"os"
//	"os/exec"
	"github.com/zededa/go-provision/types"
// XXX	"github.com/janeczku/go-ipset/ipset"
)

// XXX would be more polite to return an error then to Fatal
func createACLConfiglet(ifname string, ACLs []types.ACE) {
	fmt.Printf("createACLConfiglet: ifname %s, ACLs %v\n", ifname, ACLs)
	// XXX implement
}

func updateACLConfiglet(ifname string, ACLs []types.ACE) {
	fmt.Printf("updateACLConfiglet: ifname %s, ACLs %v\n", ifname, ACLs)
	// XXX implement
}

// XXX can we find/flush just based on the ifname?
// XXX use separate chain??
func deleteACLConfiglet(ifname string, ACLs []types.ACE) {
	fmt.Printf("deleteACLConfiglet: ifname %s ACLs %v\n", ifname, ACLs)
}
