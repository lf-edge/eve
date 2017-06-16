// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// dnsmasq configlets for overlay and underlay interfaces towards domU

package main

import (
	"fmt"       
	"log"
	"os"
	"os/exec"
)

// XXX TODO move ipset to be ACL dependent
const dnsmasqOverlayStatic=`
except-interface=lo
bind-interfaces
log-queries
log-dhcp
no-hosts
no-ping
bogus-priv
stop-dns-rebind
rebind-localhost-ok
domain-needed
# SHOULD be derived from underlay ACL.
# Needed here for underlay since queries for A RRs might come over IPv6
ipset=/google.com/ipv4.google.com,ipv6.google.com
ipset=/zededa.net/ipv4.zededa.net,ipv6.zededa.net
dhcp-range=::,static,0,infinite
`

// XXX TODO move ipset to be ACL dependent
const dnsmasqUnderlayStatic=`
except-interface=lo
bind-interfaces
log-queries
log-dhcp
no-hosts
no-ping
bogus-priv
stop-dns-rebind
rebind-localhost-ok
domain-needed
# SHOULD be derived from underlay ACL
ipset=/google.com/ipv4.google.com,ipv6.google.com
ipset=/zededa.net/ipv4.zededa.net,ipv6.zededa.net
dhcp-range=172.27.0.0,static,255.255.0.0,infinite
`

// XXX would be more polite to return an error then to Fatal
// XXX less args?
// XXX fix addn-hosts - should we use a hostdir per overlay so we can add
// one file per eid? Makes it more dynamic.
func createDnsmasqOverlayConfiglet(cfgPathname string, olIfname string,
     olAddr1 string, olAddr2 string, olMac string, hostsDir string,
     olNum int, appNum int) {
	file, err := os.Create(cfgPathname)
	if err != nil {
		log.Fatal("os.Create for ", cfgPathname, err)
	}
	defer file.Close()
	file.WriteString(dnsmasqOverlayStatic)
	file.WriteString(fmt.Sprintf("pid-file=/var/run/dnsmasq.%s.pid\n",
		olIfname))
	file.WriteString(fmt.Sprintf("interface=%s\n", olIfname))
	file.WriteString(fmt.Sprintf("listen-address=%s\n", olAddr1))
	file.WriteString(fmt.Sprintf("dhcp-host=%s,[%s]\n", olMac, olAddr2))
	// addn-hosts=${HOSTSDIR}/hosts6.${OLNUM}_${APPNUM}
	file.WriteString(fmt.Sprintf("addn-hosts=%s/hosts6.%d_%d\n",
		hostsDir, olNum, appNum))
}

// XXX would be more polite to return an error then to Fatal
// XXX less args?
func createDnsmasqUnderlayConfiglet(cfgPathname string, ulIfname string,
     ulAddr1 string, ulAddr2 string, ulMac string) {
	file, err := os.Create(cfgPathname)
	if err != nil {
		log.Fatal("os.Create for ", cfgPathname, err)
	}
	defer file.Close()
	file.WriteString(dnsmasqUnderlayStatic)
	file.WriteString(fmt.Sprintf("pid-file=/var/run/dnsmasq.%s.pid\n",
		ulIfname))
	file.WriteString(fmt.Sprintf("interface=%s\n", ulIfname))
	file.WriteString(fmt.Sprintf("listen-address=%s\n", ulAddr1))
	file.WriteString(fmt.Sprintf("dhcp-host=%s,id:*,%s\n", ulMac, ulAddr2))
}

func deleteDnsmasqConfiglet(cfgPathname string) {
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
//    DMDIR=/home/nordmark/dnsmasq-2.75/src
//    ${DMDIR}/dnsmasq --conf-file=/etc/dnsmasq.${OLIFNAME}.conf
// or
//    ${DMDIR}/dnsmasq --conf-file=/etc/dnsmasq.${ULIFNAME}.conf
func startDnsmasq(cfgPathname string) {
	cmd := "nohup"
	args := []string{
		"/home/nordmark/dnsmasq-2.75/src/dnsmasq",
		"-C",
		cfgPathname,
	}
	go exec.Command(cmd, args...).Output()
}

//    pkill -u radvd -f radvd.${OLIFNAME}.conf
func stopDnsmasq(cfgFilename string, printOnError bool) {
	// XXX add dnsmasq to match?
	pkillUserArgs("nobody", cfgFilename, printOnError)
}
