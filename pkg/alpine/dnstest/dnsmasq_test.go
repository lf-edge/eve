// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
)

type dnsmasqProcess struct {
	cmd *exec.Cmd
}

func (d *dnsmasqProcess) Stop() {
	dnsmasqPidFile := "/var/run/dnsmasq.pid"
	bs, err := os.ReadFile(dnsmasqPidFile)
	if err == nil {
		pidString := string(bs)
		pidString = strings.TrimSpace(pidString)
		pid, err := strconv.Atoi(pidString)
		if err != nil {
			fmt.Printf("could not parse '%s': %v\n", pidString, err)
		} else {
			err := syscall.Kill(pid, syscall.SIGTERM)
			if err != nil {
				panic(err)
			}
			time.Sleep(time.Second)
			err = syscall.Kill(pid, syscall.SIGKILL)
			if err != nil && err != syscall.ESRCH {
				panic(err)
			}
		}
	}
	os.Remove(dnsmasqPidFile)

	err = d.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		fmt.Println(err)
	}
	time.Sleep(time.Second)
	err = d.cmd.Process.Signal(syscall.SIGKILL)
	if err != nil {
		fmt.Println(err)
	}
	err = d.cmd.Wait()
	if err != nil {
		fmt.Println(err)
	}

	d.cmd = nil
}

func startDnsmasqProcess(loAddr net.IP) *dnsmasqProcess {
	d := dnsmasqProcess{}

	dnsmasqBinaryPath := "/out/usr/sbin/dnsmasq"
	if path := os.Getenv("DNSMASQ_BINARY"); path != "" {
		dnsmasqBinaryPath = path
	}
	args := []string{
		"--no-resolv",
		"-u", "nobody",
		"-g", "nobody",
		"-S", loAddr.String(),
		"-a", "127.0.0.1",
		"-p", "1054",
	}
	d.cmd = exec.Command(dnsmasqBinaryPath, args...)
	d.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	d.cmd.Stdout = os.Stdout
	d.cmd.Stderr = os.Stderr

	err := d.cmd.Start()
	if err != nil {
		panic(err)
	}

	return &d
}

func delDummyInterface() {
	link, err := netlink.LinkByName("dnsmasq")
	if link == nil || err != nil {
		return
	}
	err = netlink.LinkDel(link)
	if err != nil {
		fmt.Println(err)
	}
}

func createDummyInterface(loAddr netlink.Addr) {
	dummy := netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "dnsmasq"},
	}
	err := netlink.LinkAdd(&dummy)
	if err != nil {
		panic(err)
	}

	addrs, err := netlink.AddrList(&dummy, netlink.FAMILY_ALL)
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		err := netlink.AddrDel(&dummy, &addr)
		if err != nil {
			fmt.Println(err)
		}
	}

	err = netlink.AddrAdd(&dummy, &loAddr)
	if err != nil {
		panic(err)
	}

	err = netlink.LinkSetUp(&dummy)
	if err != nil {
		panic(err)
	}
}

// dnsServer is a simple in-process DNS server for testing.
type dnsServer struct {
	domain2ip    map[string]net.IP
	dnsServerUDP *dns.Server
	dnsServerTCP *dns.Server

	silent atomic.Bool
}

func (d *dnsServer) handleDNSReq(w dns.ResponseWriter, msg *dns.Msg) {
	if len(msg.Question) != 1 {
		log.Printf("amount of questions unsupported: %+v", len(msg.Question))
		return
	}

	if d.silent.Load() {
		return
	}

	var reply dns.Msg

	if msg.Question[0].Qtype == dns.TypeA {
		domain := msg.Question[0].Name
		domain = strings.TrimSuffix(domain, ".")

		defaultIP, defaultFound := d.domain2ip["*"]
		destIP, found := d.domain2ip[domain]
		if !found && defaultFound {
			found = true
			destIP = defaultIP
		}
		if found {
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    32,
				},
				A: destIP,
			}}

		} else {
			log.Printf("domain '%s' not found", domain)
		}
	}

	reply.SetReply(msg)

	err := w.WriteMsg(&reply)
	if err != nil {
		log.Printf("could not write dns response message: %+v\n", err)
	}
}

func (d *dnsServer) Stop() {
	for _, f := range []func() error{
		d.dnsServerUDP.Shutdown,
		d.dnsServerTCP.Shutdown} {

		err := f()
		if err != nil {
			log.Printf("shut down failed: %+v\n", err)
		}

	}
}

func (d *dnsServer) IsMute() bool {
	return d.silent.Load()
}
func (d *dnsServer) Mute() {
	d.silent.Store(true)
}
func (d *dnsServer) Unmute() {
	d.silent.Store(false)
}

func listendns(laddr string) *dnsServer {

	d := dnsServer{
		domain2ip: map[string]net.IP{
			"google.com": {8, 8, 8, 8},
			"*":          {1, 2, 3, 4},
		},
	}

	d.silent.Store(false)

	d.dnsServerUDP = &dns.Server{
		Addr:         laddr + ":53",
		Net:          "udp",
		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
		Handler:      dns.HandlerFunc(d.handleDNSReq),

		ReusePort: true,
	}
	d.dnsServerTCP = &dns.Server{
		Addr:         laddr + ":53",
		Net:          "tcp",
		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
		Handler:      dns.HandlerFunc(d.handleDNSReq),

		ReusePort: true,
	}

	go func() {
		err := d.dnsServerUDP.ListenAndServe()
		if err != nil {
			log.Fatalf("udp cannot listen: %v", err)
		}
	}()
	go func() {
		err := d.dnsServerTCP.ListenAndServe()
		if err != nil {
			log.Fatalf("tcp cannot listen: %v", err)
		}
	}()

	return &d
}

func lookup(nameserver string, host string) net.IP {
	c := dns.Client{
		Net:          "tcp",
		Timeout:      10 * time.Second,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	msg := dns.Msg{}
	if !strings.HasSuffix(host, ".") {
		host = host + "."
	}
	msg.SetQuestion(host, dns.TypeA)

	r, _, err := c.Exchange(&msg, nameserver)
	if err != nil {
		fmt.Println("ERR: ", err)
	}

	if r == nil {
		fmt.Println("ERR: no answer")
	}

	if r == nil || r.Answer == nil || len(r.Answer) == 0 {
		return nil
	}

	a, ok := r.Answer[0].(*dns.A)
	if !ok {
		return nil
	}

	return a.A
}

func parallelLookup(parallel int, count int, host string, nameserver string) uint32 {
	eg, _ := errgroup.WithContext(context.Background())
	eg.SetLimit(parallel)

	var success atomic.Uint32

	for i := 0; i < count; i++ {
		currentI := i
		eg.Go(func() error {
			iHost := fmt.Sprintf("%d.%s", currentI, host)
			ip := lookup(nameserver, iHost)
			if ip != nil {
				success.Add(1)
			}
			return nil
		})
	}

	err := eg.Wait()
	if err != nil {
		panic(err)
	}

	return success.Load()
}

func TestLotsOfRequests(t *testing.T) {
	loAddr := netlink.Addr{
		IPNet: &net.IPNet{
			IP:   []byte{192, 168, 100, 1},
			Mask: []byte{255, 255, 255, 0},
		},
	}

	createDummyInterface(loAddr)
	defer delDummyInterface()

	listendns("")

	dm := startDnsmasqProcess(loAddr.IP)
	defer dm.Stop()

	time.Sleep(time.Second)

	parallelLookup(20, 100, "google.com", "127.0.0.1:1054")

	count := 0
	time.Sleep(time.Second)
	for i := 0; i < 500; i++ {
		resolvedIP := lookup("127.0.0.1:1054", "google.com")
		count++
		if resolvedIP != nil {
			break
		}
		time.Sleep(time.Second / 2)
	}

	t.Logf("count: %d", count)
	if count > 70 {
		t.Fatalf("expected less ignored DNS requests until success, got %d", count)
	}
}
