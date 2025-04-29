// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

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
			"google.com": net.IP{8, 8, 8, 8},
			"*":          net.IP{1, 2, 3, 4},
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
		ReuseAddr: true,
	}
	d.dnsServerTCP = &dns.Server{
		Addr:         laddr + ":53",
		Net:          "tcp",
		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
		Handler:      dns.HandlerFunc(d.handleDNSReq),

		ReusePort: true,
		ReuseAddr: true,
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
