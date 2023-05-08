// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/miekg/dns"
)

// ResolveConfDirs : directories where resolv.conf for an interface could be found.
var ResolveConfDirs = []string{"/run/dhcpcd/resolv.conf", "/run/wwan/resolv.conf"}

const (
	// DNSMaxParallelRequests is the maximum amount of parallel DNS requests
	DNSMaxParallelRequests     = 5
	maxTTLSec              int = 3600
	dnsTimeout                 = 30 * time.Second
)

// DNSResponse represents a response from a DNS server (A Record)
type DNSResponse struct {
	IP  net.IP
	TTL uint32
}

// IfnameToResolvConf : Look for a file created by dhcpcd
func IfnameToResolvConf(ifname string) string {
	for _, d := range ResolveConfDirs {
		filename := fmt.Sprintf("%s/%s.dhcp", d, ifname)
		_, err := os.Stat(filename)
		if err == nil {
			return filename
		}
	}
	return ""
}

// ResolvConfToIfname : Returns the name of the interface for which
// the given resolv.conf file was created.
func ResolvConfToIfname(resolvConf string) string {
	ext := filepath.Ext(resolvConf)
	if ext != ".dhcp" {
		return ""
	}
	for _, d := range ResolveConfDirs {
		if strings.HasPrefix(resolvConf, d) {
			return strings.TrimSuffix(filepath.Base(resolvConf), ext)
		}
	}
	return ""
}

// ResolveWithSrcIP resolves a domain with a given dns server and source Ip
func ResolveWithSrcIP(domain string, dnsServerIP net.IP, srcIP net.IP) ([]DNSResponse, error) {
	var response []DNSResponse
	sourceUDPAddr := net.UDPAddr{IP: srcIP}
	dialer := net.Dialer{LocalAddr: &sourceUDPAddr}
	dnsClient := dns.Client{Dialer: &dialer}
	msg := dns.Msg{}
	if domain[len(domain)-1] != '.' {
		domain = domain + "."
	}
	msg.SetQuestion(domain, dns.TypeA)
	dnsClient.Timeout = time.Duration(dnsTimeout)
	reply, _, err := dnsClient.Exchange(&msg, net.JoinHostPort(dnsServerIP.String(), "53"))
	if err != nil {
		return response, fmt.Errorf("dns exchange failed: %v", err)
	}
	for _, answer := range reply.Answer {
		if aRecord, ok := answer.(*dns.A); ok {
			response = append(response, DNSResponse{
				IP:  aRecord.A,
				TTL: aRecord.Header().Ttl,
			})
		}
	}

	return response, nil
}

// ResolveWithPortsLambda resolves a domain by using source IPs and dns servers from DeviceNetworkStatus
// As a resolver func ResolveWithSrcIP can be used
func ResolveWithPortsLambda(domain string,
	dns types.DeviceNetworkStatus,
	resolve func(string, net.IP, net.IP) ([]DNSResponse, error)) ([]DNSResponse, []error) {

	quit := make(chan struct{})
	work := make(chan struct{}, DNSMaxParallelRequests)
	resolvedIPsChan := make(chan []DNSResponse)
	countDNSRequests := 0
	var errs []error
	var errsMutex sync.Mutex
	var wg sync.WaitGroup

	for _, port := range dns.Ports {
		if port.Cost > 0 {
			continue
		}

		var srcIPs []net.IP
		for _, addrInfo := range port.AddrInfoList {
			if addrInfo.Addr.IsGlobalUnicast() {
				srcIPs = append(srcIPs, addrInfo.Addr)
			}
		}

		for _, dnsIP := range port.DNSServers {
			for _, srcIP := range srcIPs {
				wg.Add(1)
				dnsIPCopy := make(net.IP, len(dnsIP))
				copy(dnsIPCopy, dnsIP)
				srcIPCopy := make(net.IP, len(srcIP))
				copy(srcIPCopy, srcIP)
				countDNSRequests++
				go func(dnsIP, srcIP net.IP) {
					select {
					case work <- struct{}{}:
						// if writable, means less than dnsMaxParallelRequests goroutines are currently running
					}
					select {
					case <-quit:
						// will return in case the quit chan has been closed,
						// meaning another dns server already resolved the IP
						return
					default:
						// do not wait for receiving a quit
					}
					response, err := resolve(domain, dnsIP, srcIP)
					if err != nil {
						errsMutex.Lock()
						defer errsMutex.Unlock()
						errs = append(errs, err)
					}
					if response != nil {
						resolvedIPsChan <- response
					}
					<-work
					wg.Done()
				}(dnsIPCopy, srcIPCopy)
			}
		}
	}

	wgChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgChan)
	}()

	select {
	case <-wgChan:
		var responses []DNSResponse
		if countDNSRequests == 0 {
			// fallback in case no resolver is configured
			ips, err := net.LookupIP(domain)
			if err != nil {
				return nil, append(errs, fmt.Errorf("fallback resolver failed: %+v", err))
			}
			for _, ip := range ips {
				responses = append(responses, DNSResponse{
					IP:  ip,
					TTL: uint32(maxTTLSec),
				})
			}
		}
		return responses, nil
	case ip := <-resolvedIPsChan:
		close(quit)
		return ip, errs
	}
}
