// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/miekg/dns"
)

const (
	// DhcpcdResolvConfDir : directory where dhcpcd stores resolv.conf
	// files separately for every interface (named <interface>.dhcp).
	DhcpcdResolvConfDir = "/run/dhcpcd/resolv.conf"
	// WwanResolvConfDir : directory where wwan microservice stores resolv.conf
	// files separately for every interface (named <interface>.dhcp).
	WwanResolvConfDir = "/run/wwan/resolv.conf"
)

// ResolveConfDirs : directories where resolv.conf for an interface could be found.
var ResolveConfDirs = []string{DhcpcdResolvConfDir, WwanResolvConfDir}

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
	if !strings.HasSuffix(domain, ".") {
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

type cachedDNSResponses struct {
	dnsResponses []DNSResponse
	validUntil   time.Time
}

type cachedDNSResponseKey struct {
	domain string
	srcIP  string
}

var resolveCache = map[cachedDNSResponseKey]cachedDNSResponses{}

// ResolveCacheWrap wraps around a resolve func (e.g. ResolveWithSrcIP) and caches DNS entries
func ResolveCacheWrap(resolve func(string, net.IP, net.IP) ([]DNSResponse, error)) func(domain string, dnsServerIP net.IP, srcIP net.IP) ([]DNSResponse, error) {
	return func(domain string, dnsServerIP net.IP, srcIP net.IP) ([]DNSResponse, error) {

		cacheKey := cachedDNSResponseKey{
			domain: domain,
			srcIP:  srcIP.String(),
		}
		dnsResponses, found := resolveCache[cacheKey]
		if !found || !dnsResponses.validUntil.After(time.Now()) {
			dnsResponses, err := resolve(domain, dnsServerIP, srcIP)
			if err == nil {
				minValidUntil := uint32(math.MaxUint32)
				for _, dnsResponse := range dnsResponses {
					if dnsResponse.TTL < uint32(minValidUntil) {
						minValidUntil = dnsResponse.TTL
					}
				}
				validUntil := time.Now().Add(time.Duration(minValidUntil * uint32(time.Second)))
				resolveCache[cacheKey] = cachedDNSResponses{
					dnsResponses: dnsResponses,
					validUntil:   validUntil,
				}
			}

			return dnsResponses, err
		}

		return dnsResponses.dnsResponses, nil
	}
}

// ResolveWithPortsLambda resolves a domain by using source IPs and dns servers from DeviceNetworkStatus
// As a resolver func ResolveWithSrcIP can be used
func ResolveWithPortsLambda(domain string,
	dns types.DeviceNetworkStatus,
	resolve func(string, net.IP, net.IP) ([]DNSResponse, error)) ([]DNSResponse, []error) {

	quit := make(chan struct{})
	work := make(chan struct{}, DNSMaxParallelRequests)
	defer close(work)

	resolvedIPsChan := make(chan []DNSResponse, 1)
	defer close(resolvedIPsChan)

	countDNSRequests := 0
	var errs []error
	var errsMutex sync.Mutex
	var wg sync.WaitGroup

	for _, port := range dns.Ports {
		if !port.IsL3Port || port.Cost > 0 {
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
					defer func() {
						wg.Done()
						<-work
					}()
					// if writable, means less than dnsMaxParallelRequests goroutines are currently running
					work <- struct{}{}

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
					if response != nil && len(response) > 0 {
						select {
						case resolvedIPsChan <- response:
						default:
						}
					}
				}(dnsIPCopy, srcIPCopy)
			}
		}
	}

	wgChan := make(chan struct{})

	go func() {
		wg.Wait()
		close(wgChan)
	}()

	defer func() {
		close(quit)
		<-wgChan
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
		return responses, errs
	case ip := <-resolvedIPsChan:
		return ip, nil
	}

}
