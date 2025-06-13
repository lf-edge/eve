// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nim

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// TTL in seconds assumed when DNS response is missing (has zero) TTL.
	defaultTTL = 30

	// How often to rerun lookup and store fresh entries into the cache.
	defaultRefetchPeriod = 30 * time.Second
	maxRefetchPeriod     = 1 * time.Hour
	refetchDelay         = 3 * time.Second
)

// Go routine that periodically resolves and caches controller IP address.
// The cached IP address can be used with SendOnIntf function to speed up
// controller API calls by avoiding repeated hostname resolutions.
func (n *nim) runResolverCacheForController() {
	var content []byte
	var err error
	for len(content) == 0 {
		content, err = os.ReadFile(types.ServerFileName)
		if err != nil {
			n.Log.Errorf("Failed to read %s: %v; "+
				"waiting for it",
				types.ServerFileName, err)
			time.Sleep(10 * time.Second)
		} else if len(content) == 0 {
			n.Log.Errorf("Empty %s file - waiting for it",
				types.ServerFileName)
			time.Sleep(10 * time.Second)
		}
	}
	controllerHostname := string(content)
	controllerHostname = strings.TrimSpace(controllerHostname)
	if host, _, err := net.SplitHostPort(controllerHostname); err == nil {
		controllerHostname = host
	}
	if net.ParseIP(controllerHostname) != nil {
		// Controller hostname is already defined as an IP address.
		return
	}

	dnsQueryTimer := time.NewTimer(defaultRefetchPeriod)

	wdName := agentName + "-resolverCache"
	stillRunning := time.NewTicker(stillRunTime)
	n.PubSub.StillRunning(wdName, warningTime, errorTime)
	n.PubSub.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-dnsQueryTimer.C:
			// Use smallest returned TTL as the update frequency.
			// Even if the DNS server implementation returns the remaining value
			// of the TTL it caches, it will still work.
			minTTL := n.resolveAndCacheIP(controllerHostname)
			var retryAfter time.Duration
			if minTTL == 0 {
				// No response or a failure; make sure we redo the query after 30 seconds.
				retryAfter = defaultRefetchPeriod
			} else {
				retryAfter = time.Duration(minTTL) * time.Second
				// DNS server may return TTL as the remaining time of its own cached TTL.
				// In order to avoid re-fetching controller IP when TTL is close to zero
				// (and thus caching it is practically pointless), we wait few extra
				// seconds before running DNS query again.
				retryAfter += refetchDelay
			}
			// Make sure we do not stop re-fetching for a long time if the returned
			// TTL is some crazy high value.
			if retryAfter > maxRefetchPeriod {
				retryAfter = maxRefetchPeriod
			}
			dnsQueryTimer = time.NewTimer(retryAfter)

		case <-stillRunning.C:
		}
		n.PubSub.StillRunning(wdName, warningTime, errorTime)
	}
}

func (n *nim) doDNSQuery(hostname string) []controllerconn.DNSResponse {
	dnsResponse, errs := controllerconn.ResolveWithPortsLambda(
		hostname,
		n.dpcManager.GetDNS(),
		controllerconn.ResolveWithSrcIP,
	)
	if len(errs) > 0 {
		n.Log.Warnf("doDNSQuery failed: %+v", errs)
	}
	return dnsResponse
}

// Try to resolve the IP address for the given hostname and cache it using pubsub.
// Currently used only for the controller hostname.
func (n *nim) resolveAndCacheIP(hostname string) (minTTL uint32) {
	queryTime := time.Now()
	dnsResponses := n.doDNSQuery(hostname)
	cachedData := types.CachedResolvedIPs{Hostname: hostname}
	for _, dnsResp := range dnsResponses {
		if dnsResp.TTL == 0 {
			dnsResp.TTL = defaultTTL
		}
		cachedData.CachedIPs = append(cachedData.CachedIPs, types.CachedIP{
			IPAddress:  dnsResp.IP,
			ValidUntil: queryTime.Add(time.Duration(dnsResp.TTL) * time.Second),
		})
		if minTTL == 0 || dnsResp.TTL < minTTL {
			minTTL = dnsResp.TTL
		}
	}
	err := n.pubCachedResolvedIPs.Publish(hostname, cachedData)
	if err != nil {
		n.Log.Errorf("Failed to cache resolved IPs for hostname %s: %v",
			hostname, err)
	}
	return minTTL
}
