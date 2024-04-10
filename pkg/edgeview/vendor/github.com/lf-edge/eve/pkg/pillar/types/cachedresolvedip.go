// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// CachedIP : cached IP with time-limited validity.
type CachedIP struct {
	IPAddress  net.IP
	ValidUntil time.Time
}

// String representation of CachedIP.
func (c CachedIP) String() string {
	return fmt.Sprintf("IP %s valid until %v", c.IPAddress, c.ValidUntil)
}

// CachedResolvedIPs serves as a cache for storing the IP addresses obtained through
// DNS resolution for a given hostname.
type CachedResolvedIPs struct {
	Hostname  string
	CachedIPs []CachedIP
}

// String representation of CachedResolvedIPs.
func (c CachedResolvedIPs) String() string {
	cachedIPs := make([]string, 0, len(c.CachedIPs))
	for _, ip := range c.CachedIPs {
		cachedIPs = append(cachedIPs, ip.String())
	}
	return fmt.Sprintf("Hostname %s with cached resolved IPs: [%s]", c.Hostname,
		strings.Join(cachedIPs, ", "))
}

// Key is used for pubsub
func (c CachedResolvedIPs) Key() string {
	return c.Hostname
}

// LogCreate :
func (c CachedResolvedIPs) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.CachedResolvedIPsLogType, "",
		nilUUID, c.LogKey())
	logObject.Metricf("CachedResolvedIPs create %s", c.String())
}

// LogModify :
func (c CachedResolvedIPs) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.CachedResolvedIPsLogType, "",
		nilUUID, c.LogKey())
	oldVal, ok := old.(CachedResolvedIPs)
	if !ok {
		logObject.Clone().Fatalf(
			"LogModify: Old object interface passed is not of CachedResolvedIPs type")
	}
	logObject.Metricf("CachedResolvedIPs modified from %s to %s",
		oldVal.String(), c.String())
}

// LogDelete :
func (c CachedResolvedIPs) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.CachedResolvedIPsLogType, "",
		nilUUID, c.LogKey())
	logObject.Metricf("CachedResolvedIPs delete %s", c.String())
	base.DeleteLogObject(logBase, c.LogKey())
}

// LogKey :
func (c CachedResolvedIPs) LogKey() string {
	return string(base.CachedResolvedIPsLogType) + "-" + c.Key()
}
