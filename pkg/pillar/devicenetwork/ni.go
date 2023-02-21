package devicenetwork

import "path"

// DnsmasqLeaseDir is a directory with files (one per NI bridge) storing IP leases
// granted to applications by dnsmasq.
var DnsmasqLeaseDir = "/run/zedrouter/dnsmasq.leases/"

// DnsmasqLeaseFilePath returns the path to a file with IP leases granted
// to applications connected to a given bridge.
func DnsmasqLeaseFilePath(bridgeIfName string) string {
	return path.Join(DnsmasqLeaseDir, bridgeIfName)
}
