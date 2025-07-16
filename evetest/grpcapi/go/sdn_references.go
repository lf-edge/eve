// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Some extra non-generated methods for SDN protobuf types that help with
// network model parsing and validation.

// revive:disable -- this file lives alongside protobuf-generated code in a directory named "go"
package _go

import (
	"fmt"
)

// LabeledItem is implemented by anything that has logical label associated with it.
// These methods helps with the config parsing and validation.
type LabeledItem interface {
	// ItemType : name of the item type (e.g. "port", "bond", "bridge", etc.)
	ItemType() string
	// ItemLogicalLabel : logical label of the item.
	ItemLogicalLabel() string
	// ReferencesFromItem : all references to logical labels from inside of the item.
	ReferencesFromItem() []LogicalLabelRef
}

// LabeledItemWithCategory : items of the same type can be further separated with categories.
// Still the pair (type, logicalLabel) remains as the unique item ID.
type LabeledItemWithCategory interface {
	LabeledItem
	// ItemCategory : optional item category (e.g. different kinds of endpoints).
	ItemCategory() string
}

// LogicalLabelRef : reference to an item's logical label.
type LogicalLabelRef struct {
	// ItemType: Type of the referenced item.
	ItemType string
	// ItemCategory : Category of the referenced item. Can be empty.
	ItemCategory string
	// ItemLogicalLabel : LogicalLabel of the referenced item.
	ItemLogicalLabel string
	// RefKey is used to enforce reference exclusivity.
	// There should not be more than one reference towards
	// the same item with the same RefKey.
	RefKey string
}

// ItemType is "port".
func (p *Port) ItemType() string {
	return "port"
}

// ItemLogicalLabel returns port's logical label.
func (p *Port) ItemLogicalLabel() string {
	return p.LogicalLabel
}

// ReferencesFromItem return empty set of references.
func (p *Port) ReferencesFromItem() []LogicalLabelRef {
	return nil
}

// ItemType is "bond".
func (b *Bond) ItemType() string {
	return "bond"
}

// ItemLogicalLabel returns the logical label of the bond.
func (b *Bond) ItemLogicalLabel() string {
	return b.LogicalLabel
}

// ReferencesFromItem lists all the aggregated ports.
func (b *Bond) ReferencesFromItem() []LogicalLabelRef {
	var refs []LogicalLabelRef
	for _, port := range b.GetPorts() {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Port{}).ItemType(),
			ItemLogicalLabel: port,
			// Same as what bridge uses to enforce exclusive access to the port.
			RefKey: PortMasterRef,
		})
	}
	return refs
}

// ItemType is "bridge".
func (b *Bridge) ItemType() string {
	return "bridge"
}

// ItemLogicalLabel returns logical label of the bridge.
func (b *Bridge) ItemLogicalLabel() string {
	return b.LogicalLabel
}

// PortMasterRef : reference to a physical port by a master interface (bond or bridge).
// Same between (and within) bonds and bridges to enforce exclusive access to the port.
const PortMasterRef = "port-master"

// ReferencesFromItem lists all the ports and bonds referenced by the bridge.
func (b *Bridge) ReferencesFromItem() []LogicalLabelRef {
	var refs []LogicalLabelRef
	for _, port := range b.GetPorts() {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Port{}).ItemType(),
			ItemLogicalLabel: port,
			RefKey:           PortMasterRef,
		})
	}
	for _, bond := range b.GetBonds() {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Bond{}).ItemType(),
			ItemLogicalLabel: bond,
			RefKey:           PortMasterRef,
		})
	}
	return refs
}

// ItemType is "network".
func (n *Network) ItemType() string {
	return "network"
}

// ItemLogicalLabel returns the logical label of the network.
func (n *Network) ItemLogicalLabel() string {
	return n.LogicalLabel
}

// NetworkBridgeRefPrefix : prefix used for references to bridges from networks.
const NetworkBridgeRefPrefix = "bridge-network"

// ReferencesFromItem lists the bridge and all the endpoints and other networks
// referenced from this network.
func (n *Network) ReferencesFromItem() []LogicalLabelRef {
	var refs []LogicalLabelRef
	// Bridge reference.
	var bridgeRefKey string
	if n.GetVlanId() == 0 {
		// At most one non-VLANed network for this bridge.
		bridgeRefKey = NetworkBridgeRefPrefix
	} else {
		// Ensures unique VLAN IDs.
		bridgeRefKey = fmt.Sprintf("%s-vlan%d", NetworkBridgeRefPrefix, n.GetVlanId())
	}
	refs = append(refs, LogicalLabelRef{
		ItemType:         (&Bridge{}).ItemType(),
		ItemLogicalLabel: n.GetBridge(),
		RefKey:           bridgeRefKey,
	})
	// References from inside the DHCP config.
	dhcpConfigs := make(map[string]*DHCP)
	if n.GetIpv4().GetDhcp().GetEnable() {
		dhcpConfigs["ipv4"] = n.GetIpv4().GetDhcp()
	}
	if n.GetIpv6().GetDhcp().GetEnable() {
		dhcpConfigs["ipv6"] = n.GetIpv6().GetDhcp()
	}
	for ipversion, dhcpConfig := range dhcpConfigs {
		netKey := fmt.Sprintf("%s-network-%s", ipversion, n.GetLogicalLabel())
		for _, dns := range dhcpConfig.GetDns().GetPrivateDns() {
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Endpoint{}).ItemType(),
				ItemCategory:     (&DNSServer{}).ItemCategory(),
				ItemLogicalLabel: dns,
				// Avoids duplicate DNS servers for the same network.
				RefKey: "dns-for-network-" + netKey,
			})
		}
		if dhcpConfig.GetPrivateNtp() != "" {
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Endpoint{}).ItemType(),
				ItemCategory:     (&NTPServer{}).ItemCategory(),
				ItemLogicalLabel: dhcpConfig.GetPrivateNtp(),
				RefKey:           "ntp-for-network-" + netKey,
			})
		}
		if dhcpConfig.GetNetbootServer() != "" {
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Endpoint{}).ItemType(),
				ItemCategory:     (&NetbootServer{}).ItemCategory(),
				ItemLogicalLabel: dhcpConfig.GetNetbootServer(),
				RefKey:           "netboot-for-network-" + netKey,
			})
		}
	}
	// Routable networks.
	if n.GetRouter() != nil {
		for _, reachEp := range n.GetRouter().GetReachableEndpoints() {
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Endpoint{}).ItemType(),
				ItemLogicalLabel: reachEp,
				RefKey:           "reachable-by-network-" + n.GetLogicalLabel(),
			})
		}
		for _, reachNet := range n.GetRouter().GetReachableNetworks() {
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Network{}).ItemType(),
				ItemLogicalLabel: reachNet,
				RefKey:           "reachable-by-network-" + n.GetLogicalLabel(),
			})
		}
	}
	// Reference to a TransparentProxy.
	if n.GetTransparentProxy() != "" {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Endpoint{}).ItemType(),
			ItemCategory:     (&TransparentProxy{}).ItemCategory(),
			ItemLogicalLabel: n.GetTransparentProxy(),
			RefKey:           "network-tproxy-" + n.GetLogicalLabel(),
		})
	}
	return refs
}

// GetAll : returns all endpoints as one list.
// For every endpoint, it returns only the embedded Endpoint struct.
func (eps *Endpoints) GetAll() (all []*Endpoint) {
	for _, dnsSrv := range eps.GetDnsServers() {
		all = append(all, dnsSrv.GetEndpoint())
	}
	for _, ntpSrv := range eps.GetNtpServers() {
		all = append(all, ntpSrv.GetEndpoint())
	}
	for _, httpSrv := range eps.GetHttpServers() {
		all = append(all, httpSrv.GetEndpoint())
	}
	for _, exProxy := range eps.GetExplicitProxies() {
		all = append(all, exProxy.GetEndpoint())
	}
	for _, tProxy := range eps.GetTransparentProxies() {
		all = append(all, tProxy.GetEndpoint())
	}
	for _, netBootSrv := range eps.GetNetbootServers() {
		all = append(all, netBootSrv.GetEndpoint())
	}
	for _, scepSrv := range eps.GetScepServers() {
		all = append(all, scepSrv.GetEndpoint())
	}
	return all
}

// ItemType is "endpoint".
func (e *Endpoint) ItemType() string {
	return "endpoint"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *Endpoint) ItemLogicalLabel() string {
	return e.LogicalLabel
}

// EndpointBridgeRefPrefix : prefix used for references to bridges from endpoints.
const EndpointBridgeRefPrefix = "bridge-endpoint-"

// ReferencesFromItem can be further extended by endpoint specializations.
func (e *Endpoint) ReferencesFromItem() []LogicalLabelRef {
	var refs []LogicalLabelRef
	if e.GetDirectL2Connect().GetBridge() != "" {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Bridge{}).ItemType(),
			ItemLogicalLabel: e.GetDirectL2Connect().GetBridge(),
			RefKey:           EndpointBridgeRefPrefix + e.GetLogicalLabel(),
		})
	}
	return refs
}

// ItemType just returns the underlying Endpoint item type.
func (e *DNSServer) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "dns-server"
func (e *DNSServer) ItemCategory() string {
	return "dns-server"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *DNSServer) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem returns all endpoints referenced from the DNS server config.
// as well as references of the underlying Endpoint.
func (e *DNSServer) ReferencesFromItem() []LogicalLabelRef {
	refs := e.Endpoint.ReferencesFromItem()
	for i, entry := range e.GetStaticEntries() {
		if entry.GetEndpointFqdnRef() != "" {
			refKey := fmt.Sprintf("dns-server-%s-entry-%d-fqdn",
				e.GetEndpoint().GetLogicalLabel(), i)
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Endpoint{}).ItemType(),
				ItemLogicalLabel: entry.GetEndpointFqdnRef(),
				RefKey:           refKey,
			})
		}
		if entry.GetEndpointIpRef().GetLogicalLabel() != "" {
			refKey := fmt.Sprintf("dns-server-%s-entry-%d-ip",
				e.GetEndpoint().GetLogicalLabel(), i)
			refs = append(refs, LogicalLabelRef{
				ItemType:         (&Endpoint{}).ItemType(),
				ItemLogicalLabel: entry.GetEndpointIpRef().GetLogicalLabel(),
				RefKey:           refKey,
			})
		}
	}
	return refs
}

// ItemType just returns the underlying Endpoint item type.
func (e *HTTPServer) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "http-server"
func (e *HTTPServer) ItemCategory() string {
	return "http-server"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *HTTPServer) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem return all DNS servers referenced from the HTTP server config
// as well as references of the underlying Endpoint.
func (e *HTTPServer) ReferencesFromItem() []LogicalLabelRef {
	refs := e.Endpoint.ReferencesFromItem()
	for _, dns := range e.GetDnsClientConfig().GetPrivateDns() {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Endpoint{}).ItemType(),
			ItemCategory:     (&DNSServer{}).ItemCategory(),
			ItemLogicalLabel: dns,
			// Avoids duplicate DNS servers within the same HTTP server.
			RefKey: "http-server-" + e.GetEndpoint().GetLogicalLabel(),
		})
	}
	return refs
}

// ItemType just returns the underlying Endpoint item type.
func (e *NTPServer) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "ntp-server"
func (e *NTPServer) ItemCategory() string {
	return "ntp-server"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *NTPServer) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem returns references of the underlying Endpoint.
func (e *NTPServer) ReferencesFromItem() []LogicalLabelRef {
	return e.GetEndpoint().ReferencesFromItem()
}

// ItemType just returns the underlying Endpoint item type.
func (e *ExplicitProxy) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "explicit-proxy"
func (e *ExplicitProxy) ItemCategory() string {
	return "explicit-proxy"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *ExplicitProxy) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem return all DNS servers referenced from the proxy config
// as well as references of the underlying Endpoint.
func (e *ExplicitProxy) ReferencesFromItem() []LogicalLabelRef {
	refs := e.Endpoint.ReferencesFromItem()
	for _, dns := range e.GetProxy().GetDnsClientConfig().GetPrivateDns() {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Endpoint{}).ItemType(),
			ItemCategory:     (&DNSServer{}).ItemCategory(),
			ItemLogicalLabel: dns,
			// Avoids duplicate DNS servers within the same explicit proxy.
			RefKey: "explicit-proxy-" + e.GetEndpoint().GetLogicalLabel(),
		})
	}
	return refs
}

// ItemType just returns the underlying Endpoint item type.
func (e *TransparentProxy) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "transparent-proxy"
func (e *TransparentProxy) ItemCategory() string {
	return "transparent-proxy"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *TransparentProxy) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem return all DNS servers referenced from the proxy config
// as well as references of the underlying Endpoint.
func (e *TransparentProxy) ReferencesFromItem() []LogicalLabelRef {
	refs := e.Endpoint.ReferencesFromItem()
	for _, dns := range e.GetProxy().GetDnsClientConfig().GetPrivateDns() {
		refs = append(refs, LogicalLabelRef{
			ItemType:         (&Endpoint{}).ItemType(),
			ItemCategory:     (&DNSServer{}).ItemCategory(),
			ItemLogicalLabel: dns,
			// Avoids duplicate DNS servers within the same transparent proxy.
			RefKey: "transparent-proxy-" + e.GetEndpoint().GetLogicalLabel(),
		})
	}
	return refs
}

// ItemType just returns the underlying Endpoint item type.
func (e *NetbootServer) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "netboot-server"
func (e *NetbootServer) ItemCategory() string {
	return "netboot-server"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *NetbootServer) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem returns references of the underlying Endpoint.
func (e *NetbootServer) ReferencesFromItem() []LogicalLabelRef {
	return e.GetEndpoint().ReferencesFromItem()
}

// ItemType just returns the underlying Endpoint item type.
func (e *SCEPServer) ItemType() string {
	return e.GetEndpoint().ItemType()
}

// ItemCategory is "scep-server"
func (e *SCEPServer) ItemCategory() string {
	return "scep-server"
}

// ItemLogicalLabel returns the logical label of the endpoint.
func (e *SCEPServer) ItemLogicalLabel() string {
	return e.GetEndpoint().ItemLogicalLabel()
}

// ReferencesFromItem returns references of the underlying Endpoint.
func (e *SCEPServer) ReferencesFromItem() []LogicalLabelRef {
	return e.GetEndpoint().ReferencesFromItem()
}
