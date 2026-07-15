// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	log "github.com/sirupsen/logrus"
)

const (
	// Minimum accepted MTU value.
	// As per RFC 8200, the MTU must not be less than 1280 bytes to accommodate IPv6 packets.
	minMTU = 1280
	// Maximum MTU supported by the e1000 driver (can be used for interfaces connecting
	// Evetest-SDN with an EVE device).
	maxMTU = 16110
	// The maximum valid VLAN ID under the IEEE 802.1Q standard.
	maxVLAN = 4094
)

type parsedNetModel struct {
	*api.NetworkModel
	items labeledItems
}

type labeledItems map[itemID]*labeledItem

func (li labeledItems) getItem(typename, logicalLabel string) *labeledItem {
	return li[itemID{
		typename:     typename,
		logicalLabel: logicalLabel,
	}]
}

type itemID struct {
	typename     string
	logicalLabel string
}

type itemRef struct {
	itemID
	refKey string
}

type labeledItem struct {
	api.LabeledItem
	category     string            // empty if not categorized
	referencing  []itemRef         // other items referenced by this item
	referencedBy map[string]itemID // RefKey -> item
}

// Parse and validate network model.
func (a *agent) parseNetModel(netModel *api.NetworkModel) (parsedModel parsedNetModel, err error) {
	parsedModel.NetworkModel = netModel

	// Parse and validate logical labels and their referencing.
	eps := netModel.GetEndpoints()
	items := a.slicesToLabeledItems(netModel.GetPorts(), netModel.GetBonds(),
		netModel.GetBridges(), netModel.GetNetworks(), eps.GetDnsServers(),
		eps.GetNtpServers(), eps.GetNetbootServers(), eps.GetHttpServers(),
		eps.GetExplicitProxies(), eps.GetTransparentProxies(), eps.GetScepServers())
	parsedModel.items, err = a.parseLabeledItems(items)
	if err != nil {
		return
	}

	if err = a.validatePorts(&parsedModel); err != nil {
		return
	}
	if err = a.validateBridges(&parsedModel); err != nil {
		return
	}
	if err = a.validateControllerConfig(&parsedModel); err != nil {
		return
	}
	if err = a.validateNetworks(&parsedModel); err != nil {
		return
	}
	if err = a.validateEndpoints(&parsedModel); err != nil {
		return
	}
	if err = a.validateFirewall(&parsedModel); err != nil {
		return
	}
	return
}

func (a *agent) validatePorts(netModel *parsedNetModel) (err error) {
	// Validate that all ports have valid MAC addresses and that MACs are unique
	// across both EVE and SDN sides.
	macs := make(map[string]struct{})
	for _, port := range netModel.GetPorts() {
		portMACs := []string{port.GetEveMacAddress(), port.GetSdnMacAddress()}
		for _, mac := range portMACs {
			if _, duplicate := macs[mac]; duplicate {
				err = fmt.Errorf("port %s has duplicate MAC address %s",
					port.LogicalLabel, mac)
				return
			}
			macs[mac] = struct{}{}
			var parsedMAC net.HardwareAddr
			parsedMAC, err = net.ParseMAC(port.GetEveMacAddress())
			if err != nil {
				err = fmt.Errorf("port %s has invalid MAC address: %v",
					port.GetLogicalLabel(), err)
				return
			}
			if bytes.HasPrefix(parsedMAC, constants.SDNHostPortMACPrefix) {
				err = fmt.Errorf(
					"port %s has MAC address with prefix reserved for the host port",
					port.GetLogicalLabel())
				return
			}
		}
	}

	// QueueLimit and BurstLimit are mandatory when RateLimit is set.
	for _, port := range netModel.GetPorts() {
		if port.GetTrafficControl().GetRateLimit() != 0 {
			if port.GetTrafficControl().GetQueueLimit() == 0 {
				err = fmt.Errorf("RateLimit set for port %s without QueueLimit",
					port.GetLogicalLabel())
				return
			}
			if port.GetTrafficControl().GetBurstLimit() == 0 {
				err = fmt.Errorf("RateLimit set for port %s without BurstLimit",
					port.GetLogicalLabel())
				return
			}
		}
	}
	return nil
}

func (a *agent) validateBridges(netModel *parsedNetModel) (err error) {
	for _, bridge := range netModel.GetBridges() {
		pnac := bridge.GetPnac()
		if pnac == nil || !pnac.GetEnable_8021X() {
			continue
		}
		for _, eapUser := range pnac.GetUsers() {
			if eapUser.GetIdentity() == "" {
				err = fmt.Errorf("missing EAP user identity for bridge %s PNAC",
					bridge.GetLogicalLabel())
				return
			}
			if len(eapUser.GetMethods()) == 0 {
				err = fmt.Errorf("missing EAP user method for bridge %s PNAC",
					bridge.GetLogicalLabel())
				return
			}
			for _, method := range eapUser.GetMethods() {
				switch method {
				case api.EAPMethod_EAP_METHOD_PEAP,
					api.EAPMethod_EAP_METHOD_TTLS,
					api.EAPMethod_EAP_METHOD_MD5:
					if eapUser.GetPassword() == "" {
						err = fmt.Errorf("missing EAP user password for bridge %s PNAC",
							bridge.GetLogicalLabel())
						return
					}
				}
			}
		}
		if pnac.GetPreAuthVlanId() != 0 && pnac.GetPreAuthVlanId() > maxVLAN {
			err = fmt.Errorf("pre-authorization VLAN ID %d configured for bridge %s "+
				"PNAC is too large", pnac.GetPreAuthVlanId(), bridge.GetLogicalLabel())
			return
		}
		if pnac.GetPostAuthVlanId() != 0 && pnac.GetPostAuthVlanId() > maxVLAN {
			err = fmt.Errorf("post-authorization VLAN ID %d configured for bridge %s "+
				"PNAC is too large", pnac.GetPostAuthVlanId(), bridge.GetLogicalLabel())
			return
		}
		if pnac.GetCaCertPem() != "" {
			cert, key := pnac.GetCaCertPem(), pnac.GetCaKeyPem()
			if err = a.validateCertPEM(cert, key, true); err != nil {
				return
			}
		} else {
			err = fmt.Errorf("bridge %s has PNAC configuration without certificate",
				bridge.GetLogicalLabel())
			return
		}
	}
	return nil
}

func (a *agent) validateNetworks(netModel *parsedNetModel) (err error) {
	// Validate network IP config.
	for _, network := range netModel.GetNetworks() {
		if network.GetIpv4().GetSubnet() != "" {
			err = a.validateNetworkIPConfig(network.GetLogicalLabel(), network.GetIpv4(),
				true, false)
			if err != nil {
				return
			}
		}
		if network.GetIpv6().GetSubnet() != "" {
			err = a.validateNetworkIPConfig(network.GetLogicalLabel(), network.GetIpv6(),
				false, true)
			if err != nil {
				return
			}
		}
	}

	// Validate routes towards EVE.
	for _, network := range netModel.GetNetworks() {
		if network.GetRouter() == nil {
			continue
		}
		// Subnets are already validated.
		var subnet1, subnet2 *net.IPNet
		if network.GetIpv4().GetSubnet() != "" {
			_, subnet1, _ = net.ParseCIDR(network.GetIpv4().GetSubnet())
		}
		if network.GetIpv6().GetSubnet() != "" {
			_, subnet2, _ = net.ParseCIDR(network.GetIpv6().GetSubnet())
		}
		for _, route := range network.GetRouter().GetRoutesTowardsEve() {
			if _, _, err = net.ParseCIDR(route.GetDstNetwork()); err != nil {
				err = fmt.Errorf("network %s route %+v has invalid destination: %w",
					network.GetLogicalLabel(), route, err)
				return
			}
			gwIP := net.ParseIP(route.GetGateway())
			if gwIP == nil {
				err = fmt.Errorf("network %s route %+v has invalid gateway IP (%s)",
					network.GetLogicalLabel(), route, route.GetGateway())
				return
			}
			routable := (subnet1 != nil && subnet1.Contains(gwIP)) ||
				(subnet2 != nil && subnet2.Contains(gwIP))
			if !routable {
				err = fmt.Errorf("network %s route %+v has gateway IP (%s) "+
					"which is not from within the network subnet(s)",
					network.GetLogicalLabel(), route, route.GetGateway())
				return
			}
		}
	}

	// Validate MTU settings.
	for _, network := range netModel.GetNetworks() {
		if network.GetMtu() != 0 && network.GetMtu() < minMTU {
			err = fmt.Errorf("MTU %d configured for network %s is too small",
				network.GetMtu(), network.GetLogicalLabel())
			return
		}
		if network.GetMtu() > maxMTU {
			err = fmt.Errorf("MTU %d configured for network %s is too large",
				network.GetMtu(), network.GetLogicalLabel())
			return
		}
	}

	// Validate VLAN settings.
	for _, network := range netModel.GetNetworks() {
		if network.GetVlanId() != 0 && network.GetVlanId() > maxVLAN {
			err = fmt.Errorf("VLAN ID %d configured for network %s is too large",
				network.GetVlanId(), network.GetLogicalLabel())
			return
		}
	}
	return nil
}

func (a *agent) validateNetworkIPConfig(netLabel string, netIPConf *api.NetworkIPConfig,
	shouldBeIPv4, shouldBeIPv6 bool) error {
	// Validate network Subnet and gateway IP.
	_, subnet, err := net.ParseCIDR(netIPConf.GetSubnet())
	if err != nil {
		return fmt.Errorf("network %s has invalid subnet: %w", netLabel, err)
	}
	if shouldBeIPv4 && subnet.IP.To4() == nil {
		return fmt.Errorf("expected IPv4 subnet for network %s, got: %v",
			netLabel, subnet)
	}
	if shouldBeIPv6 && subnet.IP.To4() != nil {
		return fmt.Errorf("expected IPv6 subnet for network %s, got: %v",
			netLabel, subnet)
	}
	if subnet.IP.To4() == nil {
		ones, _ := subnet.Mask.Size()
		if ones < 64 {
			return fmt.Errorf("IPv6 subnet for network %s must be at least /64, got /%d",
				netLabel, ones)
		}
	}
	// Make sure that remaining fields have the same IP version as Subnet.
	shouldBeIPv4 = subnet.IP.To4() != nil
	shouldBeIPv6 = subnet.IP.To4() == nil
	gwIP := net.ParseIP(netIPConf.GetGwIp())
	if gwIP == nil {
		return fmt.Errorf("network %s has invalid gateway IP (%s)",
			netLabel, netIPConf.GetGwIp())
	}
	// This also checks that gwIP has the correct IP version.
	if !subnet.Contains(gwIP) {
		return fmt.Errorf(
			"network %s has gateway IP (%s) which is not inside the subnet (%s)",
			netLabel, netIPConf.GetGwIp(), netIPConf.GetSubnet())
	}

	// Validate DHCP config.
	dhcp := netIPConf.GetDhcp()
	if !dhcp.GetEnable() {
		return nil
	}
	if dhcp.GetIpRange().GetFromIp() != "" {
		fromIP := net.ParseIP(dhcp.GetIpRange().GetFromIp())
		if fromIP == nil {
			return fmt.Errorf("network %s has invalid DHCP range FromIP (%s)",
				netLabel, dhcp.GetIpRange().GetFromIp())
		}
		toIP := net.ParseIP(dhcp.GetIpRange().GetToIp())
		if toIP == nil {
			return fmt.Errorf("network %s has invalid DHCP range ToIP (%s)",
				netLabel, dhcp.GetIpRange().GetToIp())
		}
		// This also checks that fromIP and toIP have the correct IP version.
		if !subnet.Contains(fromIP) || !subnet.Contains(toIP) {
			return fmt.Errorf("network %s has DHCP IP range outside of the subnet",
				netLabel)
		}
		if bytes.Compare(fromIP, toIP) > 0 {
			return fmt.Errorf("network %s has DHCP IP range where FromIP > ToIP",
				netLabel)
		}
	}
	for _, dns := range dhcp.GetDns().GetPublicDns() {
		dnsIP := net.ParseIP(dns)
		if dnsIP == nil {
			return fmt.Errorf("network %s has invalid public DNS server IP (%s)",
				netLabel, dns)
		}
		if shouldBeIPv4 && dnsIP.To4() == nil {
			return fmt.Errorf("expected IPv4 DNS server address for network %s, got: %v",
				netLabel, dnsIP)
		}
		if shouldBeIPv6 && dnsIP.To4() != nil {
			return fmt.Errorf("expected IPv6 DNS server address for network %s, got: %v",
				netLabel, dnsIP)
		}
	}
	if dhcp.GetPrivateNtp() != "" && dhcp.GetPublicNtp() != "" {
		return fmt.Errorf("network %s has both public and private NTP configured",
			netLabel)
	}
	for _, entry := range dhcp.GetStaticEntries() {
		if _, err = net.ParseMAC(entry.GetMac()); err != nil {
			return fmt.Errorf("network %s has static DHCP entry with invalid MAC (%s)",
				netLabel, entry.GetMac())
		}
		ip := net.ParseIP(entry.GetIp())
		if ip == nil {
			return fmt.Errorf("network %s has static DHCP entry with invalid IP (%s)",
				netLabel, entry.GetIp())
		}
		if shouldBeIPv4 && ip.To4() == nil {
			return fmt.Errorf("expected IPv4 static DHCP entry for network %s, got: %v",
				netLabel, ip)
		}
		if shouldBeIPv6 && ip.To4() != nil {
			return fmt.Errorf("expected IPv6 static DHCP entry for network %s, got: %v",
				netLabel, ip)
		}
	}
	if shouldBeIPv6 && dhcp.GetWpad() != "" {
		return fmt.Errorf(
			"network %s configured with WPAD URL (%s) which is not supported for IPv6",
			netLabel, dhcp.GetWpad())
	}
	return nil
}

func (a *agent) validateEndpoints(netModel *parsedNetModel) (err error) {
	//nolint:godox
	// TODO: NetbootArtifacts
	for _, dnsSrv := range netModel.GetEndpoints().GetDnsServers() {
		if err = a.validateEndpoint(dnsSrv.GetEndpoint()); err != nil {
			return
		}
		for _, upstreamSrv := range dnsSrv.GetUpstreamServers() {
			if ip := net.ParseIP(upstreamSrv); ip == nil {
				err = fmt.Errorf("DNS server %s has invalid upstream server IP (%s)",
					dnsSrv.GetEndpoint().GetLogicalLabel(), upstreamSrv)
				return
			}
		}
		for _, entry := range dnsSrv.GetStaticEntries() {
			if entry.GetFqdnLiteral() == "" && entry.GetEndpointFqdnRef() == "" {
				err = fmt.Errorf("DNS server %s has static entry with empty FQDN",
					dnsSrv.GetEndpoint().GetLogicalLabel())
				return
			}
			if entry.GetIpLiteral() != "" {
				if ip := net.ParseIP(entry.GetIpLiteral()); ip == nil {
					err = fmt.Errorf("DNS server %s has invalid static entry IP (%s)",
						dnsSrv.GetEndpoint().GetLogicalLabel(), entry.GetIpLiteral())
					return
				}
			}
		}
	}
	for _, proxy := range netModel.GetEndpoints().GetExplicitProxies() {
		if err = a.validateEndpoint(proxy.GetEndpoint()); err != nil {
			return
		}
		for _, dns := range proxy.GetProxy().GetDnsClientConfig().GetPublicDns() {
			if dnsIP := net.ParseIP(dns); dnsIP == nil {
				err = fmt.Errorf("proxy %s has invalid public DNS server IP (%s)",
					proxy.GetEndpoint().GetLogicalLabel(), dns)
				return
			}
		}
		if proxy.GetHttpProxy().GetPort() == 0 && proxy.GetHttpsProxy().GetPort() == 0 {
			err = fmt.Errorf("proxy %s without port numbers",
				proxy.GetEndpoint().GetLogicalLabel())
			return
		}
		if proxy.GetHttpProxy().GetPort() != 0 && proxy.GetHttpsProxy().GetPort() != 0 {
			if proxy.GetHttpProxy().GetPort() == proxy.GetHttpsProxy().GetPort() {
				err = fmt.Errorf("proxy %s with colliding ports",
					proxy.GetEndpoint().GetLogicalLabel())
				return
			}
		}
		for _, user := range proxy.GetUsers() {
			if user.GetUsername() == "" {
				err = fmt.Errorf("proxy %s with empty username",
					proxy.GetEndpoint().GetLogicalLabel())
				return
			}
		}
		if proxy.GetProxy().GetCaCertPem() != "" {
			caCert := proxy.GetProxy().GetCaCertPem()
			caKey := proxy.GetProxy().GetCaKeyPem()
			if err = a.validateCertPEM(caCert, caKey, true); err != nil {
				return
			}
		}
		ruleHosts := make(map[string]struct{})
		for _, rule := range proxy.GetProxy().GetProxyRules() {
			if _, duplicate := ruleHosts[rule.GetReqHost()]; duplicate {
				err = fmt.Errorf("proxy %s has duplicate rules",
					proxy.GetEndpoint().GetLogicalLabel())
				return
			}
			ruleHosts[rule.ReqHost] = struct{}{}
		}
	}
	for _, proxy := range netModel.GetEndpoints().GetTransparentProxies() {
		if err = a.validateEndpoint(proxy.GetEndpoint()); err != nil {
			return
		}
		for _, dns := range proxy.GetProxy().GetDnsClientConfig().GetPublicDns() {
			if dnsIP := net.ParseIP(dns); dnsIP == nil {
				err = fmt.Errorf("proxy %s has invalid public DNS server IP (%s)",
					proxy.GetEndpoint().GetLogicalLabel(), dns)
				return
			}
		}
		if proxy.GetProxy().GetCaCertPem() != "" {
			caCert := proxy.GetProxy().GetCaCertPem()
			caKey := proxy.GetProxy().GetCaKeyPem()
			if err = a.validateCertPEM(caCert, caKey, true); err != nil {
				return
			}
		}
		ruleHosts := make(map[string]struct{})
		for _, rule := range proxy.GetProxy().GetProxyRules() {
			if _, duplicate := ruleHosts[rule.GetReqHost()]; duplicate {
				err = fmt.Errorf("proxy %s has duplicate rules",
					proxy.GetEndpoint().GetLogicalLabel())
				return
			}
			ruleHosts[rule.GetReqHost()] = struct{}{}
		}
	}
	for _, httpSrv := range netModel.GetEndpoints().GetHttpServers() {
		if err = a.validateEndpoint(httpSrv.GetEndpoint()); err != nil {
			return
		}
		if httpSrv.GetHttpPort() == 0 && httpSrv.GetHttpsPort() == 0 {
			err = fmt.Errorf("HTTP server %s without port numbers",
				httpSrv.GetEndpoint().GetLogicalLabel())
			return
		}
		if httpSrv.GetHttpPort() != 0 && httpSrv.GetHttpsPort() != 0 {
			if httpSrv.GetHttpPort() == httpSrv.GetHttpsPort() {
				err = fmt.Errorf("HTTP server %s with colliding ports",
					httpSrv.GetEndpoint().GetLogicalLabel())
				return
			}
		}
		if httpSrv.GetCertPem() != "" {
			cert, key := httpSrv.GetCertPem(), httpSrv.GetKeyPem()
			if err = a.validateCertPEM(cert, key, false); err != nil {
				return
			}
		} else if httpSrv.GetHttpsPort() != 0 {
			err = fmt.Errorf("HTTPS server %s without certificate",
				httpSrv.GetEndpoint().GetLogicalLabel())
			return
		}
	}
	for _, netbootSrv := range netModel.GetEndpoints().GetNetbootServers() {
		if err = a.validateEndpoint(netbootSrv.GetEndpoint()); err != nil {
			return
		}
	}
	for _, ntpSrv := range netModel.GetEndpoints().GetNtpServers() {
		if err = a.validateEndpoint(ntpSrv.GetEndpoint()); err != nil {
			return
		}
	}
	for _, scepSrv := range netModel.GetEndpoints().GetScepServers() {
		if err = a.validateEndpoint(scepSrv.GetEndpoint()); err != nil {
			return
		}
		if scepSrv.GetCaCertPem() != "" {
			cert, key := scepSrv.GetCaCertPem(), scepSrv.GetCaKeyPem()
			if err = a.validateCertPEM(cert, key, true); err != nil {
				return
			}
		} else {
			err = fmt.Errorf("SCEP server %s without certificate",
				scepSrv.GetEndpoint().GetLogicalLabel())
			return
		}
	}
	return nil
}

func (a *agent) validateEndpoint(endpoint *api.Endpoint) (err error) {
	err = a.validateEndpointIPConfig(endpoint.GetLogicalLabel(), endpoint.GetIpv4(),
		true, false)
	if err != nil {
		return
	}
	err = a.validateEndpointIPConfig(endpoint.GetLogicalLabel(), endpoint.GetIpv6(),
		false, true)
	if err != nil {
		return
	}
	// Validate MTU settings.
	if endpoint.GetMtu() != 0 && endpoint.GetMtu() < minMTU {
		return fmt.Errorf("MTU %d configured for endpoint %s is too small",
			endpoint.GetMtu(), endpoint.GetLogicalLabel())
	}
	if endpoint.GetMtu() > maxMTU {
		return fmt.Errorf("MTU %d configured for endpoint %s is too large",
			endpoint.GetMtu(), endpoint.GetLogicalLabel())
	}
	return nil
}

func (a *agent) validateEndpointIPConfig(epLabel string, epIPConf *api.EndpointIPConfig,
	shouldBeIPv4, shouldBeIPv6 bool) error {
	if epIPConf.GetSubnet() == "" {
		// L2-only endpoint.
		return nil
	}
	_, subnet, err := net.ParseCIDR(epIPConf.GetSubnet())
	if err != nil {
		return fmt.Errorf("endpoint %s with invalid subnet '%s': %w",
			epLabel, epIPConf.GetSubnet(), err)
	}
	if shouldBeIPv4 && subnet.IP.To4() == nil {
		return fmt.Errorf("expected IPv4 subnet for endpoint %s, got: %v",
			epLabel, subnet)
	}
	if shouldBeIPv6 && subnet.IP.To4() != nil {
		return fmt.Errorf("expected IPv6 subnet for endpoint %s, got: %v",
			epLabel, subnet)
	}
	ones, bits := subnet.Mask.Size()
	if bits-ones < 2 {
		return fmt.Errorf("endpoint %s uses subnet with less than 2 host IPs (%s)",
			epLabel, epIPConf.Subnet)
	}
	if subnet.IP.To4() == nil {
		if ones < 64 {
			return fmt.Errorf("IPv6 subnet for endpoint %s must be at least /64, got /%d",
				epLabel, ones)
		}
	}
	// Validate IP address.
	ip := net.ParseIP(epIPConf.GetIp())
	if ip == nil {
		return fmt.Errorf("endpoint %s with invalid IP address (%s)",
			epLabel, epIPConf.GetIp())
	}
	// This also checks that endpoint IP has the correct IP version.
	if !subnet.Contains(ip) {
		return fmt.Errorf("endpoint %s has IP (%s) address outside of the configured "+
			"subnet (%s)", epLabel, epIPConf.GetIp(), epIPConf.GetSubnet())
	}
	return nil
}

func (a *agent) validateFirewall(netModel *parsedNetModel) (err error) {
	for _, rule := range netModel.GetFirewall().GetRules() {
		if rule.GetSrcSubnet() != "" {
			if _, _, err = net.ParseCIDR(rule.GetSrcSubnet()); err != nil {
				err = fmt.Errorf("firewall rule with invalid subnet '%s': %w",
					rule.GetSrcSubnet(), err)
				return
			}
		}
		if rule.GetDstSubnet() != "" {
			if _, _, err = net.ParseCIDR(rule.GetDstSubnet()); err != nil {
				err = fmt.Errorf("firewall rule with invalid subnet '%s': %w",
					rule.GetDstSubnet(), err)
				return
			}
		}
		if len(rule.GetPorts()) > 0 {
			if rule.GetProtocol() != api.FwProto_TCP &&
				rule.GetProtocol() != api.FwProto_UDP {
				err = fmt.Errorf("firewall rule with non-empty set of ports (%v) "+
					" but protocol is neither TCP nor UDP (%v)", rule.Ports, rule.Protocol)
				return
			}
		}
	}
	return nil
}

func (a *agent) validateControllerConfig(netModel *parsedNetModel) (err error) {
	if netModel.GetControllerConfig().GetControllerPort() == 0 {
		err = errors.New("missing controller port")
		return
	}
	return nil
}

func (a *agent) validateCertPEM(certPem, keyPem string, isCA bool) error {
	// Check that certificate can be parsed.
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return errors.New("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PEM certificate: %v", err)
	}
	if isCA != cert.IsCA {
		return fmt.Errorf("invalid certificate purpose (IsCA=%t)", cert.IsCA)
	}
	// Check that private key can be parsed.
	block, _ = pem.Decode([]byte(keyPem))
	if block == nil {
		return errors.New("failed to decode PEM private key")
	}
	privateKey, err := a.parsePrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	// Check that the public key and the private key correspond with each other.
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if pub.N.Cmp(rsaKey.N) != 0 {
			return errors.New("private key does not match public key")
		}
	case *ecdsa.PublicKey:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if pub.X.Cmp(ecdsaKey.X) != 0 || pub.Y.Cmp(ecdsaKey.Y) != 0 {
			return errors.New("private key does not match public key")
		}
	case ed25519.PublicKey:
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return errors.New("private key type does not match public key type")
		}
		if !bytes.Equal(ed25519Key.Public().(ed25519.PublicKey), pub) {
			return errors.New("private key does not match public key")
		}
	default:
		return errors.New("unknown public key algorithm")
	}
	return nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func (a *agent) parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func (a *agent) parseLabeledItems(items []api.LabeledItem) (labeledItems, error) {
	parsedItems := make(labeledItems)
	for _, item := range items {
		id := itemID{
			typename:     item.ItemType(),
			logicalLabel: item.ItemLogicalLabel(),
		}
		if _, duplicate := parsedItems[id]; duplicate {
			return nil, fmt.Errorf("duplicate logical label: %s/%s",
				id.typename, id.logicalLabel)
		}
		var category string
		if categItem, withCategory := item.(api.LabeledItemWithCategory); withCategory {
			category = categItem.ItemCategory()
		}
		parsedItems[id] = &labeledItem{
			LabeledItem:  item,
			category:     category,
			referencedBy: make(map[string]itemID),
		}
	}
	for _, item := range items {
		id := itemID{
			typename:     item.ItemType(),
			logicalLabel: item.ItemLogicalLabel(),
		}
		for _, ref := range item.ReferencesFromItem() {
			refID := itemID{
				typename:     ref.ItemType,
				logicalLabel: ref.ItemLogicalLabel,
			}
			refItem, exists := parsedItems[refID]
			if !exists {
				return nil, fmt.Errorf("referenced item %s/%s does not exist "+
					"(ref-key: %s)", refID.typename, refID.logicalLabel, ref.RefKey)
			}
			if ref.ItemCategory != "" {
				if refItem.category != ref.ItemCategory {
					return nil, fmt.Errorf("category mismatch for referenced item %s/%s "+
						"(expected %s, has %s)", refID.typename, refID.logicalLabel,
						ref.ItemCategory, refItem.category)
				}
			}
			_, collision := refItem.referencedBy[ref.RefKey]
			if collision {
				return nil, fmt.Errorf("colliding referencing to logical label: %s/%s "+
					"(ref-key: %s)", refID.typename, refID.logicalLabel, ref.RefKey)
			}
			refItem.referencedBy[ref.RefKey] = id
			parsedItems[id].referencing = append(parsedItems[id].referencing, itemRef{
				itemID: refID,
				refKey: ref.RefKey,
			})
		}
	}
	return parsedItems, nil
}

func (a *agent) slicesToLabeledItems(slices ...interface{}) (items []api.LabeledItem) {
	for _, slice := range slices {
		rv := reflect.ValueOf(slice)
		for i := 0; i < rv.Len(); i++ {
			item := rv.Index(i)
			if labeledItem, ok := item.Interface().(api.LabeledItem); ok {
				items = append(items, labeledItem)
			} else {
				log.Warnf("Not an instance of labeled item: %+v", item)
			}
		}
	}
	return items
}
