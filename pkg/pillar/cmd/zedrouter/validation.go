// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
)

func (z *zedrouter) doNetworkInstanceSanityCheck(config *types.NetworkInstanceConfig) error {
	z.log.Functionf("Sanity Checking NetworkInstance(%s-%s): type:%d, IpType:%d",
		config.DisplayName, config.UUID, config.Type, config.IpType)

	//  Check NetworkInstanceType
	switch config.Type {
	case types.NetworkInstanceTypeLocal:
		// Do nothing
	case types.NetworkInstanceTypeSwitch:
		// Do nothing
	default:
		return fmt.Errorf("network instance type %d is not supported", config.Type)
	}

	// IpType - Check for valid types
	switch config.IpType {
	case types.AddressTypeNone:
		// Do nothing
	case types.AddressTypeIPV4, types.AddressTypeIPV6,
		types.AddressTypeCryptoIPV4, types.AddressTypeCryptoIPV6:
		err := z.doNetworkInstanceSubnetSanityCheck(config)
		if err != nil {
			return err
		}
		err = z.doNetworkInstanceDhcpRangeSanityCheck(config)
		if err != nil {
			return err
		}
		err = z.doNetworkInstanceGatewaySanityCheck(config)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("IpType %d not supported", config.IpType)
	}
	return nil
}

func (z *zedrouter) doNetworkInstanceSubnetSanityCheck(
	config *types.NetworkInstanceConfig) error {
	if config.Subnet.IP == nil || config.Subnet.IP.IsUnspecified() {
		return fmt.Errorf("subnet unspecified for %s-%s: %+v",
			config.Key(), config.DisplayName, config.Subnet)
	}
	return nil
}

func (z *zedrouter) doNetworkInstanceDhcpRangeSanityCheck(
	config *types.NetworkInstanceConfig) error {
	if config.DhcpRange.Start == nil || config.DhcpRange.Start.IsUnspecified() {
		return fmt.Errorf("DhcpRange Start Unspecified: %+v",
			config.DhcpRange.Start)
	}
	if !config.Subnet.Contains(config.DhcpRange.Start) {
		return fmt.Errorf("DhcpRange Start(%s) not within Subnet(%s)",
			config.DhcpRange.Start.String(), config.Subnet.String())
	}
	if config.DhcpRange.End == nil || config.DhcpRange.End.IsUnspecified() {
		return fmt.Errorf("DhcpRange End Unspecified: %+v",
			config.DhcpRange.Start)
	}
	if !config.Subnet.Contains(config.DhcpRange.End) {
		return fmt.Errorf("DhcpRange End(%s) not within Subnet(%s)",
			config.DhcpRange.End.String(), config.Subnet.String())
	}
	return nil
}

func (z *zedrouter) doNetworkInstanceGatewaySanityCheck(
	config *types.NetworkInstanceConfig) error {
	if config.Gateway == nil || config.Gateway.IsUnspecified() {
		return fmt.Errorf("gateway is not specified: %+v",
			config.Gateway)
	}
	if !config.Subnet.Contains(config.Gateway) {
		return fmt.Errorf("gateway(%s) not within Subnet(%s)",
			config.Gateway.String(), config.Subnet.String())
	}
	if config.DhcpRange.Contains(config.Gateway) {
		return fmt.Errorf("gateway(%s) is in DHCP Range(%v,%v)",
			config.Gateway, config.DhcpRange.Start,
			config.DhcpRange.End)
	}
	return nil
}

func (z *zedrouter) checkNetworkInstanceIPConflicts(
	config *types.NetworkInstanceConfig) error {
	// Check for overlapping subnets between NIs.
	items := z.subNetworkInstanceConfig.GetAll()
	for key2, config2 := range items {
		niConfig2 := config2.(types.NetworkInstanceConfig)
		if config.Key() == key2 {
			continue
		}
		if netutils.OverlappingSubnets(&config.Subnet, &niConfig2.Subnet) {
			return fmt.Errorf("subnet (%s) overlaps with another "+
				"network instance (%s-%s) subnet (%s)",
				config.Subnet.String(), niConfig2.DisplayName, niConfig2.UUID,
				niConfig2.Subnet.String())
		}
	}
	// Check for overlapping subnets between the NI and device ports.
	for _, port := range z.deviceNetworkStatus.Ports {
		if netutils.OverlappingSubnets(&config.Subnet, &port.Subnet) {
			return fmt.Errorf("subnet (%s) overlaps with device port %s "+
				"subnet (%s)", config.Subnet.String(), port.Logicallabel,
				port.Subnet.String())
		}
	}
	return nil
}

func (z *zedrouter) checkNetworkInstanceMTUConflicts(config types.NetworkInstanceConfig,
	status *types.NetworkInstanceStatus) (fallbackMTU uint16, err error) {
	uplink := z.getNIUplinkConfig(status)
	if uplink.LogicalLabel == "" {
		// Air-gapped
		return 0, nil
	}
	if uplink.MTU == 0 {
		// Not yet known?
		z.log.Warnf("Missing MTU for uplink port %s", uplink.LogicalLabel)
		return 0, nil
	}
	niMTU := config.MTU
	if niMTU == 0 {
		niMTU = types.DefaultMTU
	}
	if niMTU != uplink.MTU {
		return uplink.MTU, fmt.Errorf("MTU (%d) configured for the network instance "+
			"differs from the MTU (%d) of the associated port %s. "+
			"Will use port's MTU instead.",
			niMTU, uplink.MTU, uplink.LogicalLabel)
	}
	return 0, nil
}

func (z *zedrouter) validateAppNetworkConfig(appNetConfig types.AppNetworkConfig) error {
	z.log.Functionf("AppNetwork(%s), check for duplicate port map acls",
		appNetConfig.DisplayName)
	// For App Networks, check for common port map rules
	adapterCfgList1 := appNetConfig.AppNetAdapterList
	if len(adapterCfgList1) == 0 {
		return nil
	}
	if z.containsHangingACLPortMapRule(adapterCfgList1) {
		return fmt.Errorf("network with no uplink, has portmap")
	}
	sub := z.subAppNetworkConfig
	items := sub.GetAll()
	for _, c := range items {
		appNetConfig2 := c.(types.AppNetworkConfig)
		adapterCfgList2 := appNetConfig2.AppNetAdapterList
		if len(adapterCfgList2) == 0 {
			continue
		}
		if appNetConfig.DisplayName == appNetConfig2.DisplayName {
			continue
		}
		appNetStatus2 := z.lookupAppNetworkStatus(appNetConfig2.Key())
		if appNetStatus2 == nil {
			continue
		}
		if appNetStatus2.HasError() || !appNetStatus2.Activated {
			continue
		}
		if z.checkForPortMapOverlap(adapterCfgList1, adapterCfgList2) {
			return fmt.Errorf("app %s and %s have duplicate portmaps",
				appNetConfig.DisplayName, appNetStatus2.DisplayName)
		}
	}
	return nil
}

func (z *zedrouter) validateAppNetworkConfigForModify(
	newConfig types.AppNetworkConfig, oldConfig types.AppNetworkConfig) error {
	// XXX What about changing the number of interfaces as part of an inactive/active
	// transition?
	// XXX We could allow the addition of interfaces if the domU would find out through
	// some hotplug event.
	// But deletion is hard.
	// For now don't allow any adds or deletes.
	if len(newConfig.AppNetAdapterList) != len(oldConfig.AppNetAdapterList) {
		return fmt.Errorf("changing number of AppNetAdapters (for %s) is unsupported",
			newConfig.UUIDandVersion)
	}
	return z.validateAppNetworkConfig(newConfig)
}

func (z *zedrouter) checkNetworkReferencesFromApp(config types.AppNetworkConfig) (
	netInErrState bool, err error) {
	// Check AppNetAdapters for the existence of the network instances
	// XXX - Should we also check for Network(instance)Status objects here itself?
	for _, adapterConfig := range config.AppNetAdapterList {
		netInstStatus := z.lookupNetworkInstanceStatus(adapterConfig.Network.String())
		if netInstStatus == nil {
			err := fmt.Errorf("missing network instance %s for app %s/%s",
				adapterConfig.Network.String(), config.UUIDandVersion, config.DisplayName)
			z.log.Error(err)
			// App network configuration that has AppNetAdapters pointing to non-existent
			// network instances is invalid. Such configuration should never come to
			// device from cloud.
			// But, on the device sometimes, zedrouter sees the app network configuration
			// before seeing the required network instance configuration. This is transient
			// and zedrouter re-creates the app network when the corresponding network
			// instance configuration finally arrives.
			// In such cases it is less confusing to put the app network in network wait
			// state rather than in error state.
			// We use the AwaitNetworkInstance in AppNetworkStatus that is already present.
			return false, err
		}
		if netInstStatus.HasError() && !netInstStatus.EligibleForActivate() {
			err := fmt.Errorf(
				"network instance %s needed by app %s/%s is in error state: %s",
				adapterConfig.Network.String(), config.UUIDandVersion, config.DisplayName,
				netInstStatus.Error)
			z.log.Error(err)
			return true, err
		}
		if !netInstStatus.Activated {
			err := fmt.Errorf("network instance %s needed by app %s/%s is not activated",
				adapterConfig.Network.String(), config.UUIDandVersion, config.DisplayName)
			z.log.Error(err)
			return false, err
		}
	}
	return false, nil
}

// Check if there is a portmap rule for a network instance with no uplink interface.
func (z *zedrouter) containsHangingACLPortMapRule(
	adapterCfgList []types.AppNetAdapterConfig) bool {
	for _, adapterCfg := range adapterCfgList {
		network := adapterCfg.Network.String()
		netInstStatus := z.lookupNetworkInstanceStatus(network)
		if netInstStatus == nil || netInstStatus.PortLogicalLabel != "" {
			continue
		}
		for _, ace := range adapterCfg.ACLs {
			for _, action := range ace.Actions {
				if action.PortMap {
					return true
				}
			}
		}
	}
	return false
}

func (z *zedrouter) checkForPortMapOverlap(adapterCfgList1 []types.AppNetAdapterConfig,
	adapterCfgList2 []types.AppNetAdapterConfig) bool {
	for _, adapterCfg1 := range adapterCfgList1 {
		network1 := adapterCfg1.Network
		// Validate whether there are duplicate portmap rules within itself.
		if z.detectPortMapConflictWithinAdapter(adapterCfg1.ACLs) {
			return true
		}
		for _, adapterCfg2 := range adapterCfgList2 {
			network2 := adapterCfg2.Network
			if network1 == network2 || z.checkUplinkPortOverlap(network1, network2) {
				if z.detectPortMapConflictAcrossAdapters(adapterCfg1.ACLs, adapterCfg2.ACLs) {
					return true
				}
			}
		}
	}
	return false
}

// Check if network instances are sharing common uplink.
func (z *zedrouter) checkUplinkPortOverlap(network1, network2 uuid.UUID) bool {
	netInstStatus1 := z.lookupNetworkInstanceStatus(network1.String())
	netInstStatus2 := z.lookupNetworkInstanceStatus(network2.String())
	if netInstStatus1 == nil || netInstStatus2 == nil {
		return false
	}
	return netInstStatus1.SelectedUplinkIntfName == netInstStatus2.SelectedUplinkIntfName
}

// Caller should clear the appropriate status.Pending* if the caller will
// return after adding the error.
func (z *zedrouter) addAppNetworkError(status *types.AppNetworkStatus,
	tag string, err error) (changed bool) {
	z.log.Errorf("%s: %v", tag, err)
	// XXX The use of appendError() could be more normalized
	status.Error, changed = appendError(status.Error, tag, err.Error())
	status.ErrorTime = time.Now()
	if changed {
		z.publishAppNetworkStatus(status)
	}
	return changed
}

func appendError(allErrors string, prefix string, lasterr string) (
	newError string, changed bool) {
	if strings.Contains(allErrors, lasterr) {
		// Avoid duplicate errors.
		return allErrors, false
	}
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr), true
}

func (z *zedrouter) detectPortMapConflictWithinAdapter(ACLs []types.ACE) bool {
	matchTypes1 := []string{"protocol"}
	matchTypes2 := []string{"protocol", "lport"}
	idx1 := 0
	ruleNum := len(ACLs)
	for idx1 < ruleNum-1 {
		ace1 := ACLs[idx1]
		for _, action := range ace1.Actions {
			if !action.PortMap {
				continue
			}
			idx2 := idx1 + 1
			for idx2 < ruleNum {
				ace2 := ACLs[idx2]
				for _, action1 := range ace2.Actions {
					if !action1.PortMap {
						continue
					}
					// check for protocol/TargetPort
					if action.TargetPort == action1.TargetPort &&
						z.matchACEs(ace1, ace2, matchTypes1) {
						z.log.Errorf("Port-map match found for %d %d: ace1 %v ace2 %v",
							idx1, idx2, ace1, ace2)
						return true
					}
					// check for protocol/lport
					if z.matchACEs(ace1, ace2, matchTypes2) {
						z.log.Errorf("Port-map match found for %d %d: ace1 %v ace2 %v",
							idx1, idx2, ace1, ace2)
						return true
					}
				}
				idx2++
			}
		}
		idx1++
	}
	return false
}

// Check for duplicate portmap rules in between two set of ACLs.
// For this, we will match the protocol/lport being same.
func (z *zedrouter) detectPortMapConflictAcrossAdapters(
	ACLs []types.ACE, ACLs1 []types.ACE) bool {
	matchTypes := []string{"protocol", "lport"}
	for _, ace1 := range ACLs {
		for _, action := range ace1.Actions {
			// not a portmap rule
			if !action.PortMap {
				continue
			}
			for _, ace2 := range ACLs1 {
				for _, action1 := range ace2.Actions {
					// not a portmap rule
					if !action1.PortMap {
						continue
					}
					// match for protocol/lport
					if z.matchACEs(ace1, ace2, matchTypes) {
						z.log.Errorf("Port-map match found for ace %v ace2 %v",
							ace1, ace2)
						return true
					}
				}
			}
		}
	}
	return false
}

// generic comparison routine for ACL match conditions
func (z *zedrouter) matchACEs(ace1 types.ACE, ace2 types.ACE,
	matchTypes []string) bool {
	valueList1 := make([]string, len(matchTypes))
	valueList2 := make([]string, len(matchTypes))

	for idx, matchType := range matchTypes {
		for _, match := range ace1.Matches {
			if matchType == match.Type {
				valueList1[idx] = match.Value
			}
		}
		for _, match := range ace2.Matches {
			if matchType == match.Type {
				valueList2[idx] = match.Value
			}
		}
	}
	for idx, value := range valueList1 {
		value1 := valueList2[idx]
		if value == "" || value1 == "" ||
			value != value1 {
			z.log.Functionf("difference for %d: value %s value1 %s",
				idx, value, value1)
			return false
		}
	}
	return true
}
