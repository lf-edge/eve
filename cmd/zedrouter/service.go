// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService setup

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/eriknordmark/netlink"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	config := cast.CastNetworkServiceConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleNetworkServiceModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.Key(), config)
		return
	}
	status := lookupNetworkServiceStatus(ctx, key)
	if status != nil {
		log.Infof("handleNetworkServiceModify(%s)\n", key)
		status.PendingModify = true
		pub.Publish(status.Key(), *status)
		doServiceModify(ctx, config, status)
		status.PendingModify = false
		publishNetworkServiceStatus(ctx, status, true)
		log.Infof("handleNetworkServiceModify(%s) done\n", key)
	} else {
		handleNetworkServiceCreate(ctx, key, config)
	}
}

func handleNetworkServiceCreate(ctx *zedrouterContext, key string, config types.NetworkServiceConfig) {
	log.Infof("handleNetworkServiceCreate(%s)\n", key)

	pub := ctx.pubNetworkServiceStatus
	status := types.NetworkServiceStatus{
		UUID:        config.UUID,
		DisplayName: config.DisplayName,
		Type:        config.Type,
		AppLink:     config.AppLink,
		Adapter:     config.Adapter,
	}
	status.PendingAdd = true
	pub.Publish(status.Key(), status)
	err := doServiceCreate(ctx, config, &status)
	if err != nil {
		log.Infof("doServiceCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		publishNetworkServiceStatus(ctx, &status, true)
		return
	}
	pub.Publish(status.Key(), status)
	if config.Activate {
		err := doServiceActivate(ctx, config, &status)
		if err != nil {
			log.Errorf("doServiceActivate(%s) failed: %s\n", key, err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			status.Activated = true
		}
	}
	status.PendingAdd = false
	publishNetworkServiceStatus(ctx, &status, true)
	log.Infof("handleNetworkServiceCreate(%s) done\n", key)
}

func handleNetworkServiceDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleNetworkServiceDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	status := lookupNetworkServiceStatus(ctx, key)
	if status == nil {
		log.Infof("handleNetworkServiceDelete: unknown %s\n", key)
		return
	}
	status.PendingDelete = true
	pub.Publish(status.Key(), status)
	if status.Activated {
		doServiceInactivate(ctx, status)
	}
	doServiceDelete(ctx, status)
	status.PendingDelete = false
	publishNetworkServiceStatus(ctx, status, true)
	pub.Unpublish(status.Key())
	deleteNetworkServiceMetrics(ctx, status.Key())
	log.Infof("handleNetworkServiceDelete(%s) done\n", key)
}

func doServiceCreate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Infof("doServiceCreate NetworkService key %s type %d\n",
		config.UUID, config.Type)
	var err error

	switch config.Type {
	case types.NST_STRONGSWAN:
		err = strongswanCreate(ctx, config, status)
	case types.NST_LISP:
		err = lispCreate(ctx, config, status)
	case types.NST_BRIDGE:
		err = bridgeCreate(ctx, config, status)
	case types.NST_NAT:
		err = natCreate(ctx, config, status)
	case types.NST_LB:
		errStr := "doServiceCreate NetworkService LB not yet supported"
		err = errors.New(errStr)
	default:
		errStr := fmt.Sprintf("doServiceCreate NetworkService %d not yet supported",
			config.Type)
		err = errors.New(errStr)
	}
	return err
}

func doServiceModify(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) {

	log.Infof("doServiceModify NetworkService key %s\n", config.UUID)
	if config.Type != status.Type ||
		config.AppLink != status.AppLink ||
		config.Adapter != status.Adapter {
		errStr := fmt.Sprintf("doServiceModify NetworkService can't change key %s",
			config.UUID)
		log.Errorln(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		return
	}

	if config.Activate && !status.Activated {
		err := doServiceActivate(ctx, config, status)
		if err != nil {
			log.Errorf("doServiceActivate(%s) failed: %s\n",
				config.Key(), err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			status.Activated = true
		}
	} else if status.Activated && !config.Activate {
		doServiceInactivate(ctx, status)
		status.Activated = false
	}
}

// Find ifname as a bridge Adapter and see if it can be updated
func maybeUpdateBridgeIPAddr(ctx *zedrouterContext, ifname string) {
	log.Infof("maybeUpdateBridgeIPAddr(%s)\n", ifname)
	pub := ctx.pubNetworkServiceStatus
	items := pub.GetAll()
	for key, st := range items {
		status := cast.CastNetworkServiceStatus(st)
		if status.Key() != key {
			log.Errorf("maybeUpdateBridgeIPAddr key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		ifname2 := types.AdapterToIfName(ctx.deviceNetworkStatus,
			status.Adapter)
		if ifname2 != ifname {
			log.Infof("maybeUpdateBridgeIPAddr(%s) wrong adapter %s, %s\n",
				ifname, ifname2, status.Adapter)
			continue
		}
		if status.Type != types.NST_BRIDGE {
			log.Infof("maybeUpdateBridgeIPAddr(%s) not bridge %d\n",
				ifname, status.Type)
			continue
		}
		if !status.Activated {
			log.Errorf("maybeUpdateBridgeIPAddr(%s) not activated\n",
				ifname)
			continue
		}
		netstatus := lookupNetworkObjectStatus(ctx, status.AppLink.String())
		if netstatus == nil {
			log.Errorf("maybeUpdateBridgeIPAddr(%s) no applink for %s\n",
				ifname, status.Key())
			continue
		}
		updateBridgeIPAddr(ctx, netstatus)
	}
}

func doServiceActivate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Infof("doServiceActivate NetworkService key %s type %d\n",
		config.UUID, config.Type)

	// We must have an existing AppLink to activate
	netstatus := lookupNetworkObjectStatus(ctx, config.AppLink.String())
	if netstatus == nil {
		// Remember to check when NetworkObjects are added
		// XXX return error or not?
		status.MissingNetwork = true
		return errors.New(fmt.Sprintf("No AppLink %s for service %s",
			config.AppLink.String(), config.UUID))
	}
	status.MissingNetwork = false
	if netstatus.Error != "" {
		errStr := fmt.Sprintf("AppLink %s has error %s",
			config.AppLink.String(), netstatus.Error)
		return errors.New(errStr)
	}

	log.Infof("doServiceActivate found NetworkObjectStatus %s\n",
		netstatus.Key())

	// Check that Adapter is either "uplink", "freeuplink", or
	// an existing port name assigned to domO/zedrouter. A Bridge
	// only works with a single adapter interface.
	allowMgmtPort := (config.Type != types.NST_BRIDGE)
	err := validateAdapter(ctx, config.Adapter, allowMgmtPort)
	if err != nil {
		return err
	}
	status.IfNameList = adapterToIfNames(ctx, config.Adapter)

	switch config.Type {
	case types.NST_STRONGSWAN:
		err = strongswanActivate(ctx, config, status, netstatus)
	case types.NST_LISP:
		err = lispActivate(ctx, config, status, netstatus)
	case types.NST_BRIDGE:
		err = bridgeActivate(ctx, config, status, netstatus)
		if err != nil {
			updateBridgeIPAddr(ctx, netstatus)
		}
	case types.NST_NAT:
		err = natActivate(ctx, config, status, netstatus)
	case types.NST_LB:
		errStr := "doServiceActivate NetworkService LB not yet supported"
		err = errors.New(errStr)
	default:
		errStr := fmt.Sprintf("doServiceActivate NetworkService %d not yet supported",
			config.Type)
		err = errors.New(errStr)
	}
	return err
}

// Called when a NetworkObject is added
// Walk all NetworkServiceStatus looking for MissingNetwork, then
// check if network UUID is the AppLink
func checkAndRecreateService(ctx *zedrouterContext, network uuid.UUID) {

	log.Infof("checkAndRecreateServer(%s)\n", network.String())
	pub := ctx.pubNetworkServiceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastNetworkServiceStatus(st)
		if !status.MissingNetwork {
			continue
		}
		if status.AppLink != network {
			continue
		}
		log.Infof("checkAndRecreateService(%s) missing for %s\n",
			network.String(), status.Key())

		config := lookupNetworkServiceConfig(ctx, status.Key())
		if config == nil {
			log.Warnf("checkAndRecreateService(%s) no config for %s\n",
				network.String(), status.Key())
			continue
		}
		if !config.Activate {
			continue
		}
		log.Infof("checkAndRecreateService(%s) reactivate for %s\n",
			network.String(), status.Key())
		if status.Error != "" {
			log.Infof("checkAndRecreateService(%s) remove error %s for %s\n",
				network.String(), status.Error, status.Key())
			status.Error = ""
			status.ErrorTime = time.Time{}
		}
		err := doServiceActivate(ctx, *config, &status)
		if err != nil {
			log.Infof("checkAndRecreateService srv %s failed %s\n",
				status.Key(), err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			status.Activated = true
			status.MissingNetwork = false
		}
		pub.Publish(status.Key(), status)
	}
}

func validateAdapter(ctx *zedrouterContext, adapter string,
	allowMgmtPort bool) error {

	if adapter == "" {
		errStr := fmt.Sprintf("Adapter not specified")
		return errors.New(errStr)
	}
	if allowMgmtPort {
		if strings.EqualFold(adapter, "uplink") {
			return nil
		}
		if strings.EqualFold(adapter, "freeuplink") {
			return nil
		}
	}
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, adapter)
	// XXX look for ifname; this assumes it exists in dom0/zedrouter
	// and not assigned to pciback
	// XXX also check not management port? assignable checked for bridge ...
	// XXX need a resourcemgr to track use of resources
	link, _ := netlink.LinkByName(ifname)
	if link == nil {
		errStr := fmt.Sprintf("Unknown adapter %s, %s",
			adapter, ifname)
		return errors.New(errStr)
	}
	return nil
}

func doServiceInactivate(ctx *zedrouterContext,
	status *types.NetworkServiceStatus) {

	log.Infof("doServiceInactivate NetworkService key %s type %d\n",
		status.UUID, status.Type)
	// We must have an existing AppLink to activate
	netstatus := lookupNetworkObjectStatus(ctx, status.AppLink.String())
	if netstatus == nil {
		status.MissingNetwork = true
		// Should have been caught at time of activate
		log.Infof("No AppLink for %s", status.Key())
		return
	}
	status.MissingNetwork = false

	log.Infof("doServiceInactivate found NetworkObjectStatus %s\n",
		netstatus.Key())

	switch status.Type {
	case types.NST_STRONGSWAN:
		strongswanInactivate(ctx, status, netstatus)
	case types.NST_LISP:
		lispInactivate(ctx, status, netstatus)
	case types.NST_BRIDGE:
		bridgeInactivate(ctx, status, netstatus)
		updateBridgeIPAddr(ctx, netstatus)
	case types.NST_NAT:
		natInactivate(ctx, status, netstatus)
	case types.NST_LB:
		errStr := "doServiceInactivate NetworkService LB not yet supported"
		log.Errorln(errStr)
	default:
		errStr := fmt.Sprintf("doServiceInactivate NetworkService %d not yet supported",
			status.Type)
		log.Infoln(errStr)
	}
}

func doServiceDelete(ctx *zedrouterContext, status *types.NetworkServiceStatus) {
	log.Infof("doServiceDelete NetworkService key %s type %d\n",
		status.UUID, status.Type)
	// Anything to do except the inactivate already done?
	switch status.Type {
	case types.NST_STRONGSWAN:
		strongswanDelete(status)
	case types.NST_LISP:
		lispDelete(ctx, status)
	case types.NST_BRIDGE:
		bridgeDelete(status)
	case types.NST_NAT:
		natDelete(status)
	case types.NST_LB:
		errStr := "doServiceDelete NetworkService LB not yet supported"
		log.Errorln(errStr)
	default:
		errStr := fmt.Sprintf("doServiceDelete NetworkService %d not yet supported",
			status.Type)
		log.Errorln(errStr)
	}
}

func lookupNetworkServiceConfig(ctx *zedrouterContext, key string) *types.NetworkServiceConfig {

	sub := ctx.subNetworkServiceConfig
	c, _ := sub.Get(key)
	if c == nil {
		return nil
	}
	config := cast.CastNetworkServiceConfig(c)
	if config.Key() != key {
		log.Errorf("lookupNetworkServiceConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupNetworkServiceStatus(ctx *zedrouterContext, key string) *types.NetworkServiceStatus {

	pub := ctx.pubNetworkServiceStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkServiceStatus(st)
	if status.Key() != key {
		log.Errorf("lookupNetworkServiceStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupNetworkServiceMetrics(ctx *zedrouterContext, key string) *types.NetworkServiceMetrics {
	pub := ctx.pubNetworkServiceMetrics
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkServiceMetrics(st)
	if status.Key() != key {
		log.Errorf("lookupNetworkServiceMetrics key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func deleteNetworkServiceMetrics(ctx *zedrouterContext, key string) {
	pub := ctx.pubNetworkServiceMetrics
	if metrics := lookupNetworkServiceMetrics(ctx, key); metrics != nil {
		pub.Unpublish(metrics.Key())
	}
}

// Entrypoint from networkobject to look for the service type and optional
// adapter
func getServiceInfo(ctx *zedrouterContext, appLink uuid.UUID) (types.NetworkServiceType, string, error) {
	// Find any service which is associated with the appLink UUID
	log.Infof("getServiceInfo(%s)\n", appLink.String())
	status := lookupAppLink(ctx, appLink)
	if status == nil {
		errStr := fmt.Sprintf("getServiceInfo: no NetworkServiceStatus for %s", appLink.String())
		return types.NST_FIRST, "", errors.New(errStr)
	}
	return status.Type, status.Adapter, nil
}

// Entrypoint from networkobject to look for a bridge's IPv4 address
func getBridgeServiceIPv4Addr(ctx *zedrouterContext, appLink uuid.UUID) (string, error) {
	// Find any service which is associated with the appLink UUID
	log.Infof("getBridgeServiceIPv4Addr(%s)\n", appLink.String())
	status := lookupAppLink(ctx, appLink)
	if status == nil {
		errStr := fmt.Sprintf("getBridgeServiceIPv4Addr(%s): no NetworkServiceStatus",
			appLink.String())
		return "", errors.New(errStr)
	}
	if status.Type != types.NST_BRIDGE {
		errStr := fmt.Sprintf("getBridgeServiceIPv4Addr(%s): service not a bridge; type %d",
			appLink.String(), status.Type)
		return "", errors.New(errStr)
	}
	if status.Adapter == "" {
		log.Infof("getBridgeServiceIPv4Addr(%s): bridge but no Adapter\n",
			appLink.String())
		return "", nil
	}

	// Get IP address from adapter
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Adapter)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return "", err
	}
	// XXX Add IPv6 underlay; ignore link-locals.
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		log.Infof("getBridgeServiceIPv4Addr(%s): found addr %s\n",
			appLink.String(), addr.IP.String())
		return addr.IP.String(), nil
	}
	log.Infof("getBridgeServiceIPv4Addr(%s): no IP address on %s yet\n",
		appLink.String(), status.Adapter)
	return "", nil
}

func lookupAppLink(ctx *zedrouterContext, appLink uuid.UUID) *types.NetworkServiceStatus {
	log.Infof("lookupAppLink(%s)\n", appLink.String())
	pub := ctx.pubNetworkServiceStatus
	items := pub.GetAll()
	for key, st := range items {
		status := cast.CastNetworkServiceStatus(st)
		if status.Key() != key {
			log.Infof("lookupAppLink key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		if status.AppLink == appLink {
			log.Infof("lookupAppLink(%s) found %s\n",
				appLink.String(), status.Key())
			return &status
		}
	}
	return nil
}

// this is periodic state change handler
func publishNetworkServiceStatusAll(ctx *zedrouterContext) {
	pub := ctx.pubNetworkServiceStatus
	stlist := pub.GetAll()
	if stlist == nil {
		return
	}
	for _, st := range stlist {
		status := cast.CastNetworkServiceStatus(st)
		if status.Type == types.NST_LISP {
			// For Lisp, service info update is triggered when we receive
			// update from lisp-ztr with changes to its state info.
			// Lisp does not need a timer to check for updates.
			continue
		}
		publishNetworkServiceStatus(ctx, &status, false)
	}
	return
}

func publishNetworkServiceStatus(ctx *zedrouterContext, status *types.NetworkServiceStatus, force bool) {
	pub := ctx.pubNetworkServiceStatus
	change := false
	switch status.Type {
	case types.NST_STRONGSWAN:
		change = strongSwanVpnStatusGet(ctx, status)
	}
	if force == true || change == true {
		pub.Publish(status.Key(), &status)
	}
}

func publishNetworkServiceMetrics(ctx *zedrouterContext, status *types.NetworkServiceMetrics, force bool) {
	pub := ctx.pubNetworkServiceMetrics
	change := false
	if force == true || change == true {
		pub.Publish(status.Key(), &status)
	}
}

// ==== Lisp

// XXX note that we can't change the mapservers nor IID unless we move
// those configlets to Activate
func lispCreate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {
	return nil
}

func lispActivate(ctx *zedrouterContext,
	config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) error {

	log.Infof("lispActivate(%s)\n", config.DisplayName)

	status.LispStatus = config.LispConfig

	// XXX Create Lisp IID & map-server configlets here
	iid := config.LispConfig.IID
	mapServers := config.LispConfig.MapServers
	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(iid), 10)
	file, err := os.Create(cfgPathnameIID)
	if err != nil {
		log.Errorf("lispActivate failed ", err)
		return err
	}
	defer file.Close()

	// Write map-servers to configlet
	for _, ms := range mapServers {
		msConfigLine := fmt.Sprintf(lispMStemplate, iid,
			ms.NameOrIp, ms.Credential)
		file.WriteString(msConfigLine)
	}

	// Write Lisp IID template
	iidConfig := fmt.Sprintf(lispIIDtemplate, iid)
	file.WriteString(iidConfig)

	if netstatus.Error != "" {
		errStr := fmt.Sprintf("AppLink %s has error %s",
			config.AppLink.String(), netstatus.Error)
		return errors.New(errStr)
	}
	if netstatus.Ipv4Eid {
		ipv4Network := netstatus.Subnet.IP.Mask(netstatus.Subnet.Mask)
		maskLen, _ := netstatus.Subnet.Mask.Size()
		subnet := fmt.Sprintf("%s/%d",
			ipv4Network.String(), maskLen)
		file.WriteString(fmt.Sprintf(
			lispIPv4IIDtemplate, iid, subnet))
	}

	// Go through the AppNetworkStatus and create Lisp configlets that use
	// this service.
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()

	for _, ans := range items {
		appNetStatus := cast.CastAppNetworkStatus(ans)
		for _, olconfig := range appNetStatus.OverlayNetworkList {
			if olconfig.Network == status.AppLink {
				// We are interconnected
				// Try and create the Lisp configlets
				createAndStartLisp(ctx, appNetStatus,
					olconfig.OverlayNetworkConfig,
					status, lispRunDirname, netstatus.BridgeName)
			}
		}
	}

	log.Infof("lispActivate(%s)\n", status.DisplayName)
	return nil
}

func lispInactivate(ctx *zedrouterContext,
	status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) {

	// XXX What should we do?
	// TODO:
	// Should we just remove all database-mappings, IIDs and interface{}
	// stanzas corresponding to this service and bridge. Then restart lisp??

	// Go through the AppNetworkConfigs and create Lisp parameters that use
	// this service.
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()

	// When service is deactivated we should delete IID and map-server
	// configuration also
	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(status.LispStatus.IID), 10)
	if err := os.Remove(cfgPathnameIID); err != nil {
		log.Errorln(err)
	}

	for _, ans := range items {
		appNetStatus := cast.CastAppNetworkStatus(ans)
		if len(appNetStatus.OverlayNetworkList) == 0 {
			continue
		}
		for _, olStatus := range appNetStatus.OverlayNetworkList {
			if olStatus.Network == status.AppLink {
				// Pass global deviceNetworkStatus
				deleteLispConfiglet(lispRunDirname, false,
					status.LispStatus.IID, olStatus.EID,
					olStatus.AppIPAddr,
					*ctx.deviceNetworkStatus,
					ctx.legacyDataPlane)
			}
		}
	}

	log.Infof("lispInactivate(%s)\n", status.DisplayName)
}

func lispDelete(ctx *zedrouterContext, status *types.NetworkServiceStatus) {
	// XXX What should we do?
	// TODO:
	// Do something similar to lispInactivate??
	// Or should we do something similar to handleDelete in zedrouter.go??
	// We have the EIDs as part of AppNetworkStatus and IID as part of NetworkServiceStatus.
	// We will have to bring them together somehow to clear the lisp configlets, ACLs etc.
	netstatus := lookupNetworkObjectStatus(ctx, status.AppLink.String())
	if netstatus == nil {
		status.MissingNetwork = true
		// Should have been caught at time of activate
		log.Infof("No AppLink for %s", status.Key())
		return
	}
	status.MissingNetwork = false
	lispInactivate(ctx, status, netstatus)

	log.Infof("lispDelete(%s)\n", status.DisplayName)
}

// ==== Bridge

// XXX need a better check than assignable since it could be any
// member of an IoBundle.
// XXX also need to check the bundle isn't assigned to a domU?
func bridgeCreate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Infof("bridgeCreate(%s)\n", config.DisplayName)
	ib := types.LookupIoBundle(ctx.assignableAdapters, types.IoEth,
		config.Adapter)
	if ib == nil {
		errStr := fmt.Sprintf("bridge %s is not assignable for %s",
			config.Adapter, config.Key())
		return errors.New(errStr)
	}
	// XXX check it isn't assigned to dom0? That's maintained
	// in domainmgr so can't do it here.
	// For now check it isn't a zedrouter port instead.
	if types.IsPort(*ctx.deviceNetworkStatus, config.Adapter) {
		errStr := fmt.Sprintf("Zedrouter port %s not available as bridge for %s",
			config.Adapter, config.Key())
		return errors.New(errStr)
	}
	return nil
}

func bridgeActivate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) error {

	log.Infof("bridgeActivate(%s)\n", status.DisplayName)
	// For now we only support passthrough
	if netstatus.Dhcp != types.DT_PASSTHROUGH {
		errStr := fmt.Sprintf("Unsupported DHCP type %d for bridge service for %s",
			netstatus.Dhcp, status.Key())
		return errors.New(errStr)
	}

	bridgeLink, err := findBridge(netstatus.BridgeName)
	if err != nil {
		errStr := fmt.Sprintf("findBridge(%s) failed %s",
			netstatus.BridgeName, err)
		return errors.New(errStr)
	}
	// Find adapter
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Adapter)
	alink, _ := netlink.LinkByName(ifname)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown adapter %s, %s",
			status.Adapter, ifname)
		return errors.New(errStr)
	}
	// Make sure it is up
	//    ip link set ${adapter} up
	if err := netlink.LinkSetUp(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
			status.Adapter, err)
		return errors.New(errStr)
	}
	// ip link set ${adapter} master ${bridge_name}
	if err := netlink.LinkSetMaster(alink, bridgeLink); err != nil {
		errStr := fmt.Sprintf("LinkSetMaster %s %s failed: %s",
			status.Adapter, netstatus.BridgeName, err)
		return errors.New(errStr)
	}
	log.Infof("bridgeActivate: added %s to bridge %s\n",
		status.Adapter, netstatus.BridgeName)
	return nil
}

func bridgeInactivate(ctx *zedrouterContext,
	status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) {

	log.Infof("bridgeInactivate(%s)\n", status.DisplayName)
	// Find adapter
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Adapter)
	alink, _ := netlink.LinkByName(ifname)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown adapter %s, %s",
			status.Adapter, ifname)
		log.Errorln(errStr)
		return
	}
	// ip link set ${adapter} nomaster
	if err := netlink.LinkSetNoMaster(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetMaster %s failed: %s",
			status.Adapter, err)
		log.Infoln(errStr)
		return
	}
	log.Infof("bridgeInactivate: removed %s from bridge\n",
		status.Adapter)
}

func bridgeDelete(status *types.NetworkServiceStatus) {
	log.Infof("bridgeDelete(%s)\n", status.DisplayName)
}

// ==== Nat

func natCreate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Infof("natCreate(%s)\n", config.DisplayName)
	return nil
}

// XXX need to redo this when MgmtPorts/FreeMgmtPorts changes?
func natActivate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) error {

	log.Infof("natActivate(%s)\n", status.DisplayName)
	if netstatus.Subnet.IP == nil {
		errStr := fmt.Sprintf("Missing subnet for NAT service for %s",
			status.Key())
		return errors.New(errStr)
	}
	status.Subnet = netstatus.Subnet
	subnetStr := netstatus.Subnet.String()

	for _, a := range status.IfNameList {
		err := iptableCmd("-t", "nat", "-A", "POSTROUTING", "-o", a,
			"-s", subnetStr, "-j", "MASQUERADE")
		if err != nil {
			return err
		}
		err = PbrRouteAddDefault(netstatus.BridgeName, a)
		if err != nil {
			return err
		}
	}
	// Add to Pbr table
	err := PbrNATAdd(subnetStr)
	if err != nil {
		return err
	}
	return nil
}

// Expand the generic names, and return the interface name
// Does not verify the existence of the adapters/interfaces
func adapterToIfNames(ctx *zedrouterContext, adapter string) []string {
	if strings.EqualFold(adapter, "uplink") {
		return types.GetMgmtPortsAny(*ctx.deviceNetworkStatus, 0)
	}
	if strings.EqualFold(adapter, "freeuplink") {
		return types.GetMgmtPortsFree(*ctx.deviceNetworkStatus, 0)
	}
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, adapter)
	return []string{ifname}
}

func natInactivate(ctx *zedrouterContext, status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) {

	log.Infof("netInactivate(%s)\n", status.DisplayName)
	subnetStr := status.Subnet.String()
	for _, a := range status.IfNameList {
		err := iptableCmd("-t", "nat", "-D", "POSTROUTING", "-o", a,
			"-s", subnetStr, "-j", "MASQUERADE")
		if err != nil {
			log.Errorf("natInactivate: iptableCmd failed %s\n", err)
		}
		err = PbrRouteDeleteDefault(netstatus.BridgeName, a)
		if err != nil {
			log.Errorf("natInactivate: PbrRouteDeleteDefault failed %s\n", err)
		}
	}
	// Remove from Pbr table
	err := PbrNATDel(subnetStr)
	if err != nil {
		log.Errorf("natInactivate: PbrNATDel failed %s\n", err)
	}
}

func natDelete(status *types.NetworkServiceStatus) {

	log.Infof("natDelete(%s)\n", status.DisplayName)
}
