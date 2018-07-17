// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Process input in the form of a collection of AppNetworkConfig structs
// from zedmanager and zedagent. Publish the status as AppNetworkStatus.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables, lisp.config,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/adapters"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"
)

const (
	agentName     = "zedrouter"
	runDirname    = "/var/run/zedrouter"
	tmpDirname    = "/var/tmp/zededa"
	DataPlaneName = "lisp-ztr"
)

// Set from Makefile
var Version = "No version specified"

type zedrouterContext struct {
	// Experimental Zededa data plane enable/disable flag
	separateDataPlane       bool
	subNetworkObjectConfig  *pubsub.Subscription
	subNetworkServiceConfig *pubsub.Subscription
	pubNetworkObjectStatus  *pubsub.Publication
	pubNetworkServiceStatus *pubsub.Publication
	subAppNetworkConfig     *pubsub.Subscription
	subAppNetworkConfigAg   *pubsub.Subscription // From zedagent for dom0
	pubAppNetworkStatus     *pubsub.Publication
	assignableAdapters      *types.AssignableAdapters
	usableAddressCount      int
	manufacturerModel       string
	subDeviceNetworkConfig  *pubsub.Subscription
	pubDeviceNetworkStatus  *pubsub.Publication
	ready                   bool
}

var debug = false

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	if _, err := os.Stat(runDirname); err != nil {
		log.Printf("Create %s\n", runDirname)
		if err := os.Mkdir(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	} else {
		// dnsmasq needs to read as nobody
		if err := os.Chmod(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	pubDeviceNetworkStatus, err := pubsub.Publish(agentName,
		types.DeviceNetworkStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubDeviceNetworkStatus.ClearRestarted()

	model := hardware.GetHardwareModel()

	// Pick up (mostly static) AssignableAdapters before we process
	// any Routes; Pbr needs to know which network adapters are assignable
	aa := types.AssignableAdapters{}
	subAa := adapters.Subscribe(&aa, model)

	for !subAa.Found {
		log.Printf("Waiting for AssignableAdapters %v\n", subAa.Found)
		select {
		case change := <-subAa.C:
			subAa.ProcessChange(change)
		}
	}
	log.Printf("Have %d assignable adapters\n", len(aa.IoBundleList))

	zedrouterCtx := zedrouterContext{
		separateDataPlane:      false,
		assignableAdapters:     &aa,
		manufacturerModel:      model,
		pubDeviceNetworkStatus: pubDeviceNetworkStatus,
	}

	// Get the initial DeviceNetworkConfig
	// Subscribe from "" means /var/tmp/zededa/
	subDeviceNetworkConfig, err := pubsub.Subscribe("",
		types.DeviceNetworkConfig{}, false, &zedrouterCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkConfig.ModifyHandler = handleDNCModify
	subDeviceNetworkConfig.DeleteHandler = handleDNCDelete
	zedrouterCtx.subDeviceNetworkConfig = subDeviceNetworkConfig
	subDeviceNetworkConfig.Activate()

	for zedrouterCtx.usableAddressCount == 0 {
		log.Printf("Waiting for DeviceNetworkConfig\n")
		select {
		case change := <-subDeviceNetworkConfig.C:
			subDeviceNetworkConfig.ProcessChange(change)
		}
	}
	log.Printf("Got for DeviceNetworkConfig: %d usable addresses\n",
		zedrouterCtx.usableAddressCount)

	handleInit(runDirname, pubDeviceNetworkStatus)

	// Create publish before subscribing and activating subscriptions
	pubNetworkObjectStatus, err := pubsub.Publish(agentName,
		types.NetworkObjectStatus{})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubNetworkObjectStatus = pubNetworkObjectStatus

	pubNetworkServiceStatus, err := pubsub.Publish(agentName,
		types.NetworkServiceStatus{})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubNetworkServiceStatus = pubNetworkServiceStatus

	pubAppNetworkStatus, err := pubsub.Publish(agentName,
		types.AppNetworkStatus{})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppNetworkStatus = pubAppNetworkStatus
	pubAppNetworkStatus.ClearRestarted()

	appNumAllocatorInit(pubAppNetworkStatus)
	bridgeNumAllocatorInit(pubNetworkObjectStatus)

	// Subscribe to network objects and services from zedagent
	subNetworkObjectConfig, err := pubsub.Subscribe("zedagent",
		types.NetworkObjectConfig{}, false, &zedrouterCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkObjectConfig.ModifyHandler = handleNetworkObjectModify
	subNetworkObjectConfig.DeleteHandler = handleNetworkObjectDelete
	zedrouterCtx.subNetworkObjectConfig = subNetworkObjectConfig
	subNetworkObjectConfig.Activate()

	subNetworkServiceConfig, err := pubsub.Subscribe("zedagent",
		types.NetworkServiceConfig{}, false, &zedrouterCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkServiceConfig.ModifyHandler = handleNetworkServiceModify
	subNetworkServiceConfig.DeleteHandler = handleNetworkServiceDelete
	zedrouterCtx.subNetworkServiceConfig = subNetworkServiceConfig
	subNetworkServiceConfig.Activate()

	// Subscribe to AppNetworkConfig from zedmanager and from zedagent
	subAppNetworkConfig, err := pubsub.Subscribe("zedmanager",
		types.AppNetworkConfig{}, false, &zedrouterCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAppNetworkConfig.ModifyHandler = handleAppNetworkConfigModify
	subAppNetworkConfig.DeleteHandler = handleAppNetworkConfigDelete
	subAppNetworkConfig.RestartHandler = handleRestart
	zedrouterCtx.subAppNetworkConfig = subAppNetworkConfig
	subAppNetworkConfig.Activate()

	// Subscribe to AppNetworkConfig from zedmanager
	subAppNetworkConfigAg, err := pubsub.Subscribe("zedagent",
		types.AppNetworkConfig{}, false, &zedrouterCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAppNetworkConfigAg.ModifyHandler = handleAppNetworkConfigModify
	subAppNetworkConfigAg.DeleteHandler = handleAppNetworkConfigDelete
	zedrouterCtx.subAppNetworkConfigAg = subAppNetworkConfigAg
	subAppNetworkConfigAg.Activate()

	// XXX should we make geoRedoTime configurable?
	// We refresh the gelocation information when the underlay
	// IP address(es) change, or once an hour.
	geoRedoTime := time.Hour

	// Timer for retries after failure etc. Should be less than geoRedoTime
	geoInterval := time.Duration(10 * time.Minute)
	geoMax := float64(geoInterval)
	geoMin := geoMax * 0.3
	geoTimer := flextimer.NewRangeTicker(time.Duration(geoMin),
		time.Duration(geoMax))

	// This function is called from PBR when some uplink interface changes
	// its IP address(es)
	addrChangeUplinkFn := func(ifname string) {
		if debug {
			log.Printf("addrChangeUplinkFn(%s) called\n", ifname)
		}
		new, _ := devicenetwork.MakeDeviceNetworkStatus(deviceNetworkConfig, deviceNetworkStatus)
		// XXX switch to Equal?
		if !reflect.DeepEqual(deviceNetworkStatus, new) {
			if debug {
				log.Printf("Address change for %s from %v to %v\n",
					ifname, deviceNetworkStatus, new)
			}
			deviceNetworkStatus = new
			doDNSUpdate(&zedrouterCtx)
		} else {
			log.Printf("No address change for %s\n", ifname)
		}
	}
	addrChangeNonUplinkFn := func(ifname string) {
		if debug {
			log.Printf("addrChangeNonUplinkFn(%s) called\n", ifname)
		}
		ib := types.LookupIoBundle(&aa, types.IoEth, ifname)
		if ib == nil {
			if debug {
				log.Printf("addrChangeNonUplinkFn(%s) not assignable\n",
					ifname)
			}
			return
		}
		maybeUpdateBridgeIPAddr(&zedrouterCtx, ifname)
	}
	// We don't want any routes for assignable adapters
	suppressRoutesFn := func(ifname string) bool {
		if debug {
			log.Printf("suppressRoutesFn(%s) called\n", ifname)
		}
		ib := types.LookupIoBundle(&aa, types.IoEth, ifname)
		return ib != nil
	}

	routeChanges, addrChanges, linkChanges := PbrInit(
		deviceNetworkConfig.Uplink, deviceNetworkConfig.FreeUplinks,
		addrChangeUplinkFn, addrChangeNonUplinkFn, suppressRoutesFn)

	// Publish network metrics for zedagent every 10 seconds
	nms := getNetworkMetrics() // Need type of data
	pub, err := pubsub.Publish(agentName, nms)
	if err != nil {
		log.Fatal(err)
	}
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	// Apply any changes from the uplink config to date.
	publishDeviceNetworkStatus(zedrouterCtx.pubDeviceNetworkStatus)
	updateLispConfiglets(&zedrouterCtx, zedrouterCtx.separateDataPlane)
	setUplinks(deviceNetworkConfig.Uplink)
	setFreeUplinks(deviceNetworkConfig.FreeUplinks)

	zedrouterCtx.ready = true

	// First wait for restarted from zedmanager
	for !subAppNetworkConfig.Restarted() {
		log.Printf("Waiting for zedmanager to report restarted\n")
		select {
		case change := <-subAppNetworkConfig.C:
			subAppNetworkConfig.ProcessChange(change)
		}
	}
	log.Printf("Zedmanager has restarted\n")

	for {
		select {
		case change := <-subAppNetworkConfig.C:
			subAppNetworkConfig.ProcessChange(change)

		case change := <-subAppNetworkConfigAg.C:
			subAppNetworkConfigAg.ProcessChange(change)

		case change := <-subDeviceNetworkConfig.C:
			subDeviceNetworkConfig.ProcessChange(change)

		case change := <-addrChanges:
			PbrAddrChange(change)
		case change := <-linkChanges:
			PbrLinkChange(change)
		case change := <-routeChanges:
			PbrRouteChange(change)
		case <-publishTimer.C:
			if debug {
				log.Println("publishTimer at",
					time.Now())
			}
			err := pub.Publish("global", getNetworkMetrics())
			if err != nil {
				log.Println(err)
			}
		case <-geoTimer.C:
			if debug {
				log.Println("geoTimer at", time.Now())
			}
			change := devicenetwork.UpdateDeviceNetworkGeo(
				geoRedoTime, &deviceNetworkStatus)
			if change {
				publishDeviceNetworkStatus(pubDeviceNetworkStatus)
			}

		case change := <-subNetworkObjectConfig.C:
			subNetworkObjectConfig.ProcessChange(change)

		case change := <-subNetworkServiceConfig.C:
			subNetworkServiceConfig.ProcessChange(change)

		case change := <-subAa.C:
			subAa.ProcessChange(change)
		}
	}
}

func handleRestart(ctxArg interface{}, done bool) {
	if debug {
		log.Printf("handleRestart(%v)\n", done)
	}
	ctx := ctxArg.(*zedrouterContext)
	if ctx.ready {
		handleLispRestart(done, ctx.separateDataPlane)
	}
	if done {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		ctx.pubAppNetworkStatus.SignalRestarted()
	}
}

var deviceNetworkConfig types.DeviceNetworkConfig
var deviceNetworkStatus types.DeviceNetworkStatus
var globalRunDirname string
var lispRunDirname string

// XXX hack to avoid the pslisp hang on Erik's laptop
var broken = false

func handleInit(runDirname string, pubDeviceNetworkStatus *pubsub.Publication) {

	globalRunDirname = runDirname

	// XXX should this be in the lisp code?
	lispRunDirname = runDirname + "/lisp"
	if _, err := os.Stat(lispRunDirname); err != nil {
		log.Printf("Create %s\n", lispRunDirname)
		if err := os.Mkdir(lispRunDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	// XXX should this be in dnsmasq code?
	// Need to make sure we don't have any stale leases
	leasesFile := "/var/lib/misc/dnsmasq.leases"
	if _, err := os.Stat(leasesFile); err == nil {
		if err := os.Remove(leasesFile); err != nil {
			log.Fatal(err)
		}
	}

	// Setup initial iptables rules
	iptablesInit()

	// ipsets which are independent of config
	createDefaultIpset()

	_, err := wrap.Command("sysctl", "-w",
		"net.ipv4.ip_forward=1").Output()
	if err != nil {
		log.Fatal("Failed setting ip_forward ", err)
	}
	_, err = wrap.Command("sysctl", "-w",
		"net.ipv6.conf.all.forwarding=1").Output()
	if err != nil {
		log.Fatal("Failed setting ipv6.conf.all.forwarding ", err)
	}
	// We use ip6tables for the bridge
	_, err = wrap.Command("sysctl", "-w",
		"net.bridge.bridge-nf-call-ip6tables=1").Output()
	if err != nil {
		log.Fatal("Failed setting net.bridge-nf-call-ip6tables ", err)
	}
	_, err = wrap.Command("sysctl", "-w",
		"net.bridge.bridge-nf-call-iptables=1").Output()
	if err != nil {
		log.Fatal("Failed setting net.bridge-nf-call-iptables ", err)
	}
	_, err = wrap.Command("sysctl", "-w",
		"net.bridge.bridge-nf-call-arptables=1").Output()
	if err != nil {
		log.Fatal("Failed setting net.bridge-nf-call-arptables ", err)
	}

	// XXX hack to determine whether a real system or Erik's laptop
	_, err = wrap.Command("xl", "list").Output()
	if err != nil {
		log.Printf("Command xl list failed: %s\n", err)
		broken = true
	}
}

func publishDeviceNetworkStatus(pubDeviceNetworkStatus *pubsub.Publication) {
	pubDeviceNetworkStatus.Publish("global", deviceNetworkStatus)
}

func publishAppNetworkStatus(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	key := status.Key()
	log.Printf("publishAppNetworkStatus(%s)\n", key)
	pub := ctx.pubAppNetworkStatus
	pub.Publish(key, status)
}

func unpublishAppNetworkStatus(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	key := status.Key()
	log.Printf("unpublishAppNetworkStatus(%s)\n", key)
	pub := ctx.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("unpublishAppNetworkStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// Format a json string with any additional info
func generateAdditionalInfo(status types.AppNetworkStatus, olConfig types.OverlayNetworkConfig) string {
	additionalInfo := ""
	if status.IsZedmanager {
		if olConfig.AdditionalInfoDevice != nil {
			b, err := json.Marshal(olConfig.AdditionalInfoDevice)
			if err != nil {
				log.Fatal(err, "json Marshal AdditionalInfoDevice")
			}
			additionalInfo = string(b)
			if debug {
				log.Printf("Generated additional info device %s\n",
					additionalInfo)
			}
		}
	} else {
		// Combine subset of the device and application information
		addInfoApp := types.AdditionalInfoApp{
			DeviceEID:   deviceEID,
			DeviceIID:   deviceIID,
			DisplayName: status.DisplayName,
		}
		if additionalInfoDevice != nil {
			addInfoApp.UnderlayIP = additionalInfoDevice.UnderlayIP
			addInfoApp.Hostname = additionalInfoDevice.Hostname
		}
		b, err := json.Marshal(addInfoApp)
		if err != nil {
			log.Fatal(err, "json Marshal AdditionalInfoApp")
		}
		additionalInfo = string(b)
		if debug {
			log.Printf("Generated additional info app %s\n",
				additionalInfo)
		}
	}
	return additionalInfo
}

func updateLispConfiglets(ctx *zedrouterContext, separateDataPlane bool) {
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastAppNetworkStatus(st)
		// XXX Key
		for i, olStatus := range status.OverlayNetworkList {
			olNum := i + 1
			var olIfname string
			if status.IsZedmanager {
				olIfname = "dbo" + strconv.Itoa(olNum) + "x" +
					strconv.Itoa(status.AppNum)
			} else {
				olIfname = "bo" + strconv.Itoa(olNum) + "x" +
					strconv.Itoa(status.AppNum)
			}
			additionalInfo := generateAdditionalInfo(status,
				olStatus.OverlayNetworkConfig)
			if debug {
				log.Printf("updateLispConfiglets for %s isMgmt %v\n",
					olIfname, status.IsZedmanager)
			}
			createLispConfiglet(lispRunDirname, status.IsZedmanager,
				olStatus.IID, olStatus.EID, olStatus.LispSignature,
				deviceNetworkStatus, olIfname, olIfname,
				additionalInfo, olStatus.LispServers, separateDataPlane)
		}
	}
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func handleAppNetworkConfigModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleAppNetworkConfigModify(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	config := cast.CastAppNetworkConfig(configArg)
	if config.Key() != key {
		log.Printf("handleAppNetworkConfigModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := lookupAppNetworkStatus(ctx, key)
	if status == nil {
		handleCreate(ctx, key, config)
	} else {
		handleModify(ctx, key, config, status)
	}
	log.Printf("handleAppNetworkConfigModify(%s) done\n", key)
}

func handleAppNetworkConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Printf("handleAppNetworkConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	status := lookupAppNetworkStatus(ctx, key)
	if status == nil {
		log.Printf("handleAppNetworkConfigDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Printf("handleAppNetworkConfigDelete(%s) done\n", key)
}

// Callers must be careful to publish any changes to AppNetworkStatus
func lookupAppNetworkStatus(ctx *zedrouterContext, key string) *types.AppNetworkStatus {

	pub := ctx.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupAppNetworkStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastAppNetworkStatus(st)
	if status.Key() != key {
		log.Printf("lookupAppNetworkStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupAppNetworkConfig(ctx *zedrouterContext, key string) *types.AppNetworkConfig {

	sub := ctx.subAppNetworkConfig
	c, _ := sub.Get(key)
	if c == nil {
		sub = ctx.subAppNetworkConfigAg
		c, _ = sub.Get(key)
		if c == nil {
			log.Printf("lookupAppNetworkConfig(%s) not found\n", key)
			return nil
		}
	}
	config := cast.CastAppNetworkConfig(c)
	if config.Key() != key {
		log.Printf("lookupAppNetworkConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

// Track the device information so we can annotate the application EIDs
// Note that when we start with zedrouter config files in place the
// device one might be processed after application ones, in which case these
// empty. This results in less additional info recorded in the map servers.
// XXX note that this only works well when the IsZedmanager AppNetworkConfig
// arrives first so that these fields are filled in before other
// AppNetworkConfig entries are processed.
var deviceEID net.IP
var deviceIID uint32
var additionalInfoDevice *types.AdditionalInfoDevice

func handleCreate(ctx *zedrouterContext, key string,
	config types.AppNetworkConfig) {
	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Pick a local number to identify the application instance
	// Used for IP addresses as well bridge and file names.
	appNum := appNumAllocate(config.UUIDandVersion.UUID,
		config.IsZedmanager)

	// Start by marking with PendingAdd
	status := types.AppNetworkStatus{
		UUIDandVersion: config.UUIDandVersion,
		AppNum:         appNum,
		PendingAdd:     true,
		OlNum:          len(config.OverlayNetworkList),
		UlNum:          len(config.UnderlayNetworkList),
		DisplayName:    config.DisplayName,
		IsZedmanager:   config.IsZedmanager,
	}
	publishAppNetworkStatus(ctx, &status)

	if config.IsZedmanager {
		log.Printf("handleCreate: for %s IsZedmanager\n",
			config.DisplayName)
		if len(config.OverlayNetworkList) != 1 ||
			len(config.UnderlayNetworkList) != 0 {
			// XXX report IsZedmanager error to cloud?
			err := errors.New("Malformed IsZedmanager config; ignored")
			status.PendingAdd = false
			addError(ctx, &status, "IsZedmanager", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		ctx.separateDataPlane = config.SeparateDataPlane

		// Use this olIfname to name files
		// XXX some files might not be used until Zedmanager becomes
		// a domU at which point IsZedMansger boolean won't be needed
		olConfig := config.OverlayNetworkList[0]
		olNum := 1
		olIfname := "dbo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		// Assume there is no UUID for management overlay

		// Create olIfname dummy interface with EID and fd00::/8 route
		// pointing at it.
		// XXX also a separate route for eidAllocationPrefix if global

		// Start clean
		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Dummy{LinkAttrs: attrs}
		netlink.LinkDel(oLink)

		//    ip link add ${olIfname} type dummy
		attrs = netlink.NewLinkAttrs()
		attrs.Name = olIfname
		// Note: we ignore olConfig.AppMacAddr for IsMgmt
		olIfMac := fmt.Sprintf("00:16:3e:02:%02x:%02x", olNum, appNum)
		hw, err := net.ParseMAC(olIfMac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", olIfMac, err)
		}
		attrs.HardwareAddr = hw
		oLink = &netlink.Dummy{LinkAttrs: attrs}
		if err := netlink.LinkAdd(oLink); err != nil {
			errStr := fmt.Sprintf("LinkAdd on %s failed: %s",
				olIfname, err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		// ip link set ${olIfname} mtu 1280
		if err := netlink.LinkSetMTU(oLink, 1280); err != nil {
			errStr := fmt.Sprintf("LinkSetMTU on %s failed: %s",
				olIfname, err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		//    ip link set ${olIfname} up
		if err := netlink.LinkSetUp(oLink); err != nil {
			errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
				olIfname, err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		//    ip link set ${olIfname} arp on
		if err := netlink.LinkSetARPOn(oLink); err != nil {
			errStr := fmt.Sprintf("LinkSetARPOn on %s failed: %s",
				olIfname, err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		// Configure the EID on olIfname and set up a default route
		// for all fd00 EIDs
		//    ip addr add ${EID}/128 dev ${olIfname}
		EID := olConfig.EID
		addr, err := netlink.ParseAddr(EID.String() + "/128")
		if err != nil {
			errStr := fmt.Sprintf("ParseAddr %s failed: %s",
				EID, err)
			status.PendingAdd = false
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		if err := netlink.AddrAdd(oLink, addr); err != nil {
			errStr := fmt.Sprintf("AddrAdd %s failed: %s", EID, err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		//    ip route add fd00::/8 via fe80::1 dev $intf
		index := oLink.Attrs().Index
		_, ipnet, err := net.ParseCIDR("fd00::/8")
		if err != nil {
			log.Fatal("ParseCIDR fd00::/8 failed:\n", err)
		}
		via := net.ParseIP("fe80::1")
		if via == nil {
			log.Fatal("ParseIP fe80::1 failed: ", err)
		}
		// Need to do both an add and a change since we could have
		// a FAILED neighbor entry from a previous run and a down
		// uplink interface.
		//    ip nei add fe80::1 lladdr 00:16:3e:02:01:00 dev $intf
		//    ip nei change fe80::1 lladdr 00:16:3e:02:01:00 dev $intf
		neigh := netlink.Neigh{LinkIndex: index, IP: via,
			HardwareAddr: hw, State: netlink.NUD_PERMANENT}
		if err := netlink.NeighAdd(&neigh); err != nil {
			errStr := fmt.Sprintf("NeighAdd fe80::1 failed: %s",
				err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}
		if err := netlink.NeighSet(&neigh); err != nil {
			errStr := fmt.Sprintf("NeighSet fe80::1 failed: %s",
				err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		rt := netlink.Route{Dst: ipnet, LinkIndex: index, Gw: via}
		if err := netlink.RouteAdd(&rt); err != nil {
			errStr := fmt.Sprintf("RouteAdd fd00::/8 failed: %s",
				err)
			addError(ctx, &status, "IsZedmanager",
				errors.New(errStr))
		}

		// XXX NOTE: this hosts file is not read!
		// XXX easier when Zedmanager is in separate domU!
		// Create a hosts file for the overlay based on NameToEidList
		// Directory is /var/run/zedrouter/hosts.${OLIFNAME}
		// Each hostname in a separate file in directory to facilitate
		// adds and deletes
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		deleteHostsConfiglet(hostsDirpath, false)
		createHostsConfiglet(hostsDirpath, olConfig.NameToEidList)

		// Default EID ipset
		deleteEidIpsetConfiglet(olIfname, false)
		createEidIpsetConfiglet(olIfname, olConfig.NameToEidList,
			EID.String())

		// Set up ACLs
		err = createACLConfiglet(olIfname, true, olConfig.ACLs,
			6, "", "", nil)
		if err != nil {
			addError(ctx, &status, "createACL", err)
		}

		// Save information about zedmanger EID and additional info
		deviceEID = EID
		deviceIID = olConfig.IID
		additionalInfoDevice = olConfig.AdditionalInfoDevice

		additionalInfo := generateAdditionalInfo(status, olConfig)

		// Create LISP configlets for IID and EID/signature
		createLispConfiglet(lispRunDirname, config.IsZedmanager,
			olConfig.IID, olConfig.EID, olConfig.LispSignature,
			deviceNetworkStatus, olIfname, olIfname,
			additionalInfo, olConfig.LispServers, ctx.separateDataPlane)
		status.OverlayNetworkList = make([]types.OverlayNetworkStatus,
			len(config.OverlayNetworkList))
		for i, _ := range config.OverlayNetworkList {
			status.OverlayNetworkList[i].OverlayNetworkConfig =
				config.OverlayNetworkList[i]
		}
		status.PendingAdd = false
		publishAppNetworkStatus(ctx, &status)
		log.Printf("handleCreate done for %s\n", config.DisplayName)
		return
	}

	// Check that Network exists for all overlays and underlays.
	// XXX if not, for now just delete status and the periodic walk will
	// retry
	allNetworksExist := true
	for _, olConfig := range config.UnderlayNetworkList {
		netconfig := lookupNetworkObjectConfig(ctx,
			olConfig.Network.String())
		if netconfig != nil {
			continue
		}
		log.Printf("handleCreate(%v) for %s: missing overlay network %s\n",
			config.UUIDandVersion, config.DisplayName,
			olConfig.Network.String())
		allNetworksExist = false
	}
	for _, ulConfig := range config.UnderlayNetworkList {
		netconfig := lookupNetworkObjectConfig(ctx,
			ulConfig.Network.String())
		if netconfig != nil {
			continue
		}
		log.Printf("handleCreate(%v) for %s: missing underlay network %s\n",
			config.UUIDandVersion, config.DisplayName,
			ulConfig.Network.String())
		allNetworksExist = false
	}
	if !allNetworksExist {
		log.Printf("handleCreate(%v) for %s: missing networks XXX defer\n",
			config.UUIDandVersion, config.DisplayName)
		unpublishAppNetworkStatus(ctx, &status)
		return
	}

	olcount := len(config.OverlayNetworkList)
	if olcount > 0 {
		log.Printf("Received olcount %d\n", olcount)
	}
	status.OverlayNetworkList = make([]types.OverlayNetworkStatus,
		olcount)
	for i, _ := range config.OverlayNetworkList {
		status.OverlayNetworkList[i].OverlayNetworkConfig =
			config.OverlayNetworkList[i]
	}
	ulcount := len(config.UnderlayNetworkList)
	status.UnderlayNetworkList = make([]types.UnderlayNetworkStatus,
		ulcount)
	for i, _ := range config.UnderlayNetworkList {
		status.UnderlayNetworkList[i].UnderlayNetworkConfig =
			config.UnderlayNetworkList[i]
	}

	// XXX note that with IPv4/IPV6/LISP interfaces the domU can do
	// dns lookups on either, hence should configure the ipsets
	// for all the domU's interfaces/bridges.
	// XXX plus dnsmasq serves the Linux bridge hence need a loop
	// akin to that in updateNetworkACLConfiglet()

	// XXX ipsets := compileAppInstanceIpsets(ctx, config.OverlayNetworkList,
	// 	config.UnderlayNetworkList)
	for i, olConfig := range config.OverlayNetworkList {
		olNum := i + 1
		if debug {
			log.Printf("olNum %d network %s ACLs %v\n",
				olNum, olConfig.Network.String(), olConfig.ACLs)
		}
		EID := olConfig.EID
		bridgeName := "bo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		vifName := "nbo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		oLink, err := findBridge(bridgeName)
		if err != nil {
			status.PendingAdd = false
			addError(ctx, &status, "findBridge", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		bridgeName = oLink.Name
		bridgeMac := oLink.HardwareAddr
		log.Printf("bridgeName %s MAC %s\n",
			bridgeName, bridgeMac.String())

		var appMac string // Handed to domU
		if olConfig.AppMacAddr != nil {
			appMac = olConfig.AppMacAddr.String()
		} else {
			appMac = "00:16:3e:01:" +
				strconv.FormatInt(int64(olNum), 16) + ":" +
				strconv.FormatInt(int64(appNum), 16)
		}
		log.Printf("appMac %s\n", appMac)

		// Record what we have so far
		olStatus := &status.OverlayNetworkList[olNum-1]
		olStatus.Bridge = bridgeName
		olStatus.BridgeMac = bridgeMac
		olStatus.Vif = vifName
		olStatus.Mac = appMac
		olStatus.HostName = config.Key()

		// XXX need to get bridgeIPAddr from bridge and record it?
		// XXX add AF_INET6 to getBridgeServiceIPv6Addr(ctx, olconfig.Network)
		// Or configure this additional address?
		bridgeIPAddr := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		log.Printf("bridgeIPAddr %s EID %s\n", bridgeIPAddr, EID)

		olStatus.BridgeIPAddr = bridgeIPAddr

		// Create a hosts file for the overlay based on NameToEidList
		// Directory is /var/run/zedrouter/hosts.${BRIDGENAME}
		// Each hostname in a separate file in directory to facilitate
		// adds and deletes
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		// XXX add bulk add function? Separate create from add?
		for _, ne := range olConfig.NameToEidList {
			addIPToHostsConfiglet(hostsDirpath, ne.HostName,
				ne.EIDs)
		}
		// Create default ipset with all the EIDs in NameToEidList
		// Can be used in ACLs by specifying "alleids" as match.
		deleteEidIpsetConfiglet(bridgeName, false)
		createEidIpsetConfiglet(bridgeName, olConfig.NameToEidList,
			EID.String())

		netstatus := lookupNetworkObjectStatus(ctx,
			olConfig.Network.String())
		if netstatus == nil {
			// We had a netconfig but no status!
			status.PendingAdd = false
			errStr := fmt.Sprintf("no status for %s",
				olConfig.Network.String())
			err = errors.New(errStr)
			addError(ctx, &status, "lookupNetworkObjectStatus", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}

		// Set up ACLs before we setup dnsmasq
		err = updateNetworkACLConfiglet(ctx, netstatus)
		if err != nil {
			addError(ctx, &status, "updateNetworkACL", err)
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		publishAppNetworkStatus(ctx, &status)

		// XXX need ipsets from all bn<N> users? Or apply to nbn at
		// bridge? Still need across multiple interfaces for app
		// Apply at bridge based on ACL, but track in dnsmasq?
		// XXX foo.example.org and example.org on from different
		// apps on same bridge??? Does dnsmasq populate both?

		addhostDnsmasq(bridgeName, appMac, EID.String(),
			config.UUIDandVersion.UUID.String())

		additionalInfo := generateAdditionalInfo(status, olConfig)
		// Create LISP configlets for IID and EID/signature
		createLispConfiglet(lispRunDirname, config.IsZedmanager,
			olConfig.IID, olConfig.EID, olConfig.LispSignature,
			deviceNetworkStatus, bridgeName, bridgeName,
			additionalInfo, olConfig.LispServers,
			ctx.separateDataPlane)
	}

	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		if debug {
			log.Printf("ulNum %d network %s ACLs %v\n",
				ulNum, ulConfig.Network.String(), ulConfig.ACLs)
		}
		bridgeName := "bu" + strconv.Itoa(appNum)
		vifName := "nbu" + strconv.Itoa(ulNum) + "x" +
			strconv.Itoa(appNum)
		uLink, err := findBridge(bridgeName)
		if err != nil {
			status.PendingAdd = false
			addError(ctx, &status, "findBridge", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		bridgeName = uLink.Name
		bridgeMac := uLink.HardwareAddr

		log.Printf("bridgeName %s MAC %s\n",
			bridgeName, bridgeMac.String())

		var appMac string // Handed to domU
		if ulConfig.AppMacAddr != nil {
			appMac = ulConfig.AppMacAddr.String()
		} else {
			// Room to handle multiple underlays in 5th byte
			appMac = fmt.Sprintf("00:16:3e:00:%02x:%02x",
				ulNum, appNum)
		}
		log.Printf("appMac %s\n", appMac)

		// Record what we have so far
		ulStatus := &status.UnderlayNetworkList[ulNum-1]
		ulStatus.Bridge = bridgeName
		ulStatus.BridgeMac = bridgeMac
		ulStatus.Vif = vifName
		ulStatus.Mac = appMac
		ulStatus.HostName = config.Key()

		netstatus := lookupNetworkObjectStatus(ctx,
			ulConfig.Network.String())
		if netstatus == nil {
			// We had a netconfig but no status!
			status.PendingAdd = false
			errStr := fmt.Sprintf("no status for %s",
				ulConfig.Network.String())
			err = errors.New(errStr)
			addError(ctx, &status, "lookupNetworkObjectStatus", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		bridgeIPAddr, appIPAddr := getUlAddrs(ctx, ulNum-1, appNum, ulStatus,
			netstatus)
		// Check if we already have an address on the bridge
		bridgeIP, err := getBridgeServiceIPv4Addr(ctx, ulConfig.Network)
		if err != nil {
			log.Printf("handleCreate getBridgeServiceIPv4Addr %s\n",
				err)
		} else if bridgeIP != "" {
			bridgeIPAddr = bridgeIP
		}
		log.Printf("bridgeIPAddr %s appIPAddr %s\n", bridgeIPAddr, appIPAddr)
		ulStatus.BridgeIPAddr = bridgeIPAddr
		ulStatus.AssignedIPAddr = appIPAddr
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		addToHostsConfiglet(hostsDirpath, config.DisplayName,
			[]string{appIPAddr})

		// Create iptables with optional ipset's based ACL
		// XXX Doesn't handle IPv6 underlay ACLs

		err = updateNetworkACLConfiglet(ctx, netstatus)
		if err != nil {
			addError(ctx, &status, "updateNetworkACL", err)
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		publishAppNetworkStatus(ctx, &status)

		// XXX need ipsets from all bn<N> users? Or apply to nbn at bridge?

		addhostDnsmasq(bridgeName, appMac, appIPAddr,
			config.UUIDandVersion.UUID.String())
	}
	// Write out what we created to AppNetworkStatus
	status.PendingAdd = false
	publishAppNetworkStatus(ctx, &status)
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

// Returns the link
func findBridge(bridgeName string) (*netlink.Bridge, error) {

	var bridgeLink *netlink.Bridge
	link, err := netlink.LinkByName(bridgeName)
	if link == nil {
		errStr := fmt.Sprintf("findBridge(%s) failed %s",
			bridgeName, err)
		// XXX how to handle this failure? bridge
		// disappeared?
		return nil, errors.New(errStr)
	}
	switch link.(type) {
	case *netlink.Bridge:
		bridgeLink = link.(*netlink.Bridge)
	default:
		errStr := fmt.Sprintf("findBridge(%s) not a bridge %T",
			bridgeName, link)
		// XXX why wouldn't it be a bridge?
		return nil, errors.New(errStr)
	}
	return bridgeLink, nil
}

// XXX IPv6? LISP? Same? getOlAddrs???
func getUlAddrs(ctx *zedrouterContext, ifnum int, appNum int,
	status *types.UnderlayNetworkStatus,
	netstatus *types.NetworkObjectStatus) (string, string) {

	log.Printf("getUlAddrs(%d/%d)\n", ifnum, appNum)

	// Default
	// Not clear how to handle multiple ul from the same appInstance;
	// use /30 prefix? Require user to pick private addrs?
	// XXX limited number of ifnums for the default range - just to 27 to 31
	bridgeIPAddr := fmt.Sprintf("172.%d.%d.1", 27+ifnum, appNum)
	appIPAddr := fmt.Sprintf("172.%d.%d.2", 27+ifnum, appNum)

	// Allocate bridgeIPAddr based on BridgeMac
	log.Printf("getUlAddrs(%d/%d for %s) bridgeMac %s\n",
		ifnum, appNum, netstatus.UUID.String(),
		status.BridgeMac.String())
	addr, err := lookupOrAllocateIPv4(ctx, netstatus,
		status.BridgeMac)
	if err != nil {
		log.Printf("lookupOrAllocatePv4 failed %s\n", err)
		// Keep above default
	} else {
		bridgeIPAddr = addr
	}

	if status.AppIPAddr != nil {
		// Static IP assignment case.
		// Note that appIPAddr can be in a different subnet.
		// Assumption is that the config specifies a gateway/router
		// in the same subnet as the static address.
		appIPAddr = status.AppIPAddr.String()
	} else {
		// XXX or change type of VifInfo.Mac?
		mac, err := net.ParseMAC(status.Mac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", status.Mac, err)
		}
		log.Printf("getUlAddrs(%d/%d for %s) app Mac %s\n",
			ifnum, appNum, netstatus.UUID.String(), mac.String())
		addr, err := lookupOrAllocateIPv4(ctx, netstatus, mac)
		if err != nil {
			log.Printf("lookupOrAllocateIPv4 failed %s\n", err)
			// Keep above default
		} else {
			appIPAddr = addr
		}
	}
	log.Printf("getUlAddrs(%d/%d) done %s/%s\n",
		ifnum, appNum, bridgeIPAddr, appIPAddr)
	return bridgeIPAddr, appIPAddr
}

// Caller should clear the appropriate status.Pending* if the the caller will
// return after adding the error.
func addError(ctx *zedrouterContext,
	status *types.AppNetworkStatus, tag string, err error) {

	log.Printf("%s: %s\n", tag, err.Error())
	status.Error = appendError(status.Error, tag, err.Error())
	status.ErrorTime = time.Now()
	publishAppNetworkStatus(ctx, status)
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

// Note that handleModify will not touch the EID; just ACLs and NameToEidList
// XXX should we check that nothing else has changed?
// XXX If so flag other changes as errors; would need lastError in status.
func handleModify(ctx *zedrouterContext, key string,
	config types.AppNetworkConfig, status *types.AppNetworkStatus) {

	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// No check for version numbers since the ACLs etc might change
	// even for the same version.

	appNum := status.AppNum
	if debug {
		log.Printf("handleModify appNum %d\n", appNum)
	}

	// Check for unsupported changes
	if config.IsZedmanager != status.IsZedmanager {
		errStr := fmt.Sprintf("Unsupported: IsZedmanager changed for %s",
			config.UUIDandVersion)
		status.PendingModify = false
		addError(ctx, status, "handleModify", errors.New(errStr))
		log.Printf("handleModify done for %s\n", config.DisplayName)
		return
	}
	// XXX We could should we allow the addition of interfaces
	// if the domU would find out through some hotplug event.
	// But deletion is hard.
	// For now don't allow any adds or deletes.
	if len(config.OverlayNetworkList) != status.OlNum {
		errStr := fmt.Sprintf("Unsupported: Changed number of overlays for %s",
			config.UUIDandVersion)
		status.PendingModify = false
		addError(ctx, status, "handleModify", errors.New(errStr))
		log.Printf("handleModify done for %s\n", config.DisplayName)
		return
	}
	if len(config.UnderlayNetworkList) != status.UlNum {
		errStr := fmt.Sprintf("Unsupported: Changed number of underlays for %s",
			config.UUIDandVersion)
		status.PendingModify = false
		addError(ctx, status, "handleModify", errors.New(errStr))
		log.Printf("handleModify done for %s\n", config.DisplayName)
		return
	}

	status.SeparateDataPlane = ctx.separateDataPlane
	status.PendingModify = true
	status.UUIDandVersion = config.UUIDandVersion
	publishAppNetworkStatus(ctx, status)

	if config.IsZedmanager {
		if config.SeparateDataPlane != ctx.separateDataPlane {
			errStr := fmt.Sprintf("Unsupported: Changing experimental data plane flag on the fly\n")

			status.PendingModify = false
			addError(ctx, status, "handleModify",
				errors.New(errStr))
			log.Printf("handleModify done for %s\n",
				config.DisplayName)
			return
		}
		olConfig := config.OverlayNetworkList[0]
		olStatus := status.OverlayNetworkList[0]
		olNum := 1
		olIfname := "dbo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		// Assume there is no UUID for management overlay

		// Note: we ignore olConfig.AppMacAddr for IsMgmt

		// Update hosts
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		updateHostsConfiglet(hostsDirpath, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Default EID ipset
		updateEidIpsetConfiglet(olIfname, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Update ACLs
		err := updateACLConfiglet(olIfname, true, olStatus.ACLs,
			olConfig.ACLs, 6, "", "", nil)
		if err != nil {
			addError(ctx, status, "updateACL", err)
		}
		status.PendingModify = false
		publishAppNetworkStatus(ctx, status)
		log.Printf("handleModify done for %s\n", config.DisplayName)
		return
	}

	// XXX note that with IPv4/IPV6/LISP interfaces the domU can do
	// dns lookups on either, hence should configure the ipsets
	// for all the domU's interfaces/bridges.
	newIpsets, staleIpsets, restartDnsmasq := updateAppInstanceIpsets(ctx,
		config.OverlayNetworkList,
		config.UnderlayNetworkList,
		status.OverlayNetworkList,
		status.UnderlayNetworkList)

	// Look for ACL and NametoEidList changes in overlay
	for i, olConfig := range config.OverlayNetworkList {
		olNum := i + 1
		if debug {
			log.Printf("handleModify olNum %d\n", olNum)
		}
		// Need to check that index exists
		if len(status.OverlayNetworkList) < olNum {
			log.Println("Missing status for overlay %d; can not modify\n",
				olNum)
			continue
		}
		olStatus := status.OverlayNetworkList[olNum-1]
		bridgeName := olStatus.Bridge
		bridgeIPAddr := olStatus.BridgeIPAddr

		netconfig := lookupNetworkObjectConfig(ctx,
			olConfig.Network.String())
		// Update hosts
		// XXX doesn't handle a sharedBridge; need union of
		// all hosts on bridge
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		updateHostsConfiglet(hostsDirpath, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Default EID ipset
		// XXX shared with others; need union of all hosts on bridge
		// or per client bridge port ACLs
		updateEidIpsetConfiglet(bridgeName, olStatus.NameToEidList,
			olConfig.NameToEidList)

		netstatus := lookupNetworkObjectStatus(ctx,
			olConfig.Network.String())
		// XXX could the netstatus have disappeared after the create?
		// Update ACLs
		if netstatus != nil {
			err := updateNetworkACLConfiglet(ctx, netstatus)
			if err != nil {
				addError(ctx, status, "updateNetworkACL", err)
			}
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		publishAppNetworkStatus(ctx, status)

		// updateAppInstanceIpsets told us whether there is a change
		// to the set of ipsets, and that requires restarting dnsmasq
		// XXX shared with others
		if false && restartDnsmasq {
			cfgFilename := "dnsmasq." + bridgeName + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			EID := olConfig.EID
			stopDnsmasq(bridgeName, false)
			//remove old dnsmasq configuration file
			os.Remove(cfgPathname)
			// XXX need to determine remaining ipsets. Inside function?
			createDnsmasqOverlayConfiglet(ctx, cfgPathname, bridgeName,
				bridgeIPAddr, EID.String(), olStatus.Mac, hostsDirpath,
				config.Key(), newIpsets,
				netconfig)
			startDnsmasq(bridgeName)
		}

		additionalInfo := generateAdditionalInfo(*status, olConfig)

		// Update any signature changes
		// XXX should we check that EID didn't change?

		// Create LISP configlets for IID and EID/signature
		// XXX shared with others???
		updateLispConfiglet(lispRunDirname, false, olConfig.IID,
			olConfig.EID, olConfig.LispSignature,
			deviceNetworkStatus, bridgeName, bridgeName,
			additionalInfo, olConfig.LispServers, ctx.separateDataPlane)

	}
	// Look for ACL changes in underlay
	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		if debug {
			log.Printf("handleModify ulNum %d\n", ulNum)
		}
		// Need to check that index exists
		if len(status.UnderlayNetworkList) < ulNum {
			log.Println("Missing status for underlay %d; can not modify\n",
				ulNum)
			continue
		}
		ulStatus := status.UnderlayNetworkList[ulNum-1]
		bridgeName := ulStatus.Bridge
		bridgeIPAddr := ulStatus.BridgeIPAddr
		appIPAddr := ulStatus.AssignedIPAddr

		netconfig := lookupNetworkObjectConfig(ctx,
			ulConfig.Network.String())

		netstatus := lookupNetworkObjectStatus(ctx,
			ulConfig.Network.String())
		// XXX could the netstatus have disappeared after the create?
		if netstatus != nil {
			err := updateNetworkACLConfiglet(ctx, netstatus)
			if err != nil {
				addError(ctx, status, "updateNetworkACL", err)
			}
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		publishAppNetworkStatus(ctx, status)

		if false && restartDnsmasq {
			//update underlay dnsmasq configuration
			hostsDirpath := globalRunDirname + "/hosts." + bridgeName
			cfgFilename := "dnsmasq." + bridgeName + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			stopDnsmasq(bridgeName, false)
			//remove old dnsmasq configuration file
			os.Remove(cfgPathname)
			// XXX need ipsets from all bn<N> users
			createDnsmasqUnderlayConfiglet(ctx, cfgPathname, bridgeName,
				bridgeIPAddr, appIPAddr, ulStatus.Mac,
				hostsDirpath,
				config.Key(), newIpsets,
				netconfig)
			startDnsmasq(bridgeName)
		}
	}

	// Remove stale ipsets
	// In case if there are any references to these ipsets from other
	// domUs, then the kernel would not remove them.
	// The ipset destroy command would just fail.
	for _, ipset := range staleIpsets {
		err := ipsetDestroy(fmt.Sprintf("ipv4.%s", ipset))
		if err != nil {
			log.Println("ipset destroy ipv4", ipset, err)
		}
		err = ipsetDestroy(fmt.Sprintf("ipv6.%s", ipset))
		if err != nil {
			log.Println("ipset destroy ipv6", ipset, err)
		}
	}

	// Write out what we modified to AppNetworkStatus
	status.OverlayNetworkList = make([]types.OverlayNetworkStatus,
		len(config.OverlayNetworkList))
	for i, _ := range config.OverlayNetworkList {
		status.OverlayNetworkList[i].OverlayNetworkConfig =
			config.OverlayNetworkList[i]
	}
	status.UnderlayNetworkList = make([]types.UnderlayNetworkStatus,
		len(config.UnderlayNetworkList))
	for i, _ := range config.UnderlayNetworkList {
		status.UnderlayNetworkList[i].UnderlayNetworkConfig =
			config.UnderlayNetworkList[i]
	}
	status.PendingModify = false
	publishAppNetworkStatus(ctx, status)
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctx *zedrouterContext, key string,
	status *types.AppNetworkStatus) {

	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	appNum := status.AppNum
	maxOlNum := status.OlNum
	maxUlNum := status.UlNum
	if debug {
		log.Printf("handleDelete appNum %d maxOlNum %d maxUlNum %d\n",
			appNum, maxOlNum, maxUlNum)
	}

	status.PendingDelete = true
	publishAppNetworkStatus(ctx, status)

	if status.IsZedmanager {
		if len(status.OverlayNetworkList) != 1 ||
			len(status.UnderlayNetworkList) != 0 {
			errStr := "Malformed IsZedmanager status; ignored"
			status.PendingDelete = false
			addError(ctx, status, "handleDelete",
				errors.New(errStr))
			log.Printf("handleDelete done for %s\n",
				status.DisplayName)
			return
		}
		// Remove global state for device
		deviceEID = net.IP{}
		deviceIID = 0
		additionalInfoDevice = nil

		olNum := 1
		olStatus := &status.OverlayNetworkList[0]
		olIfname := "dbo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		// Assume there is no UUID for management overlay

		// Delete the address from loopback
		// Delete fd00::/8 route
		// Delete fe80::1 neighbor

		//    ip addr del ${EID}/128 dev ${olIfname}
		EID := status.OverlayNetworkList[0].EID
		addr, err := netlink.ParseAddr(EID.String() + "/128")
		if err != nil {
			errStr := fmt.Sprintf("ParseAddr %s failed: %s",
				EID, err)
			status.PendingDelete = false
			addError(ctx, status, "handleDelete",
				errors.New(errStr))
			log.Printf("handleDelete done for %s\n",
				status.DisplayName)
			return
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Dummy{LinkAttrs: attrs}
		// XXX can we skip explicit deletes and just remove the oLink?
		if err := netlink.AddrDel(oLink, addr); err != nil {
			errStr := fmt.Sprintf("AddrDel %s failed: %s",
				EID, err)
			addError(ctx, status, "handleDelete",
				errors.New(errStr))
		}

		//    ip route del fd00::/8 via fe80::1 dev $intf
		index := oLink.Attrs().Index
		_, ipnet, err := net.ParseCIDR("fd00::/8")
		if err != nil {
			log.Fatal("ParseCIDR fd00::/8 failed:\n", err)
		}
		via := net.ParseIP("fe80::1")
		if via == nil {
			log.Fatal("ParseIP fe80::1 failed: ", err)
		}
		rt := netlink.Route{Dst: ipnet, LinkIndex: index, Gw: via}
		if err := netlink.RouteDel(&rt); err != nil {
			errStr := fmt.Sprintf("RouteDel fd00::/8 failed: %s",
				err)
			addError(ctx, status, "handleDelete",
				errors.New(errStr))
		}
		//    ip nei del fe80::1 lladdr 0:0:0:0:0:1 dev $intf
		neigh := netlink.Neigh{LinkIndex: index, IP: via}
		if err := netlink.NeighDel(&neigh); err != nil {
			errStr := fmt.Sprintf("NeighDel fe80::1 failed: %s",
				err)
			addError(ctx, status, "handleDelete",
				errors.New(errStr))
		}

		// Remove link and associated addresses
		netlink.LinkDel(oLink)

		// Delete overlay hosts file
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		deleteHostsConfiglet(hostsDirpath, true)

		// Default EID ipset
		deleteEidIpsetConfiglet(olIfname, true)

		// Delete ACLs
		err = deleteACLConfiglet(olIfname, true, olStatus.ACLs,
			6, "", "", nil)
		if err != nil {
			addError(ctx, status, "deleteACL", err)
		}

		// Delete LISP configlets
		deleteLispConfiglet(lispRunDirname, true, olStatus.IID,
			olStatus.EID, deviceNetworkStatus, ctx.separateDataPlane)
	} else {
		// Delete everything for overlay
		for olNum := 1; olNum <= maxOlNum; olNum++ {
			if debug {
				log.Printf("handleDelete olNum %d\n", olNum)
			}
			// Need to check that index exists
			if len(status.OverlayNetworkList) < olNum {
				log.Println("Missing status for overlay %d; can not clean up\n",
					olNum)
				continue
			}

			olStatus := status.OverlayNetworkList[olNum-1]
			bridgeName := olStatus.Bridge

			// XXX need IPv6 allocate/free to do same as for ulConfig
			// XXX createDnsmasq assumes it can read this to get netstatus
			publishAppNetworkStatus(ctx, status)

			appMac := olStatus.Mac
			removehostDnsmasq(bridgeName, appMac)

			// Delete ACLs
			netstatus := lookupNetworkObjectStatus(ctx,
				olStatus.Network.String())
			// XXX could the netstatus have disappeared after the create?
			if netstatus != nil {
				err := updateNetworkACLConfiglet(ctx, netstatus)
				if err != nil {
					addError(ctx, status,
						"updateNetworkACL", err)
				}
			}

			// Delete LISP configlets
			deleteLispConfiglet(lispRunDirname, false,
				olStatus.IID, olStatus.EID,
				deviceNetworkStatus,
				ctx.separateDataPlane)

			// Delete overlay hosts file
			hostsDirpath := globalRunDirname + "/hosts." + bridgeName
			removeFromHostsConfiglet(hostsDirpath,
				status.DisplayName)

			// Default EID ipset
			// XXX not all of it? Set per app/olifname and not
			// shared across bridge?
			deleteEidIpsetConfiglet(bridgeName, true)
		}

		// XXX check if any IIDs are now unreferenced and delete them
		// XXX requires looking at all of configDir and statusDir

		// Delete everything in underlay
		for ulNum := 1; ulNum <= maxUlNum; ulNum++ {
			if debug {
				log.Printf("handleDelete ulNum %d\n", ulNum)
			}
			// Need to check that index exists
			if len(status.UnderlayNetworkList) < ulNum {
				log.Println("Missing status for underlay %d; can not clean up\n",
					ulNum)
				continue
			}
			ulStatus := status.UnderlayNetworkList[ulNum-1]
			bridgeName := ulStatus.Bridge

			netstatus := lookupNetworkObjectStatus(ctx,
				ulStatus.Network.String())
			// XXX could the netstatus have disappeared after the create?
			if netstatus != nil {
				// XXX or change type of VifInfo.Mac?
				mac, err := net.ParseMAC(ulStatus.Mac)
				if err != nil {
					log.Fatal("ParseMAC failed: ",
						ulStatus.Mac, err)
				}
				_, err = releaseIPv4(ctx, netstatus, mac)
				// XXX publish error?
				if err != nil {
					addError(ctx, status, "freeIPv4", err)
				}
			}
			// XXX createDnsmasq assumes it can read this to get netstatus
			publishAppNetworkStatus(ctx, status)

			appMac := ulStatus.Mac
			removehostDnsmasq(bridgeName, appMac)

			// Delete ACLs
			if netstatus != nil {
				err := updateNetworkACLConfiglet(ctx, netstatus)
				if err != nil {
					addError(ctx, status,
						"updateNetworkACL", err)
				}
			}
			// Delete underlay hosts file
			hostsDirpath := globalRunDirname + "/hosts." + bridgeName
			removeFromHostsConfiglet(hostsDirpath,
				status.DisplayName)
		}
	}
	status.PendingDelete = false
	publishAppNetworkStatus(ctx, status)

	// Write out what we modified to AppNetworkStatus aka delete
	unpublishAppNetworkStatus(ctx, status)

	appNumFree(status.UUIDandVersion.UUID)
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

func pkillUserArgs(userName string, match string, printOnError bool) {
	cmd := "pkill"
	args := []string{
		// XXX note that alpine does not support -u
		// XXX		"-u",
		// XXX		userName,
		"-f",
		match,
	}
	_, err := wrap.Command(cmd, args...).Output()
	if err != nil && printOnError {
		log.Printf("Command %v %v failed: %s\n", cmd, args, err)
	}
}
