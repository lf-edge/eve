// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Process input changes from a config directory containing json encoded files
// with AppNetworkConfig and compare against AppNetworkStatus in the status
// dir.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables, lisp.config,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/adapters"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"github.com/zededa/go-provision/wrap"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	agentName     = "zedrouter"
	runDirname    = "/var/run/zedrouter"
	baseDirname   = "/var/tmp/zedrouter"
	configDirname = baseDirname + "/config"
	statusDirname = runDirname + "/status"
	tmpDirname    = "/var/tmp/zededa"
	DNCDirname    = tmpDirname + "/DeviceNetworkConfig"
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
	assignableAdapters      *types.AssignableAdapters
}

// Dummy since we don't have anything to pass
type dummyContext struct {
}

// Context for handleDNCModify
type DNCContext struct {
	usableAddressCount     int
	manufacturerModel      string
	separateDataPlane      bool
	pubDeviceNetworkStatus *pubsub.Publication // XXX set
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
	debug = true // XXX XXX remove
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)
	watch.CleanupRestarted(agentName)

	if _, err := os.Stat(baseDirname); err != nil {
		log.Printf("Create %s\n", baseDirname)
		if err := os.Mkdir(baseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(configDirname); err != nil {
		log.Printf("Create %s\n", configDirname)
		if err := os.Mkdir(configDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
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

	if _, err := os.Stat(statusDirname); err != nil {
		log.Printf("Create %s\n", statusDirname)
		if err := os.Mkdir(statusDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(DNCDirname); err != nil {
		log.Printf("Create %s\n", DNCDirname)
		if err := os.MkdirAll(DNCDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	pubDeviceNetworkStatus, err := pubsub.Publish(agentName,
		types.DeviceNetworkStatus{})
	if err != nil {
		log.Fatal(err)
	}

	appNumAllocatorInit(statusDirname, configDirname)
	model := hardware.GetHardwareModel()

	// Pick up (mostly static) AssignableAdapters before we process
	// any Routes; Pbr needs to know which network adapters are assignable
	aa := types.AssignableAdapters{}
	aaChanges, aaFunc, aaCtx := adapters.Init(&aa, model)

	for !aaCtx.Found {
		log.Printf("Waiting - aaCtx %v\n", aaCtx.Found)
		select {
		case change := <-aaChanges:
			aaFunc(&aaCtx, change)
		}
	}
	log.Printf("Have %d assignable adapters\n", len(aa.IoBundleList))

	// XXX Should we wait for the DNCFilename same way as we wait
	// for AssignableAdapter filename?

	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	handleInit(DNCFilename, runDirname, pubDeviceNetworkStatus)

	DNCctx := DNCContext{}
	DNCctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	DNCctx.manufacturerModel = model
	DNCctx.separateDataPlane = false
	DNCctx.pubDeviceNetworkStatus = pubDeviceNetworkStatus

	zedrouterCtx := zedrouterContext{
		separateDataPlane:  false,
		assignableAdapters: &aa,
	}
	// Create publish before subscribing and activating subscriptions
	pubNetworkObjectStatus, err := pubsub.Publish(agentName,
		types.NetworkObjectStatus{})
	pubNetworkServiceStatus, err := pubsub.Publish(agentName,
		types.NetworkServiceStatus{})

	zedrouterCtx.pubNetworkObjectStatus = pubNetworkObjectStatus
	zedrouterCtx.pubNetworkServiceStatus = pubNetworkServiceStatus

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

	// Wait for zedmanager having populated the intial files to
	// reduce the number of LISP-RESTARTs
	restartFile := "/var/tmp/zedrouter/config/restart"
	log.Printf("Waiting for zedmanager to report in %s\n", restartFile)
	watch.WaitForFile(restartFile)
	log.Printf("Zedmanager reported in %s\n", restartFile)

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
			doDNSUpdate(&DNCctx)
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

	handleRestart(&zedrouterCtx, false)
	var restartFn watch.ConfigRestartHandler = handleRestart

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

	configChanges := make(chan string)
	go watch.WatchConfigStatus(configDirname, statusDirname, configChanges)
	deviceConfigChanges := make(chan string)
	go watch.WatchStatus(DNCDirname, deviceConfigChanges)
	for {
		select {
		case change := <-configChanges:
			watch.HandleConfigStatusEvent(change, &zedrouterCtx,
				configDirname, statusDirname,
				&types.AppNetworkConfig{},
				&types.AppNetworkStatus{},
				handleCreate, handleModify, handleDelete,
				&restartFn)
			// DNC handling also re-writes the lisp.config file.
			// We should call the updateLisp with correct Dataplane
			// flag inorder not to confuse lispers.net
			DNCctx.separateDataPlane = zedrouterCtx.separateDataPlane
		case change := <-deviceConfigChanges:
			watch.HandleStatusEvent(change, &DNCctx,
				DNCDirname,
				&types.DeviceNetworkConfig{},
				handleDNCModify, handleDNCDelete,
				nil)
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
				updateDeviceNetworkStatus(pubDeviceNetworkStatus)
			}
		case change := <-subNetworkObjectConfig.C:
			subNetworkObjectConfig.ProcessChange(change)

		case change := <-subNetworkServiceConfig.C:
			subNetworkServiceConfig.ProcessChange(change)

		case change := <-aaChanges:
			aaFunc(&aaCtx, change)
		}
	}
}

func handleRestart(ctxArg interface{}, done bool) {
	if debug {
		log.Printf("handleRestart(%v)\n", done)
	}
	ctx := ctxArg.(*zedrouterContext)
	handleLispRestart(done, ctx.separateDataPlane)
	if done {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		watch.SignalRestarted(agentName)
	}
}

var deviceNetworkConfig types.DeviceNetworkConfig
var deviceNetworkStatus types.DeviceNetworkStatus
var globalRunDirname string
var lispRunDirname string

// XXX hack to avoid the pslisp hang on Erik's laptop
var broken = false

func handleInit(configFilename string, runDirname string,
	pubDeviceNetworkStatus *pubsub.Publication) {

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

	// Need initial deviceNetworkStatus for iptablesInit
	var err error
	deviceNetworkConfig, err = devicenetwork.GetDeviceNetworkConfig(configFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, configFilename)
		log.Fatal(err)
	}
	deviceNetworkStatus, err = devicenetwork.MakeDeviceNetworkStatus(deviceNetworkConfig, deviceNetworkStatus)
	if err != nil {
		log.Printf("%s from MakeDeviceNetworkStatus\n", err)
		// Proceed even if some uplinks are missing
	}

	// Create and write with initial values
	updateDeviceNetworkStatus(pubDeviceNetworkStatus)

	// Setup initial iptables rules
	iptablesInit()

	// ipsets which are independent of config
	createDefaultIpset()

	_, err = wrap.Command("sysctl", "-w",
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

func updateDeviceNetworkStatus(pubDeviceNetworkStatus *pubsub.Publication) {
	pubDeviceNetworkStatus.Publish("global", deviceNetworkStatus)
}

// Key is UUID
var appNetworkStatus map[string]types.AppNetworkStatus
var appNetworkConfig map[string]types.AppNetworkConfig

// XXX rename to update? Remove statusFilename?
//	statusFilename := fmt.Sprintf("/var/run/%s/%s/%s.json",
//		agentName, topic, key)
// XXX introduce separate baseDir whch is /var/run (or /var/run/zededa)??
func writeAppNetworkStatus(status *types.AppNetworkStatus) {

	key := status.UUIDandVersion.UUID.String()
	// topic := "AppNetworkStatus" // XXX reflect to get name of type?
	topic := "status"
	statusFilename := fmt.Sprintf("/var/run/%s/%s/%s.json",
		agentName, topic, key)

	if appNetworkStatus == nil {
		if debug {
			log.Printf("create appNetwork status map\n")
		}
		appNetworkStatus = make(map[string]types.AppNetworkStatus)
	}
	appNetworkStatus[key] = *status

	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal AppNetworkStatus")
	}
	err = pubsub.WriteRename(statusFilename, b)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

// XXX make into generic function with myName as argument.
func removeAppNetworkStatus(status *types.AppNetworkStatus) {
	key := status.UUIDandVersion.UUID.String()
	// topic := "AppNetworkStatus" // XXX reflect to get name of type?
	topic := "status"
	statusFilename := fmt.Sprintf("/var/run/%s/%s/%s.json",
		agentName, topic, key)
	if err := os.Remove(statusFilename); err != nil {
		log.Println(err)
	}
	if _, ok := appNetworkStatus[key]; !ok {
		log.Printf("removeAppNetworkStatus for remove for %s\n", key)
		return
	}
	delete(appNetworkStatus, key)
	// pubsub.UnpublishStatus(agentName, topic, key)
}

// XXX temporary function until we use pubsub for AppNetworkConfig
func recordAppNetworkConfig(config *types.AppNetworkConfig) {

	key := config.UUIDandVersion.UUID.String()

	if appNetworkConfig == nil {
		if debug {
			log.Printf("create appNetworkConfig map\n")
		}
		appNetworkConfig = make(map[string]types.AppNetworkConfig)
	}
	appNetworkConfig[key] = *config
}

// XXX temporary function until we use pubsub for AppNetworkConfig
func removeAppNetworkConfig(key string) {
	if _, ok := appNetworkConfig[key]; !ok {
		log.Printf("removeAppNetworkConfig for remove for %s\n", key)
		return
	}
	delete(appNetworkConfig, key)
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

func updateLispConfiglets(separateDataPlane bool) {
	for _, status := range appNetworkStatus {
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

func handleCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(*types.AppNetworkConfig)
	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	recordAppNetworkConfig(config)

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
	writeAppNetworkStatus(&status)

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
			6, "", "", 0, nil)
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
		writeAppNetworkStatus(&status)
		log.Printf("handleCreate done for %s\n", config.DisplayName)
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

	// XXX use different compile??
	ipsets := compileAppInstanceIpsets(ctx, config.OverlayNetworkList,
		config.UnderlayNetworkList)
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
		oLink, created, err := findOrCreateBridge(ctx, bridgeName,
			olNum, appNum, olConfig.Network)
		if err != nil {
			status.PendingAdd = false
			addError(ctx, &status, "findOrCreateBridge", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		bridgeName = oLink.Name
		bridgeMac := oLink.HardwareAddr
		log.Printf("bridgeName %s MAC %s\n",
			bridgeName, bridgeMac.String())

		var olMac string // Handed to domU
		if olConfig.AppMacAddr != nil {
			olMac = olConfig.AppMacAddr.String()
		} else {
			olMac = "00:16:3e:01:" +
				strconv.FormatInt(int64(olNum), 16) + ":" +
				strconv.FormatInt(int64(appNum), 16)
		}
		log.Printf("olMac %s\n", olMac)

		// Record what we have so far
		olStatus := &status.OverlayNetworkList[olNum-1]
		olStatus.Bridge = bridgeName
		olStatus.BridgeMac = bridgeMac
		olStatus.Vif = vifName
		olStatus.Mac = olMac
		olStatus.HostName = config.UUIDandVersion.UUID.String()

		netconfig := lookupNetworkObjectConfig(ctx,
			olConfig.Network.String())

		// XXX need to get olAddr1 from bridge and record it
		// XXX add AF_INET6 to getBridgeServiceIPv6Addr(ctx, olconfig.Network)
		olAddr1 := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		log.Printf("olAddr1 %s EID %s\n", olAddr1, EID)

		olStatus.BridgeIPAddr = olAddr1

		// XXX set sharedBridge base on bn prefix; remove created return
		if created {
			//    ip addr add ${olAddr1}/128 dev ${bridgeName}
			addr, err := netlink.ParseAddr(olAddr1 + "/128")
			if err != nil {
				errStr := fmt.Sprintf("ParseAddr %s failed: %s",
					olAddr1, err)
				addError(ctx, &status, "handleCreate",
					errors.New(errStr))
			}
			if err := netlink.AddrAdd(oLink, addr); err != nil {
				errStr := fmt.Sprintf("AddrAdd %s failed: %s",
					olAddr1, err)
				addError(ctx, &status, "handleCreate",
					errors.New(errStr))
			}

			//    ip -6 route add ${EID}/128 dev ${bridgeName}
			_, ipnet, err := net.ParseCIDR(EID.String() + "/128")
			if err != nil {
				errStr := fmt.Sprintf("ParseCIDR %s failed: %v",
					EID, err)
				addError(ctx, &status, "handleCreate",
					errors.New(errStr))
			}
			rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
			if err := netlink.RouteAdd(&rt); err != nil {
				errStr := fmt.Sprintf("RouteAdd %s failed: %s",
					EID, err)
				addError(ctx, &status, "handleCreate",
					errors.New(errStr))
			}
		}

		// Write radvd configlet; start radvd
		cfgFilename := "radvd." + bridgeName + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename

		//    Start clean; kill just in case
		//    pkill -u radvd -f radvd.${BRIDGENAME}.conf
		stopRadvd(cfgFilename, false)
		createRadvdConfiglet(cfgPathname, bridgeName)
		startRadvd(cfgPathname, bridgeName)

		// Create a hosts file for the overlay based on NameToEidList
		// Directory is /var/run/zedrouter/hosts.${BRIDGENAME}
		// Each hostname in a separate file in directory to facilitate
		// adds and deletes
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		if created {
			deleteHostsConfiglet(hostsDirpath, false)
			createHostsConfiglet(hostsDirpath, olConfig.NameToEidList)
		} else {
			// XXX add bulk add function? Separate create from add?
			for _, ne := range olConfig.NameToEidList {
				addIPToHostsConfiglet(hostsDirpath, ne.HostName,
					ne.EIDs)
			}
		}
		// Create default ipset with all the EIDs in NameToEidList
		// Can be used in ACLs by specifying "alleids" as match.
		deleteEidIpsetConfiglet(bridgeName, false)
		createEidIpsetConfiglet(bridgeName, olConfig.NameToEidList,
			EID.String())

		netstatus := lookupNetworkObjectStatus(ctx,
			olConfig.Network.String())
		// Set up ACLs before we setup dnsmasq
		if netstatus != nil {
			err = updateNetworkACLConfiglet(ctx, netstatus)
			if err != nil {
				addError(ctx, &status, "updateNetworkACL", err)
			}
		} else {
			err = createACLConfiglet(bridgeName, false, olConfig.ACLs, 6,
				olAddr1, "", 0, netconfig)
			if err != nil {
				addError(ctx, &status, "createACL", err)
			}
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		writeAppNetworkStatus(&status)

		// Start clean
		cfgFilename = "dnsmasq." + bridgeName + ".conf"
		cfgPathname = runDirname + "/" + cfgFilename
		stopDnsmasq(cfgFilename, false)
		// XXX need ipsets from all bn<N> users

		createDnsmasqOverlayConfiglet(ctx, cfgPathname, bridgeName, olAddr1,
			EID.String(), olMac, hostsDirpath,
			config.UUIDandVersion.UUID.String(), ipsets, netconfig)
		startDnsmasq(cfgPathname, bridgeName)

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
		uLink, created, err := findOrCreateBridge(ctx, bridgeName,
			ulNum, appNum, ulConfig.Network)
		if err != nil {
			status.PendingAdd = false
			addError(ctx, &status, "findOrCreateBridge", err)
			log.Printf("handleCreate done for %s\n",
				config.DisplayName)
			return
		}
		bridgeName = uLink.Name
		bridgeMac := uLink.HardwareAddr

		log.Printf("bridgeName %s MAC %s\n",
			bridgeName, bridgeMac.String())

		var ulMac string // Handed to domU
		if ulConfig.AppMacAddr != nil {
			ulMac = ulConfig.AppMacAddr.String()
		} else {
			// Room to handle multiple underlays in 5th byte
			ulMac = fmt.Sprintf("00:16:3e:00:%02x:%02x",
				ulNum, appNum)
		}
		log.Printf("ulMac %s\n", ulMac)

		// Record what we have so far
		ulStatus := &status.UnderlayNetworkList[ulNum-1]
		ulStatus.Bridge = bridgeName
		ulStatus.BridgeMac = bridgeMac
		ulStatus.Vif = vifName
		ulStatus.Mac = ulMac
		ulStatus.HostName = config.UUIDandVersion.UUID.String()

		netconfig := lookupNetworkObjectConfig(ctx,
			ulConfig.Network.String())
		netstatus := lookupNetworkObjectStatus(ctx,
			ulConfig.Network.String())

		ulAddr1, ulAddr2 := getUlAddrs(ctx, ulNum-1, appNum, ulStatus,
			netstatus)
		// Check if we already have an address on the bridge
		// XXX isn't that done inside getUlAddrs?
		if !created {
			bridgeIP, err := getBridgeServiceIPv4Addr(ctx, ulConfig.Network)
			if err != nil {
				log.Printf("handleCreate getBridgeServiceIPv4Addr %s\n",
					err)
			} else if bridgeIP != "" {
				ulAddr1 = bridgeIP
			}
		}
		log.Printf("ulAddr1 %s ulAddr2 %s\n", ulAddr1, ulAddr2)
		ulStatus.BridgeIPAddr = ulAddr1
		ulStatus.AssignedIPAddr = ulAddr2
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName

		if created {
			//    ip addr add ${ulAddr1}/24 dev ${bridgeName}
			addr, err := netlink.ParseAddr(ulAddr1 + "/24")
			if err != nil {
				errStr := fmt.Sprintf("ParseAddr %s failed: %s",
					ulAddr1, err)
				addError(ctx, &status, "handleCreate",
					errors.New(errStr))
			}
			if err := netlink.AddrAdd(uLink, addr); err != nil {
				errStr := fmt.Sprintf("AddrAdd %s failed: %s",
					ulAddr1, err)
				addError(ctx, &status, "handleCreate",
					errors.New(errStr))
			}
			// Create a hosts file for the new bridge
			// Directory is /var/run/zedrouter/hosts.${BRIDGENAME}
			deleteHostsConfiglet(hostsDirpath, false)
			createHostsConfiglet(hostsDirpath, nil)
		}
		addToHostsConfiglet(hostsDirpath, config.DisplayName,
			[]string{ulAddr2})

		// Create iptables with optional ipset's based ACL
		// XXX Doesn't handle IPv6 underlay ACLs
		var sshPort uint
		if ulConfig.SshPortMap {
			sshPort = 8022 + 100*uint(appNum)
		}
		if netstatus != nil {
			err = updateNetworkACLConfiglet(ctx, netstatus)
			if err != nil {
				addError(ctx, &status, "updateNetworkACL", err)
			}
		} else {
			err = createACLConfiglet(bridgeName, false, ulConfig.ACLs, 4,
				ulAddr1, ulAddr2, sshPort, netconfig)
			if err != nil {
				addError(ctx, &status, "createACL", err)
			}
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		writeAppNetworkStatus(&status)

		// Start clean
		cfgFilename := "dnsmasq." + bridgeName + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename
		stopDnsmasq(cfgFilename, false)

		createDnsmasqUnderlayConfiglet(ctx, cfgPathname, bridgeName, ulAddr1,
			ulAddr2, ulMac, hostsDirpath,
			config.UUIDandVersion.UUID.String(),
			ipsets, netconfig)
		startDnsmasq(cfgPathname, bridgeName)
	}
	// Write out what we created to AppNetworkStatus
	status.PendingAdd = false
	writeAppNetworkStatus(&status)
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

var nilUUID uuid.UUID // Really a constant

// Returns the link and whether or not is was created (as opposed to found)
// XXX remove createBridge/deleteBridge logic once everything
// on nbN is working
func findOrCreateBridge(ctx *zedrouterContext, bridgeName string, ifNum int,
	appNum int, netUUID uuid.UUID) (*netlink.Bridge, bool, error) {

	// Make sure we have a NetworkObjectConfig if we have a UUID
	// Returns nil if UUID is zero
	if netUUID != nilUUID {
		netstatus := lookupNetworkObjectStatus(ctx, netUUID.String())
		if netstatus == nil {
			log.Printf("findOrCreateBridge no NetworkObjectStatus for %s\n",
				netUUID.String())
			// XXX need a fallback/retry!!
		} else if netstatus.BridgeName != "" {
			bridgeName = netstatus.BridgeName
			log.Printf("Found Bridge %s for %s\n",
				bridgeName, netUUID.String())
			bridgeLink, err := findBridge(bridgeName)
			if err != nil {
				return nil, false, err
			}
			return bridgeLink, false, nil
		}
	}

	// Create

	// Start clean
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	bridgeLink := &netlink.Bridge{LinkAttrs: attrs}
	netlink.LinkDel(bridgeLink)

	//    ip link add ${bridgeName} type bridge
	attrs = netlink.NewLinkAttrs()
	attrs.Name = bridgeName

	var bridgeMac string
	if ifNum != 0 {
		bridgeMac = fmt.Sprintf("00:16:3e:02:%02x:%02x", ifNum, appNum)
	} else {
		bridgeMac = fmt.Sprintf("00:16:3e:04:00:%02x", appNum)
	}
	hw, err := net.ParseMAC(bridgeMac)
	if err != nil {
		log.Fatal("ParseMAC failed: ", bridgeMac, err)
	}
	attrs.HardwareAddr = hw
	bridgeLink = &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(bridgeLink); err != nil {
		errStr := fmt.Sprintf("LinkAdd on %s failed: %s",
			bridgeName, err)
		return nil, true, errors.New(errStr)
	}
	//    ip link set ${bridgeName} up
	if err := netlink.LinkSetUp(bridgeLink); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
			bridgeName, err)
		return nil, true, errors.New(errStr)
	}
	return bridgeLink, true, nil
}

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
	ulAddr1 := fmt.Sprintf("172.%d.%d.1", 27+ifnum, appNum)
	ulAddr2 := fmt.Sprintf("172.%d.%d.2", 27+ifnum, appNum)

	if netstatus != nil {
		// Allocate ulAddr1 based on BridgeMac
		log.Printf("getUlAddrs(%d/%d for %s) bridgeMac %s\n",
			ifnum, appNum, netstatus.UUID.String(),
			status.BridgeMac.String())
		addr, err := lookupOrAllocateIPv4(ctx, netstatus,
			status.BridgeMac)
		if err != nil {
			log.Printf("lookupOrAllocatePv4 failed %s\n", err)
			// Keep above default
		} else {
			ulAddr1 = addr
		}
	}
	if status.AppIPAddr != nil {
		// Static IP assignment case.
		// Note that ulAddr2 can be in a different subnet.
		// Assumption is that the config specifies a gateway/router
		// in the same subnet as the static address.
		ulAddr2 = status.AppIPAddr.String()
	} else if netstatus != nil {
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
			ulAddr2 = addr
		}
	}
	log.Printf("getUlAddrs(%d/%d) done %s/%s\n",
		ifnum, appNum, ulAddr1, ulAddr2)
	return ulAddr1, ulAddr2
}

// Caller should clear the appropriate status.Pending* if the the caller will
// return after adding the error.
func addError(ctx *zedrouterContext,
	status *types.AppNetworkStatus, tag string, err error) {

	log.Printf("%s: %s\n", tag, err.Error())
	status.Error = appendError(status.Error, tag, err.Error())
	status.ErrorTime = time.Now()
	// XXX use ctx to publish
	writeAppNetworkStatus(status)
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

// Note that handleModify will not touch the EID; just ACLs and NameToEidList
// XXX should we check that nothing else has changed?
// XXX If so flag other changes as errors; would need lastError in status.
func handleModify(ctxArg interface{}, statusFilename string, configArg interface{},
	statusArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(*types.AppNetworkConfig)
	status := statusArg.(*types.AppNetworkStatus)
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	recordAppNetworkConfig(config)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		return
	}

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
	writeAppNetworkStatus(status)

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
			olConfig.ACLs, 6, "", "", 0, nil)
		if err != nil {
			addError(ctx, status, "updateACL", err)
		}
		status.PendingModify = false
		writeAppNetworkStatus(status)
		log.Printf("handleModify done for %s\n", config.DisplayName)
		return
	}

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
		olAddr1 := olStatus.BridgeIPAddr

		netconfig := lookupNetworkObjectConfig(ctx,
			olConfig.Network.String())
		// Update hosts
		// XXX doesn't handle a sharedBridge
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		updateHostsConfiglet(hostsDirpath, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Default EID ipset
		// XXX shared with others
		updateEidIpsetConfiglet(bridgeName, olStatus.NameToEidList,
			olConfig.NameToEidList)

		netstatus := lookupNetworkObjectStatus(ctx,
			olConfig.Network.String())
		// Update ACLs
		if netstatus != nil {
			err := updateNetworkACLConfiglet(ctx, netstatus)
			if err != nil {
				addError(ctx, status, "updateNetworkACL", err)
			}
		} else {
			err := updateACLConfiglet(bridgeName, false, olStatus.ACLs,
				olConfig.ACLs, 6, olAddr1, "", 0, netconfig)
			if err != nil {
				addError(ctx, status, "updateACL", err)
			}
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		writeAppNetworkStatus(status)

		// updateAppInstanceIpsets told us whether there is a change
		// to the set of ipsets, and that requires restarting dnsmasq
		// XXX shared with others
		if restartDnsmasq {
			cfgFilename := "dnsmasq." + bridgeName + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			EID := olConfig.EID
			stopDnsmasq(cfgFilename, false)
			//remove old dnsmasq configuration file
			os.Remove(cfgPathname)
			// XXX need to determine remaining ipsets. Inside function?
			createDnsmasqOverlayConfiglet(ctx, cfgPathname, bridgeName,
				olAddr1, EID.String(), olStatus.Mac, hostsDirpath,
				config.UUIDandVersion.UUID.String(), newIpsets,
				netconfig)
			startDnsmasq(cfgPathname, bridgeName)
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
		ulAddr1 := ulStatus.BridgeIPAddr
		ulAddr2 := ulStatus.AssignedIPAddr

		netconfig := lookupNetworkObjectConfig(ctx,
			ulConfig.Network.String())

		// Update ACLs
		var sshPort uint
		if ulConfig.SshPortMap {
			sshPort = 8022 + 100*uint(appNum)
		}
		netstatus := lookupNetworkObjectStatus(ctx,
			ulConfig.Network.String())
		if netstatus != nil {
			err := updateNetworkACLConfiglet(ctx, netstatus)
			if err != nil {
				addError(ctx, status, "updateNetworkACL", err)
			}
		} else {
			err := updateACLConfiglet(bridgeName, false, ulStatus.ACLs,
				ulConfig.ACLs, 4, ulAddr1, ulAddr2, sshPort, netconfig)
			if err != nil {
				addError(ctx, status, "updateACL", err)
			}
		}
		// XXX createDnsmasq assumes it can read this to get netstatus
		writeAppNetworkStatus(status)

		if restartDnsmasq {
			//update underlay dnsmasq configuration
			hostsDirpath := globalRunDirname + "/hosts." + bridgeName
			cfgFilename := "dnsmasq." + bridgeName + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			stopDnsmasq(cfgFilename, false)
			//remove old dnsmasq configuration file
			os.Remove(cfgPathname)
			// XXX need ipsets from all bn<N> users
			createDnsmasqUnderlayConfiglet(ctx, cfgPathname, bridgeName,
				ulAddr1, ulAddr2, ulStatus.Mac,
				hostsDirpath,
				config.UUIDandVersion.UUID.String(), newIpsets,
				netconfig)
			startDnsmasq(cfgPathname, bridgeName)
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
	writeAppNetworkStatus(status)
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	status := statusArg.(*types.AppNetworkStatus)
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	removeAppNetworkConfig(status.UUIDandVersion.UUID.String())

	appNum := status.AppNum
	maxOlNum := status.OlNum
	maxUlNum := status.UlNum
	if debug {
		log.Printf("handleDelete appNum %d maxOlNum %d maxUlNum %d\n",
			appNum, maxOlNum, maxUlNum)
	}

	status.PendingDelete = true
	writeAppNetworkStatus(status)

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
			6, "", "", 0, nil)
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
			olAddr1 := olStatus.BridgeIPAddr

			sharedBridge := true
			if !strings.HasPrefix(bridgeName, "bn") {
				sharedBridge = false
				log.Printf("Deleting bridge %s\n", bridgeName)
				attrs := netlink.NewLinkAttrs()
				attrs.Name = bridgeName
				oLink := &netlink.Bridge{LinkAttrs: attrs}
				// Remove link and associated addresses
				netlink.LinkDel(oLink)
			}
			netconfig := lookupNetworkObjectConfig(ctx,
				olStatus.Network.String())

			// XXX need IPv6 allocate/free to do same as for ulConfig
			// XXX createDnsmasq assumes it can read this to get netstatus
			writeAppNetworkStatus(status)

			// radvd cleanup
			// XXX not all of it; see dnsmasq below; if sharedBridge
			cfgFilename := "radvd." + bridgeName + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			stopRadvd(cfgFilename, true)
			deleteRadvdConfiglet(cfgPathname)

			// dnsmasq cleanup
			// XXX not all of it - see ulStatus below
			cfgFilename = "dnsmasq." + bridgeName + ".conf"
			cfgPathname = runDirname + "/" + cfgFilename
			stopDnsmasq(cfgFilename, true)
			deleteDnsmasqConfiglet(cfgPathname)

			// Delete ACLs
			netstatus := lookupNetworkObjectStatus(ctx,
				olStatus.Network.String())
			if netstatus != nil {
				err := updateNetworkACLConfiglet(ctx, netstatus)
				if err != nil {
					addError(ctx, status, "updateNetworkACL", err)
				}
			} else {
				err := deleteACLConfiglet(bridgeName, false,
					olStatus.ACLs, 6, olAddr1, "", 0, netconfig)
				if err != nil {
					addError(ctx, status, "deleteACL", err)
				}
			}

			// Delete LISP configlets
			deleteLispConfiglet(lispRunDirname, false,
				olStatus.IID, olStatus.EID,
				deviceNetworkStatus,
				ctx.separateDataPlane)

			// Delete overlay hosts file or directory
			hostsDirpath := globalRunDirname + "/hosts." + bridgeName
			if sharedBridge {
				removeFromHostsConfiglet(hostsDirpath,
					status.DisplayName)
			} else {
				deleteHostsConfiglet(hostsDirpath, true)
			}
			// Default EID ipset
			// XXX not all of it
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

			sharedBridge := true
			if !strings.HasPrefix(bridgeName, "bn") {
				sharedBridge = false
				log.Printf("Deleting bridge %s\n", bridgeName)
				attrs := netlink.NewLinkAttrs()
				attrs.Name = bridgeName
				uLink := &netlink.Bridge{LinkAttrs: attrs}
				// Remove link and associated addresses
				netlink.LinkDel(uLink)
			}
			netstatus := lookupNetworkObjectStatus(ctx,
				ulStatus.Network.String())

			doDelete := true
			if netstatus != nil {
				last, err := releaseIPv4(ctx, netstatus,
					ulStatus.BridgeMac)
				// XXX publish
				if err != nil {
					addError(ctx, status, "freeIPv4", err)
				}
				if !last {
					doDelete = false
				}
			}
			// XXX createDnsmasq assumes it can read this to get netstatus
			writeAppNetworkStatus(status)

			hostsDirpath := globalRunDirname + "/hosts." + bridgeName
			cfgFilename := "dnsmasq." + bridgeName + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename

			netconfig := lookupNetworkObjectConfig(ctx,
				ulStatus.Network.String())
			if doDelete {
				// dnsmasq cleanup
				stopDnsmasq(cfgFilename, true)
				deleteDnsmasqConfiglet(cfgPathname)
			} else {
				// Update
				stopDnsmasq(cfgFilename, false)
				//remove old dnsmasq configuration file
				os.Remove(cfgPathname)
				// XXX Don't need to pass app-specific args
				// XXX need ipsets from all bn<N> users
				// XXX need to determine remaining ipsets. Inside function?
				// xxx NIL for now
				createDnsmasqUnderlayConfiglet(ctx, cfgPathname, bridgeName,
					"", "", ulStatus.Mac, hostsDirpath,
					"", []string{}, netconfig)
				startDnsmasq(cfgPathname, bridgeName)
			}

			// Delete ACLs
			var sshPort uint
			if ulStatus.SshPortMap {
				sshPort = 8022 + 100*uint(appNum)
			}
			ulAddr1 := ulStatus.BridgeIPAddr
			ulAddr2 := ulStatus.AssignedIPAddr

			if netstatus != nil {
				err := updateNetworkACLConfiglet(ctx, netstatus)
				if err != nil {
					addError(ctx, status, "updateNetworkACL", err)
				}
			} else {
				err := deleteACLConfiglet(bridgeName, false,
					ulStatus.ACLs, 4, ulAddr1, ulAddr2,
					sshPort, netconfig)
				if err != nil {
					addError(ctx, status, "deleteACL", err)
				}
			}
			// Delete hosts file or directory
			if sharedBridge {
				removeFromHostsConfiglet(hostsDirpath,
					status.DisplayName)
			} else {
				deleteHostsConfiglet(hostsDirpath, true)
			}
		}
	}
	status.PendingDelete = false
	writeAppNetworkStatus(status)

	// Write out what we modified to AppNetworkStatus aka delete
	removeAppNetworkStatus(status)

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

func handleDNCModify(ctxArg interface{}, configFilename string,
	configArg interface{}) {
	config := configArg.(*types.DeviceNetworkConfig)
	ctx := ctxArg.(*DNCContext)

	if configFilename != ctx.manufacturerModel {
		if debug {
			log.Printf("handleDNCModify: ignoring %s - expecting %s\n",
				configFilename, ctx.manufacturerModel)
		}
		return
	}
	log.Printf("handleDNCModify for %s\n", configFilename)

	deviceNetworkConfig = *config
	new, _ := devicenetwork.MakeDeviceNetworkStatus(*config,
		deviceNetworkStatus)
	// XXX switch to Equal?
	if !reflect.DeepEqual(deviceNetworkStatus, new) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			deviceNetworkStatus, new)
		deviceNetworkStatus = new
		doDNSUpdate(ctx)
	}
	log.Printf("handleDNCModify done for %s\n", configFilename)
}

func handleDNCDelete(ctxArg interface{}, configFilename string) {
	log.Printf("handleDNCDelete for %s\n", configFilename)
	ctx := ctxArg.(*DNCContext)

	if configFilename != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", configFilename)
		return
	}
	new := types.DeviceNetworkStatus{}
	// XXX switch to Equal?
	if !reflect.DeepEqual(deviceNetworkStatus, new) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			deviceNetworkStatus, new)
		deviceNetworkStatus = new
		doDNSUpdate(ctx)
	}
	log.Printf("handleDNCDelete done for %s\n", configFilename)
}

func doDNSUpdate(ctx *DNCContext) {
	// Did we loose all usable addresses or gain the first usable
	// address?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	if newAddrCount == 0 && ctx.usableAddressCount != 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			newAddrCount, ctx.usableAddressCount)
		// Inform ledmanager that we have no addresses
		types.UpdateLedManagerConfig(1)
	} else if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			newAddrCount, ctx.usableAddressCount)
		// Inform ledmanager that we have uplink addresses
		types.UpdateLedManagerConfig(2)
	}
	ctx.usableAddressCount = newAddrCount
	updateDeviceNetworkStatus(ctx.pubDeviceNetworkStatus)
	updateLispConfiglets(ctx.separateDataPlane)

	setUplinks(deviceNetworkConfig.Uplink)
	setFreeUplinks(deviceNetworkConfig.FreeUplinks)
	// XXX do a NatInactivate/NatActivate if freeuplinks/uplinks changed?
}
