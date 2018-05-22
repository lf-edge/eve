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
	"flag"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"github.com/zededa/go-provision/wrap"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
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
	DNSDirname    = runDirname + "/DeviceNetworkStatus"
	DataPlaneName = "dataplane"
)

// Set from Makefile
var Version = "No version specified"

type zedrouterContext struct {
	// Experimental Zededa data plane enable/disable flag
	SeparateDataPlane bool
}

// Dummy since we don't have anything to pass
type dummyContext struct {
}

// Context for handleDNCModify
type DNCContext struct {
	usableAddressCount int
	manufacturerModel  string
	SeparateDataPlane  bool
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
	if _, err := os.Stat(DNSDirname); err != nil {
		log.Printf("Create %s\n", DNSDirname)
		if err := os.MkdirAll(DNSDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	appNumAllocatorInit(statusDirname, configDirname)
	model := hardware.GetHardwareModel()

	// XXX Should we wait for the DNCFilename same way as we wait
	// for AssignableAdapter filename?

	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	handleInit(DNCFilename, DNSDirname+"/global.json",
		runDirname)

	DNCctx := DNCContext{}
	DNCctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	DNCctx.manufacturerModel = model
	DNCctx.SeparateDataPlane = false

	ZedrouterCtx := zedrouterContext{
		SeparateDataPlane: false,
	}

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
	addrChangeFn := func(ifname string) {
		if debug {
			log.Printf("addrChangeFn(%s) called\n", ifname)
		}
		new, _ := devicenetwork.MakeDeviceNetworkStatus(deviceNetworkConfig, deviceNetworkStatus)
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

	routeChanges, addrChanges, linkChanges := PbrInit(
		deviceNetworkConfig.Uplink, deviceNetworkConfig.FreeUplinks,
		addrChangeFn)

	handleRestart(&ZedrouterCtx, false)
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
			watch.HandleConfigStatusEvent(change, &ZedrouterCtx,
				configDirname, statusDirname,
				&types.AppNetworkConfig{},
				&types.AppNetworkStatus{},
				handleCreate, handleModify, handleDelete,
				&restartFn)
			// DNC handling also re-writes the lisp.config file.
			// We should call the updateLisp with correct Dataplane
			// flag inorder not to confuse lispers.net
			DNCctx.SeparateDataPlane = ZedrouterCtx.SeparateDataPlane
		case change := <-deviceConfigChanges:
			watch.HandleStatusEvent(change, &DNCctx,
				DNCDirname,
				&types.DeviceNetworkConfig{},
				handleDNCModify, handleDNCDelete,
				nil)
		case change := <-routeChanges:
			PbrRouteChange(change)
		case change := <-addrChanges:
			PbrAddrChange(change)
		case change := <-linkChanges:
			PbrLinkChange(change)
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
				updateDeviceNetworkStatus()
			}
		}
	}
}

func handleRestart(ctxArg interface{}, done bool) {
	if debug {
		log.Printf("handleRestart(%v)\n", done)
	}
	ctx := ctxArg.(*zedrouterContext)
	handleLispRestart(done, ctx.SeparateDataPlane)
	if done {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		watch.SignalRestarted(agentName)
	}
}

var deviceNetworkConfig types.DeviceNetworkConfig
var deviceNetworkStatus types.DeviceNetworkStatus
var deviceNetworkStatusFilename string
var globalRunDirname string
var lispRunDirname string

// XXX hack to avoid the pslisp hang on Erik's laptop
var broken = false

func handleInit(configFilename string, statusFilename string,
	runDirname string) {
	deviceNetworkStatusFilename = statusFilename
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
	updateDeviceNetworkStatus()

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

func updateDeviceNetworkStatus() {
	b, err := json.Marshal(deviceNetworkStatus)
	if err != nil {
		log.Fatal(err, "json Marshal DeviceNetworkStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(deviceNetworkStatusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, deviceNetworkStatusFilename)
	}
}

// Key is UUID
var appNetworkStatus map[string]types.AppNetworkStatus

// XXX rename to update? Remove statusFilename?
//	statusFilename := fmt.Sprintf("/var/run/%s/%s/%s.json",
//		agentName, topic, key)
// XXX introduce separate baseDir whch is /var/run (or /var/run/zededa)??
func writeAppNetworkStatus(status *types.AppNetworkStatus,
	statusFilename string) {

	if appNetworkStatus == nil {
		if debug {
			log.Printf("create appNetwork status map\n")
		}
		appNetworkStatus = make(map[string]types.AppNetworkStatus)
	}
	key := status.UUIDandVersion.UUID.String()
	appNetworkStatus[key] = *status

	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal AppNetworkStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
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
	// pubsub.UnpublishStatus(agentName, topic, key)
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
	writeAppNetworkStatus(&status, statusFilename)

	if config.IsZedmanager {
		log.Printf("handleCreate: for %s IsZedmanager\n",
			config.DisplayName)
		if len(config.OverlayNetworkList) != 1 ||
			len(config.UnderlayNetworkList) != 0 {
			// XXX send to cloud?
			log.Println("Malformed IsZedmanager config; ignored")
			return
		}
		ctx.SeparateDataPlane = config.SeparateDataPlane

		// Use this olIfname to name files
		// XXX some files might not be used until Zedmanager becomes
		// a domU at which point IsZedMansger boolean won't be needed
		olConfig := config.OverlayNetworkList[0]
		olNum := 1
		olIfname := "dbo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)

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
		olIfMac := fmt.Sprintf("00:16:3e:02:%02x:%02x", olNum, appNum)
		hw, err := net.ParseMAC(olIfMac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", olIfMac, err)
		}
		attrs.HardwareAddr = hw
		oLink = &netlink.Dummy{LinkAttrs: attrs}
		if err := netlink.LinkAdd(oLink); err != nil {
			log.Printf("LinkAdd on %s failed: %s\n", olIfname, err)
		}

		// ip link set ${olIfname} mtu 1280
		if err := netlink.LinkSetMTU(oLink, 1280); err != nil {
			log.Printf("LinkSetMTU on %s failed: %s\n",
				olIfname, err)
		}

		//    ip link set ${olIfname} up
		if err := netlink.LinkSetUp(oLink); err != nil {
			log.Printf("LinkSetUp on %s failed: %s\n",
				olIfname, err)
		}

		//    ip link set ${olIfname} arp on
		if err := netlink.LinkSetARPOn(oLink); err != nil {
			log.Printf("LinkSetARPOn on %s failed: %s\n", olIfname,
				err)
		}

		// Configure the EID on olIfname and set up a default route
		// for all fd00 EIDs
		//    ip addr add ${EID}/128 dev ${olIfname}
		EID := config.OverlayNetworkList[0].EID
		addr, err := netlink.ParseAddr(EID.String() + "/128")
		if err != nil {
			// XXX send to cloud?
			log.Printf("ParseAddr %s failed: %s\n", EID, err)
			return
		}
		if err := netlink.AddrAdd(oLink, addr); err != nil {
			// XXX fatal?
			log.Printf("AddrAdd %s failed: %s\n", EID, err)
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
			log.Printf("NeighAdd fe80::1 failed: %s\n", err)
		}
		if err := netlink.NeighSet(&neigh); err != nil {
			log.Printf("NeighSet fe80::1 failed: %s\n", err)
		}

		rt := netlink.Route{Dst: ipnet, LinkIndex: index, Gw: via}
		if err := netlink.RouteAdd(&rt); err != nil {
			log.Printf("RouteAdd fd00::/8 failed: %s\n", err)
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
		createACLConfiglet(olIfname, true, olConfig.ACLs, 6, "", "", 0)

		// Save information about zedmanger EID and additional info
		deviceEID = EID
		deviceIID = olConfig.IID
		additionalInfoDevice = olConfig.AdditionalInfoDevice

		additionalInfo := generateAdditionalInfo(status, olConfig)

		// Create LISP configlets for IID and EID/signature
		createLispConfiglet(lispRunDirname, config.IsZedmanager,
			olConfig.IID, olConfig.EID, olConfig.LispSignature,
			deviceNetworkStatus, olIfname, olIfname,
			additionalInfo, olConfig.LispServers, ctx.SeparateDataPlane)
		status.OverlayNetworkList = make([]types.OverlayNetworkStatus,
			len(config.OverlayNetworkList))
		for i, _ := range config.OverlayNetworkList {
			status.OverlayNetworkList[i].OverlayNetworkConfig =
				config.OverlayNetworkList[i]
		}
		status.PendingAdd = false
		writeAppNetworkStatus(&status, statusFilename)
		log.Printf("handleCreate done for %s\n",
			config.DisplayName)
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
	// XXX restrict to first underlaynetwork. Can't handle more than one!
	// XXX results in entry with no vif and no mac
	// which causes failure in domainmgr/xl create!
	ulcount := len(config.UnderlayNetworkList)
	if ulcount > 1 {
		log.Printf("Ignoring received ulcount %d\n", ulcount)
		ulcount = 1
	}
	status.UnderlayNetworkList = make([]types.UnderlayNetworkStatus,
		ulcount)
	for i, _ := range config.UnderlayNetworkList {
		if i > 0 {
			log.Printf("Ignoring UnderlayNetworkConfig[%d] = %v\n",
				i, config.UnderlayNetworkList[i])
			continue
		}
		status.UnderlayNetworkList[i].UnderlayNetworkConfig =
			config.UnderlayNetworkList[i]
	}

	ipsets := compileAppInstanceIpsets(config.OverlayNetworkList,
		config.UnderlayNetworkList)

	for i, olConfig := range config.OverlayNetworkList {
		olNum := i + 1
		if debug {
			log.Printf("olNum %d ACLs %v\n", olNum, olConfig.ACLs)
		}
		EID := olConfig.EID
		olIfname := "bo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		if debug {
			log.Printf("olIfname %s\n", olIfname)
		}
		olAddr1 := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		if debug {
			log.Printf("olAddr1 %s EID %s\n", olAddr1, EID)
		}
		olMac := "00:16:3e:1:" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		if debug {
			log.Printf("olMac %s\n", olMac)
		}
		// Start clean
		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Bridge{LinkAttrs: attrs}
		netlink.LinkDel(oLink)

		//    ip link add ${olIfname} type bridge
		attrs = netlink.NewLinkAttrs()
		attrs.Name = olIfname
		bridgeMac := fmt.Sprintf("00:16:3e:02:%02x:%02x", olNum, appNum)
		hw, err := net.ParseMAC(bridgeMac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", bridgeMac, err)
		}
		attrs.HardwareAddr = hw
		oLink = &netlink.Bridge{LinkAttrs: attrs}
		if err := netlink.LinkAdd(oLink); err != nil {
			log.Printf("LinkAdd on %s failed: %s\n", olIfname, err)
		}

		//    ip link set ${olIfname} up
		if err := netlink.LinkSetUp(oLink); err != nil {
			log.Printf("LinkSetUp on %s failed: %s\n", olIfname, err)
		}

		//    ip addr add ${olAddr1}/128 dev ${olIfname}
		addr, err := netlink.ParseAddr(olAddr1 + "/128")
		if err != nil {
			log.Printf("ParseAddr %s failed: %s\n", olAddr1, err)
		}
		if err := netlink.AddrAdd(oLink, addr); err != nil {
			log.Printf("AddrAdd %s failed: %s\n", olAddr1, err)
		}

		//    ip -6 route add ${EID}/128 dev ${olIfname}
		_, ipnet, err := net.ParseCIDR(EID.String() + "/128")
		if err != nil {
			log.Printf("ParseCIDR %s failed: %v\n", EID, err)
		}
		if debug {
			log.Printf("oLink.Index %d\n", oLink.Index)
		}
		rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
		if err := netlink.RouteAdd(&rt); err != nil {
			log.Printf("RouteAdd %s failed: %s\n", EID, err)
		}

		// Write radvd configlet; start radvd
		cfgFilename := "radvd." + olIfname + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename

		//    Start clean; kill just in case
		//    pkill -u radvd -f radvd.${OLIFNAME}.conf
		stopRadvd(cfgFilename, false)
		createRadvdConfiglet(cfgPathname, olIfname)
		startRadvd(cfgPathname, olIfname)

		// Create a hosts file for the overlay based on NameToEidList
		// Directory is /var/run/zedrouter/hosts.${OLIFNAME}
		// Each hostname in a separate file in directory to facilitate
		// adds and deletes
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		deleteHostsConfiglet(hostsDirpath, false)
		createHostsConfiglet(hostsDirpath, olConfig.NameToEidList)

		// Create default ipset with all the EIDs in NameToEidList
		// Can be used in ACLs by specifying "alleids" as match.
		deleteEidIpsetConfiglet(olIfname, false)
		createEidIpsetConfiglet(olIfname, olConfig.NameToEidList,
			EID.String())

		// Set up ACLs before we setup dnsmasq
		createACLConfiglet(olIfname, false, olConfig.ACLs, 6,
			olAddr1, "", 0)

		// Start clean
		cfgFilename = "dnsmasq." + olIfname + ".conf"
		cfgPathname = runDirname + "/" + cfgFilename
		stopDnsmasq(cfgFilename, false)
		createDnsmasqOverlayConfiglet(cfgPathname, olIfname, olAddr1,
			EID.String(), olMac, hostsDirpath,
			config.UUIDandVersion.UUID.String(), ipsets)
		startDnsmasq(cfgPathname, olIfname)

		additionalInfo := generateAdditionalInfo(status, olConfig)
		// Create LISP configlets for IID and EID/signature
		createLispConfiglet(lispRunDirname, config.IsZedmanager,
			olConfig.IID, olConfig.EID, olConfig.LispSignature,
			deviceNetworkStatus, olIfname, olIfname,
			additionalInfo, olConfig.LispServers, ctx.SeparateDataPlane)

		// Add bridge parameters for Xen to Status
		olStatus := &status.OverlayNetworkList[olNum-1]
		olStatus.Bridge = olIfname
		olStatus.Vif = "n" + olIfname
		olStatus.Mac = olMac
	}

	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		if ulNum != 1 {
			// For now we only support one underlay interface
			// in app
			log.Printf("Ignoring multiple UnderlayNetwork\n")
			continue
		}
		if debug {
			log.Printf("ulNum %d ACLs %v\n", ulNum, ulConfig.ACLs)
		}
		ulIfname := "bu" + strconv.Itoa(appNum)
		if debug {
			log.Printf("ulIfname %s\n", ulIfname)
		}
		// Not clear how to handle multiple ul; use /30 prefix?
		ulAddr1 := "172.27." + strconv.Itoa(appNum) + ".1"
		ulAddr2 := "172.27." + strconv.Itoa(appNum) + ".2"
		if debug {
			log.Printf("ulAddr1 %s ulAddr2 %s\n", ulAddr1, ulAddr2)
		}
		// Room to handle multiple underlays in 5th byte
		ulMac := "00:16:3e:0:0:" + strconv.FormatInt(int64(appNum), 16)
		if debug {
			log.Printf("ulMac %s\n", ulMac)
		}
		// Start clean
		attrs := netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		uLink := &netlink.Bridge{LinkAttrs: attrs}
		netlink.LinkDel(uLink)

		//    ip link add ${ulIfname} type bridge
		attrs = netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		bridgeMac := fmt.Sprintf("00:16:3e:04:00:%02x", appNum)
		hw, err := net.ParseMAC(bridgeMac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", bridgeMac, err)
		}
		attrs.HardwareAddr = hw
		uLink = &netlink.Bridge{LinkAttrs: attrs}
		if err := netlink.LinkAdd(uLink); err != nil {
			log.Printf("LinkAdd on %s failed: %s\n", ulIfname, err)
		}
		//    ip link set ${ulIfname} up
		if err := netlink.LinkSetUp(uLink); err != nil {
			log.Printf("LinkSetUp on %s failed: %s\n", ulIfname, err)
		}
		//    ip addr add ${ulAddr1}/24 dev ${ulIfname}
		addr, err := netlink.ParseAddr(ulAddr1 + "/24")
		if err != nil {
			log.Printf("ParseAddr %s failed: %s\n", ulAddr1, err)
		}
		if err := netlink.AddrAdd(uLink, addr); err != nil {
			log.Printf("AddrAdd %s failed: %s\n", ulAddr1, err)
		}

		// Create iptables with optional ipset's based ACL
		// XXX Doesn't handle IPv6 underlay ACLs
		var sshPort uint
		if ulConfig.SshPortMap {
			sshPort = 8022 + 100*uint(appNum)
		}
		// XXX
		log.Printf("SshPortMap %v sshPort %d\n", ulConfig.SshPortMap,
			sshPort)
		createACLConfiglet(ulIfname, false, ulConfig.ACLs, 4,
			ulAddr1, ulAddr2, sshPort)

		// Start clean
		cfgFilename := "dnsmasq." + ulIfname + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename
		stopDnsmasq(cfgFilename, false)

		createDnsmasqUnderlayConfiglet(cfgPathname, ulIfname, ulAddr1,
			ulAddr2, ulMac, config.UUIDandVersion.UUID.String(), ipsets)
		startDnsmasq(cfgPathname, ulIfname)

		// Add bridge parameters for Xen to Status
		ulStatus := &status.UnderlayNetworkList[ulNum-1]
		ulStatus.Bridge = ulIfname
		ulStatus.Vif = "n" + ulIfname
		ulStatus.Mac = ulMac
	}
	// Write out what we created to AppNetworkStatus
	status.PendingAdd = false
	writeAppNetworkStatus(&status, statusFilename)
	log.Printf("handleCreate done for %s\n", config.DisplayName)
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
		log.Println("Unsupported: IsZedmanager changed for ",
			config.UUIDandVersion)
		return
	}
	// XXX We could should we allow the addition of interfaces
	// if the domU would find out through some hotplug event.
	// But deletion is hard.
	// For now don't allow any adds or deletes.
	if len(config.OverlayNetworkList) != status.OlNum {
		log.Println("Unsupported: Changed number of overlays for ",
			config.UUIDandVersion)
		return
	}
	if len(config.UnderlayNetworkList) != status.UlNum {
		log.Println("Unsupported: Changed number of underlays for ",
			config.UUIDandVersion)
		return
	}

	status.SeparateDataPlane = ctx.SeparateDataPlane
	status.PendingModify = true
	status.UUIDandVersion = config.UUIDandVersion
	writeAppNetworkStatus(status, statusFilename)

	if config.IsZedmanager {
		if config.SeparateDataPlane != ctx.SeparateDataPlane {
			log.Printf("Unsupported: Changing experimental data plane flag on the fly\n")
			// XXX Add an error stat here. It can be passed back to cloud in future.
			return
		}
		olConfig := config.OverlayNetworkList[0]
		olStatus := status.OverlayNetworkList[0]
		olNum := 1
		olIfname := "dbo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		// Update hosts
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		updateHostsConfiglet(hostsDirpath, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Default EID ipset
		updateEidIpsetConfiglet(olIfname, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Update ACLs
		updateACLConfiglet(olIfname, true, olStatus.ACLs,
			olConfig.ACLs, 6, "", "", 0)
		log.Printf("handleModify done for %s\n", config.DisplayName)
		return
	}

	newIpsets, staleIpsets, restartDnsmasq := updateAppInstanceIpsets(config.OverlayNetworkList,
		config.UnderlayNetworkList,
		status.OverlayNetworkList,
		status.UnderlayNetworkList)

	// Look for ACL and NametoEidList changes in overlay
	for i, olConfig := range config.OverlayNetworkList {
		olNum := i + 1
		if debug {
			log.Printf("handleModify olNum %d\n", olNum)
		}
		olIfname := "bo" + strconv.Itoa(olNum) + "x" +
			strconv.Itoa(appNum)
		olStatus := status.OverlayNetworkList[olNum-1]
		olAddr1 := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)

		// Update hosts
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		updateHostsConfiglet(hostsDirpath, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Default EID ipset
		updateEidIpsetConfiglet(olIfname, olStatus.NameToEidList,
			olConfig.NameToEidList)

		// Update ACLs
		updateACLConfiglet(olIfname, false, olStatus.ACLs,
			olConfig.ACLs, 6, olAddr1, "", 0)

		// updateAppInstanceIpsets told us whether there is a change
		// to the set of ipsets, and that requires restarting dnsmasq
		if restartDnsmasq {
			cfgFilename := "dnsmasq." + olIfname + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			EID := olConfig.EID
			olMac := "00:16:3e:1:" + strconv.FormatInt(int64(olNum), 16) +
				":" + strconv.FormatInt(int64(appNum), 16)
			stopDnsmasq(cfgFilename, false)
			//remove old dnsmasq configuration file
			os.Remove(cfgPathname)
			createDnsmasqOverlayConfiglet(cfgPathname, olIfname, olAddr1,
				EID.String(), olMac, hostsDirpath,
				config.UUIDandVersion.UUID.String(), newIpsets)
			startDnsmasq(cfgPathname, olIfname)
		}

		additionalInfo := generateAdditionalInfo(*status, olConfig)

		// Update any signature changes
		// XXX should we check that EID didn't change?

		// Create LISP configlets for IID and EID/signature
		updateLispConfiglet(lispRunDirname, false, olConfig.IID,
			olConfig.EID, olConfig.LispSignature,
			deviceNetworkStatus, olIfname, olIfname,
			additionalInfo, olConfig.LispServers, ctx.SeparateDataPlane)

	}
	// Look for ACL changes in underlay
	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		if debug {
			log.Printf("handleModify ulNum %d\n", ulNum)
		}
		ulIfname := "bu" + strconv.Itoa(appNum)
		ulAddr1 := "172.27." + strconv.Itoa(appNum) + ".1"
		ulAddr2 := "172.27." + strconv.Itoa(appNum) + ".2"
		ulStatus := status.UnderlayNetworkList[ulNum-1]

		// Update ACLs
		var sshPort uint
		if ulConfig.SshPortMap {
			sshPort = 8022 + 100*uint(appNum)
		}
		updateACLConfiglet(ulIfname, false, ulStatus.ACLs,
			ulConfig.ACLs, 4, ulAddr1, ulAddr2, sshPort)

		if restartDnsmasq {
			//update underlay dnsmasq configuration
			cfgFilename := "dnsmasq." + ulIfname + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			ulMac := "00:16:3e:0:0:" + strconv.FormatInt(int64(appNum), 16)
			stopDnsmasq(cfgFilename, false)
			//remove old dnsmasq configuration file
			os.Remove(cfgPathname)
			createDnsmasqUnderlayConfiglet(cfgPathname, ulIfname, ulAddr1,
				ulAddr2, ulMac,
				config.UUIDandVersion.UUID.String(), newIpsets)
			startDnsmasq(cfgPathname, ulIfname)
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
	writeAppNetworkStatus(status, statusFilename)
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	status := statusArg.(*types.AppNetworkStatus)
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
	writeAppNetworkStatus(status, statusFilename)

	if status.IsZedmanager {
		if len(status.OverlayNetworkList) != 1 ||
			len(status.UnderlayNetworkList) != 0 {
			log.Println("Malformed IsZedmanager status; ignored")
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

		// Delete the address from loopback
		// Delete fd00::/8 route
		// Delete fe80::1 neighbor

		//    ip addr del ${EID}/128 dev ${olIfname}
		EID := status.OverlayNetworkList[0].EID
		addr, err := netlink.ParseAddr(EID.String() + "/128")
		if err != nil {
			log.Printf("ParseAddr %s failed: %s\n", EID, err)
			return
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Dummy{LinkAttrs: attrs}
		// XXX can we skip explicit deletes and just remove the oLink?
		if err := netlink.AddrDel(oLink, addr); err != nil {
			log.Printf("AddrDel %s failed: %s\n", EID, err)
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
			log.Printf("RouteDel fd00::/8 failed: %s\n", err)
		}
		//    ip nei del fe80::1 lladdr 0:0:0:0:0:1 dev $intf
		neigh := netlink.Neigh{LinkIndex: index, IP: via}
		if err := netlink.NeighDel(&neigh); err != nil {
			log.Printf("NeighDel fe80::1 failed: %s\n", err)
		}

		// Remove link and associated addresses
		netlink.LinkDel(oLink)

		// Delete overlay hosts file
		hostsDirpath := globalRunDirname + "/hosts." + olIfname
		deleteHostsConfiglet(hostsDirpath, true)

		// Default EID ipset
		deleteEidIpsetConfiglet(olIfname, true)

		// Delete ACLs
		deleteACLConfiglet(olIfname, true, olStatus.ACLs, 6, "", "", 0)

		// Delete LISP configlets
		deleteLispConfiglet(lispRunDirname, true, olStatus.IID,
			olStatus.EID, deviceNetworkStatus, ctx.SeparateDataPlane)
	} else {
		// Delete everything for overlay
		for olNum := 1; olNum <= maxOlNum; olNum++ {
			if debug {
				log.Printf("handleDelete olNum %d\n", olNum)
			}
			olIfname := "bo" + strconv.Itoa(olNum) + "x" +
				strconv.Itoa(appNum)
			if debug {
				log.Printf("Deleting olIfname %s\n", olIfname)
			}
			olAddr1 := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
				":" + strconv.FormatInt(int64(appNum), 16)

			attrs := netlink.NewLinkAttrs()
			attrs.Name = olIfname
			oLink := &netlink.Bridge{LinkAttrs: attrs}
			// Remove link and associated addresses
			netlink.LinkDel(oLink)

			// radvd cleanup
			cfgFilename := "radvd." + olIfname + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			stopRadvd(cfgFilename, true)
			deleteRadvdConfiglet(cfgPathname)

			// dnsmasq cleanup
			cfgFilename = "dnsmasq." + olIfname + ".conf"
			cfgPathname = runDirname + "/" + cfgFilename
			stopDnsmasq(cfgFilename, true)
			deleteDnsmasqConfiglet(cfgPathname)

			// Need to check that index exists
			if len(status.OverlayNetworkList) >= olNum {
				olStatus := status.OverlayNetworkList[olNum-1]
				// Delete ACLs
				deleteACLConfiglet(olIfname, false,
					olStatus.ACLs, 6, olAddr1, "", 0)

				// Delete LISP configlets
				deleteLispConfiglet(lispRunDirname, false,
					olStatus.IID, olStatus.EID,
					deviceNetworkStatus,
					ctx.SeparateDataPlane)
			} else {
				log.Println("Missing status for overlay %d; can not clean up ACLs and LISP\n",
					olNum)
			}

			// Delete overlay hosts file
			hostsDirpath := globalRunDirname + "/hosts." + olIfname
			deleteHostsConfiglet(hostsDirpath, true)

			// Default EID ipset
			deleteEidIpsetConfiglet(olIfname, true)
		}

		// XXX check if any IIDs are now unreferenced and delete them
		// XXX requires looking at all of configDir and statusDir

		// Delete everything in underlay
		for ulNum := 1; ulNum <= maxUlNum; ulNum++ {
			if debug {
				log.Printf("handleDelete ulNum %d\n", ulNum)
			}
			ulIfname := "bu" + strconv.Itoa(appNum)
			ulAddr1 := "172.27." + strconv.Itoa(appNum) + ".1"
			ulAddr2 := "172.27." + strconv.Itoa(appNum) + ".2"
			if debug {
				log.Printf("Deleting ulIfname %s\n", ulIfname)
			}
			attrs := netlink.NewLinkAttrs()
			attrs.Name = ulIfname
			uLink := &netlink.Bridge{LinkAttrs: attrs}
			// Remove link and associated addresses
			netlink.LinkDel(uLink)

			// dnsmasq cleanup
			cfgFilename := "dnsmasq." + ulIfname + ".conf"
			cfgPathname := runDirname + "/" + cfgFilename
			stopDnsmasq(cfgFilename, true)
			deleteDnsmasqConfiglet(cfgPathname)

			// Delete ACLs
			// Need to check that index exists
			if len(status.UnderlayNetworkList) >= ulNum {
				ulStatus := status.UnderlayNetworkList[ulNum-1]
				var sshPort uint
				if ulStatus.SshPortMap {
					sshPort = 8022 + 100*uint(appNum)
				}
				deleteACLConfiglet(ulIfname, false,
					ulStatus.ACLs, 4, ulAddr1, ulAddr2,
					sshPort)
			} else {
				log.Println("Missing status for underlay %d; can not clean up ACLs\n",
					ulNum)
			}
		}
	}
	// Write out what we modified to AppNetworkStatus aka delete
	removeAppNetworkStatus(status)

	appNumFree(status.UUIDandVersion.UUID)
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

func pkillUserArgs(userName string, match string, printOnError bool) {
	cmd := "pkill"
	args := []string{
		"-u",
		userName,
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
	updateDeviceNetworkStatus()
	updateLispConfiglets(ctx.SeparateDataPlane)

	setUplinks(deviceNetworkConfig.Uplink)
	setFreeUplinks(deviceNetworkConfig.FreeUplinks)
	// XXX check if FreeUplinks changed; add/delete
	// XXX need to redo this when FreeUplinks changes
	// for _, u := range deviceNetworkConfig.FreeUplinks {
	//	iptableCmd("-t", "nat", "-A", "POSTROUTING", "-o", u,
	//		"-s", "172.27.0.0/16", "-j", "MASQUERADE")
	//}
}
