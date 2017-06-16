// Process input changes from a config directory containing json encoded files
// with AppNetworkConfig and compare against AppNetworkStatus in the status
// dir.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
)

// Determine differences in terms of the set of files in the configDir
// vs. the statusDir.
// On startup report the intial files in configDir as "modified" and report any
// which exist in statusDir but not in configDir as "deleted". Then watch for
// modifications or deletions in configDir.
// Caller needs to determine whether there are actual content modifications
// in the things reported as "modified".
func WatchConfigStatus(configDir string, statusDir string,
	fileChanges chan<- string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err, ": NewWatcher")
	}
	defer w.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-w.Events:
				baseName := path.Base(event.Name)
				// log.Println("event:", event)
				// We get create events when file is moved into
				// the watched directory.
				if event.Op &
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op &
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("deleted", baseName)
					fileChanges <- "D " + baseName
				}
			case err := <-w.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = w.Add(configDir)
	if err != nil {
		log.Fatal(err, ": ", configDir)
	}
	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		log.Fatal(err, ": ", configDir)
	}

	for _, file := range files {
		// log.Println("modified", file.Name())
		fileChanges <- "M " + file.Name()
	}

	statusFiles, err := ioutil.ReadDir(statusDir)
	if err != nil {
		log.Fatal(err, ": ", statusDir)
	}

	for _, file := range statusFiles {
		fileName := configDir + "/" + file.Name()
		if _, err := os.Stat(fileName); err != nil {
			// File does not exist in configDir
			// log.Println("deleted", file.Name())
			fileChanges <- "D " + file.Name()
		}
	}
	// Watch for changes
	<-done
}

func main() {
	// XXX make basedirName and rundirName be arguments
	basedirName := "/var/tmp/zedrouter"
	// rundirName := "/var/run/zedrouter"
	configDir := basedirName + "/config"
	statusDir := basedirName + "/status"

	handleInit(configDir+"/global", statusDir+"/global")
	fileChanges := make(chan string)
	go WatchConfigStatus(configDir, statusDir, fileChanges)
	for {
		change := <-fileChanges
		// log.Println("fileChange:", change)
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]
		// fmt.Printf("OP <%s> file <%s>\n", operation, fileName)
		if !strings.HasSuffix(fileName, ".json") {
			log.Printf("Ignoring file <%s>\n", fileName)
			continue
		}
		if operation == "D" {
			statusFile := statusDir + "/" + fileName
			if _, err := os.Stat(statusFile); err != nil {
				// File just vanished!
				log.Printf("File disappeared <%s>\n", fileName)
				continue
			}
			sb, err := ioutil.ReadFile(statusFile)
			if err != nil {
				log.Printf("%s for %s\n", err, statusFile)
				continue
			}
			status := types.AppNetworkStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s AppNetworkStatus file: %s\n",
					err, statusFile)
				continue
			}
			uuid := status.UUIDandVersion.UUID
			if uuid.String()+".json" != fileName {
				log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
					fileName, uuid.String())
				continue
			}
			fmt.Printf("handleDelete(%s)\n", fileName)
			statusName := statusDir + "/" + fileName
			handleDelete(statusName, status)
			continue
		}
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}
		configFile := configDir + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		config := types.AppNetworkConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s AppNetworkConfig file: %s\n",
				err, configFile)
			continue
		}
		uuid := config.UUIDandVersion.UUID
		if uuid.String()+".json" != fileName {
			log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
				fileName, uuid.String())
			continue
		}
		statusFile := statusDir + "/" + fileName
		if _, err := os.Stat(statusFile); err != nil {
			// File does not exist in status hence new
			fmt.Printf("handleCreate(%s)\n", fileName)
			statusName := statusDir + "/" + fileName
			handleCreate(statusName, config)
			continue
		}
		// Compare Version string
		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFile)
			continue
		}
		status := types.AppNetworkStatus{}
		if err := json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s AppNetworkStatus file: %s\n",
				err, statusFile)
			continue
		}
		uuid = status.UUIDandVersion.UUID
		if uuid.String()+".json" != fileName {
			log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
				fileName, uuid.String())
			continue
		}
		if config.UUIDandVersion.Version ==
			status.UUIDandVersion.Version {
			fmt.Printf("Same version %s for %s\n",
				config.UUIDandVersion.Version,
				fileName)
			continue
		}
		fmt.Printf("handleModify(%s)\n", fileName)
		statusName := statusDir + "/" + fileName
		handleModify(statusName, config, status)
	}
}

var globalConfig types.DeviceNetworkConfig
var globalStatus types.DeviceNetworkStatus
var globalStatusFilename string

func handleInit(configFilename string, statusFilename string) {
	globalStatusFilename = statusFilename

	cb, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, configFilename)
		log.Fatal(err)
	}
	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		log.Printf("%s DeviceNetworkConfig file: %s\n",
			err, configFilename)
		log.Fatal(err)
	}
	if _, err := os.Stat(statusFilename); err != nil {
		// Create and write with initial values
		globalStatus.Uplink = globalConfig.Uplink
		globalStatus.AppNumAllocator = 1
		writeGlobalStatus()
	}
	sb, err := ioutil.ReadFile(statusFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, statusFilename)
		log.Fatal(err)
	}
	if err := json.Unmarshal(sb, &globalStatus); err != nil {
		log.Printf("%s DeviceNetworkStatus file: %s\n",
			err, statusFilename)
		log.Fatal(err)
	}
}

func writeGlobalStatus() {
	b, err := json.Marshal(globalStatus)
	if err != nil {
		log.Fatal(err, "json Marshal DeviceNetworkStatus")
	}
	// XXX perhaps create temp and rename to avoid loss?
	// XXX permissions?
	err = ioutil.WriteFile(globalStatusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, globalStatusFilename)
	}
}

func writeAppNetworkStatus(status *types.AppNetworkStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal AppNetworkStatus")
	}
	// XXX perhaps create temp and rename to avoid loss?
	// XXX permissions?
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func handleCreate(statusFilename string, config types.AppNetworkConfig) {
	fmt.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	appNum := globalStatus.AppNumAllocator
	globalStatus.AppNumAllocator += 1
	writeGlobalStatus()

	status := types.AppNetworkStatus{
		UUIDandVersion: config.UUIDandVersion,
		AppNum:         appNum,
		PendingAdd:     true,
		OlNum:          len(config.OverlayNetworkList),
		UlNum:          len(config.UnderlayNetworkList),
		DisplayName:    config.DisplayName,
		IsZedmanager:   config.IsZedmanager,
	}

	if config.IsZedmanager {
		if len(config.OverlayNetworkList) != 1 ||
		   len(config.UnderlayNetworkList) != 0 {
			log.Println("Malformed IsZedmanager config; ignored")
			return
		}
		writeAppNetworkStatus(&status, statusFilename)
		
		// Configure the EID on loopback and set up a default route
		// for all
		//    ip addr add ${EID}/128 dev lo
		EID := config.OverlayNetworkList[0].EID
		addr, err := netlink.ParseAddr(EID.String() + "/128")
		if err != nil {
			fmt.Printf("ParseAddr %s failed: %s\n", EID, err)
			return
		}
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			fmt.Printf("LinkByname(lo) failed: %s\n", err)
			return
		}
		if err := netlink.AddrAdd(lo, addr); err != nil {
			fmt.Printf("AddrAdd %s failed: %s\n", EID, err)
		}

		//    ip route add fd00::/8 via fe80::1 src $eid dev $intf
		upLink, err := netlink.LinkByName(globalConfig.Uplink)
		if err != nil {
			fmt.Printf("LinkByname(%s) failed: %s\n",
				globalConfig.Uplink, err)
		}
		index := upLink.Attrs().Index
		_, ipnet, err := net.ParseCIDR("fd00::/8")
		if err != nil {
			log.Fatal("ParseCIDR fd00::/8 failed:\n", err)
		}
		via := net.ParseIP("fe80::1")

		if via == nil {
			log.Fatal("ParseIP fe80::1 failed: ", err)
		}
		//    ip nei add fe80::1 lladdr 0:0:0:0:0:1 dev $intf
		//    ip nei change fe80::1 lladdr 0:0:0:0:0:1 dev $intf
		hw, err := net.ParseMAC("00:00:00:00:00:01")
		if err != nil {
			log.Fatal("ParseMAC failed: ", err)
		}
		neigh := netlink.Neigh{LinkIndex: index, IP: via,
			HardwareAddr: hw, State: netlink.NUD_PERMANENT}
		if err := netlink.NeighAdd(&neigh); err != nil {
			fmt.Printf("NeighAdd fe80::1 failed: %s\n", err)
		}		
		if err := netlink.NeighSet(&neigh); err != nil {
			fmt.Printf("NeighSet fe80::1 failed: %s\n", err)
		}		

		// XXX needed fix in library for Src to work
		// /home/nordmark/gocode/src/github.com/vishvananda/netlink/route_linux.go
		// Replaced RTA_PREFSRC with RTA_SRC
		rt := netlink.Route{Dst: ipnet, LinkIndex: index,
			Gw: via, Src: EID}
		if err := netlink.RouteAdd(&rt); err != nil {
			fmt.Printf("RouteAdd fd00::/8 failed: %s\n", err)
		}

		// XXX ACLs for IsZedmanager? Apply to input/output
		// XXX use an IpSet for the EIDs; overlay.$IID?
		// Implies an input/output drop for fd00::/8 but that will
		// affect application overlays unless applied to uplink only.

		// XXX NameToEids to /etc/host? XXX easier in separate domU!
		
		status.OverlayNetworkList = config.OverlayNetworkList
		status.PendingAdd = false
		writeAppNetworkStatus(&status, statusFilename)
		return
	}
	writeAppNetworkStatus(&status, statusFilename)
	
	for i, olConfig := range config.OverlayNetworkList {
		olNum := i + 1
		fmt.Printf("olNum %d ACLs %v\n", olNum, olConfig.ACLs)

		EID := olConfig.EID
		olIfname := "bo" + strconv.Itoa(olNum) + "_" +
			strconv.Itoa(appNum)
		fmt.Printf("olIfname %s\n", olIfname)
		olAddr1 := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		fmt.Printf("olAddr1 %s EID %s\n", olAddr1, EID)
		olMac := "00:16:3e:1:" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		fmt.Printf("olMac %s\n", olMac)

		// Start clean
		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Bridge{LinkAttrs: attrs}
		netlink.LinkDel(oLink)

		//    ip link add ${olIfname} type bridge
		attrs = netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink = &netlink.Bridge{LinkAttrs: attrs}
		if err := netlink.LinkAdd(oLink); err != nil {
			fmt.Printf("LinkAdd on %s failed: %s\n", olIfname, err)
		}

		//    ip link set ${olIfname} up
		if err := netlink.LinkSetUp(oLink); err != nil {
			fmt.Printf("LinkSetUp on %s failed: %s\n", olIfname, err)
		}

		//    ip addr add ${olAddr1}/128 dev ${olIfname}
		addr, err := netlink.ParseAddr(olAddr1 + "/128")
		if err != nil {
			fmt.Printf("ParseAddr %s failed: %s\n", olAddr1, err)
		}
		if err := netlink.AddrAdd(oLink, addr); err != nil {
			fmt.Printf("AddrAdd %s failed: %s\n", olAddr1, err)
		}

		//    ip -6 route add ${EID}/128 dev ${olIfname}
		_, ipnet, err := net.ParseCIDR(EID.String() + "/128")
		if err != nil {
			fmt.Printf("ParseCIDR %s failed: %v\n", EID, err)
		}
		fmt.Printf("oLink.Index %d\n", oLink.Index)
		rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
		if err := netlink.RouteAdd(&rt); err != nil {
			fmt.Printf("RouteAdd %s failed: %s\n", EID, err)
		}
		// Write radvd configlet; start radvd
		// XXX TODO define as a function
		cfgFilename := "radvd." + olIfname + ".conf"
		cfgPathname := "/etc/" + cfgFilename
		pidPathname := "/var/run/radvd." + olIfname + ".pid"

		//    Start clean; kill just in case
		//    pkill -u radvd -f radvd.${OLIFNAME}.conf
		pkillUserArgs("radvd", cfgFilename, false)
		
		file, err := os.Create(cfgPathname)
		if err != nil {
			log.Fatal("os.Create for ", cfgPathname, err)
		}
		defer file.Close()
		multiLine := `
interface %s {
	IgnoreIfMissing on;
	AdvSendAdvert on;
	MaxRtrAdvInterval 1800;
	AdvManagedFlag on;
};
`
		file.WriteString(fmt.Sprintf(multiLine, olIfname))
		//    radvd -u radvd -C /etc/radvd.${OLIFNAME}.conf -p /var/run/radvd.${OLIFNAME}.pid
		cmd := "nohup"
		args := []string{
			"radvd",
			"-u",
			"radvd",
			"-C",
			cfgPathname,
			"-p",
			pidPathname,
		}
		go exec.Command(cmd, args...).Output()

		// Create a hosts file for the overlay based on NameToEids
		// XXX TODO define as a function
		
		// Start clean
		cfgFilename = "dnsmasq." + olIfname + ".conf"
		pkillUserArgs("nobody", cfgFilename, false)

		// XXX add start; keep configdir for ipset? directory for addn-hosts?
	}

	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		if ulNum != 1 {
			// For now we only support one underlay interface
			// in app
			fmt.Printf("Ignoring multiple UnderlayNetwork\n")
			continue
		}
		fmt.Printf("ulNum %d ACLs %v\n", ulNum, ulConfig.ACLs)
		ulIfname := "bu" + strconv.Itoa(appNum)
		fmt.Printf("ulIfname %s\n", ulIfname)
		// Not clear how to handle multiple ul; use /30 prefix?
		ulAddr1 := "172.27." + strconv.Itoa(appNum) + ".1"
		ulAddr2 := "172.27." + strconv.Itoa(appNum) + ".2"
		fmt.Printf("ulAddr1 %s ulAddr2 %s\n", ulAddr1, ulAddr2)
		// Room to handle multiple underlays in 5th byte
		ulMac := "00:16:3e:0:0:" + strconv.FormatInt(int64(appNum), 16)
		fmt.Printf("ulMac %s\n", ulMac)

		// Start clean
		attrs := netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		uLink := &netlink.Bridge{LinkAttrs: attrs}
		netlink.LinkDel(uLink)

		//    ip link add ${ulIfname} type bridge
		attrs = netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		uLink = &netlink.Bridge{LinkAttrs: attrs}
		if err := netlink.LinkAdd(uLink); err != nil {
			fmt.Printf("LinkAdd on %s failed: %s\n", ulIfname, err)
		}
		//    ip link set ${ulIfname} up
		if err := netlink.LinkSetUp(uLink); err != nil {
			fmt.Printf("LinkSetUp on %s failed: %s\n", ulIfname, err)
		}
		//    ip addr add ${ulAddr1}/24 dev ${ulIfname}
		addr, err := netlink.ParseAddr(ulAddr1 + "/24")
		if err != nil {
			fmt.Printf("ParseAddr %s failed: %s\n", ulAddr1, err)
		}
		if err := netlink.AddrAdd(uLink, addr); err != nil {
			fmt.Printf("AddrAdd %s failed: %s\n", ulAddr1, err)
		}

		// Start clean
		cfgFilename := "dnsmasq." + ulIfname + ".conf"
		pkillUserArgs("nobody", cfgFilename, false)
	}
	// Write out what we created to AppNetworkStatus
	// XXX TBD to handle core dumps before this point? Cleanup based
	// on Pending?
	status.PendingAdd = false
	writeAppNetworkStatus(&status, statusFilename)
}

// Note that modify will not touch the EID; just ACLs and NameToEids??
// No change to olNum and ulNum either!
func handleModify(statusFilename string, config types.AppNetworkConfig,
	status types.AppNetworkStatus) {
	fmt.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	appNum := status.AppNum
	fmt.Printf("handleModify appNum %d\n", appNum)

	status.PendingModify = true
	writeAppNetworkStatus(&status, statusFilename)

	// Look for ACL and NametoEids changes in overlay
	// XXX flag others as errors; need lastError in status?
	// XXX flag change in olNum as error
	for i, _ := range config.OverlayNetworkList {
		olNum := i + 1
		fmt.Printf("handleModify olNum %d\n", olNum)
	}
	// Look for ACL changes in underlay
	// XXX flag others as errors; need lastError in status?
	// XXX flag change in olNum as error
	for i, _ := range config.UnderlayNetworkList {
		ulNum := i + 1
		fmt.Printf("handleModify ulNum %d\n", ulNum)
	}
	// Write out what we modified to AppNetworkStatus
	// XXX todo
	status.UUIDandVersion = config.UUIDandVersion
	status.PendingModify = false
	writeAppNetworkStatus(&status, statusFilename)
}

// Need the olNum and ulNum to delete and EID route to delete
func handleDelete(statusFilename string, status types.AppNetworkStatus) {
	fmt.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	appNum := status.AppNum
	maxOlNum := status.OlNum
	maxUlNum := status.UlNum
	fmt.Printf("handleDelete appNum %d maxOlNum %d maxUlNum %d\n",
		appNum, maxOlNum, maxUlNum)

	status.PendingDelete = true
	writeAppNetworkStatus(&status, statusFilename)

	if status.IsZedmanager {
		if len(status.OverlayNetworkList) != 1 ||
		   len(status.UnderlayNetworkList) != 0 {
			log.Println("Malformed IsZedmanager status; ignored")
			return
		}
		// Delete the address from loopback
		// Delete fd00::/8 route
		// Delete fe80::1 neighbor

		//    ip addr del ${EID}/128 dev lo
		EID := status.OverlayNetworkList[0].EID
		addr, err := netlink.ParseAddr(EID.String() + "/128")
		if err != nil {
			fmt.Printf("ParseAddr %s failed: %s\n", EID, err)
			return
		}
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			fmt.Printf("LinkByname(lo) failed: %s\n", err)
			return
		}
		if err := netlink.AddrDel(lo, addr); err != nil {
			fmt.Printf("AddrDel %s failed: %s\n", EID, err)
		}

		//    ip route del fd00::/8 via fe80::1 src $eid dev $intf
		upLink, err := netlink.LinkByName(globalConfig.Uplink)
		if err != nil {
			fmt.Printf("LinkByname(%s) failed: %s\n",
				globalConfig.Uplink, err)
		}
		index := upLink.Attrs().Index
		_, ipnet, err := net.ParseCIDR("fd00::/8")
		if err != nil {
			log.Fatal("ParseCIDR fd00::/8 failed:\n", err)
		}
		via := net.ParseIP("fe80::1")
		if via == nil {
			log.Fatal("ParseIP fe80::1 failed: ", err)
		}
		rt := netlink.Route{Dst: ipnet, LinkIndex: index,
			Gw: via, Src: EID}
		if err := netlink.RouteDel(&rt); err != nil {
			fmt.Printf("RouteDel fd00::/8 failed: %s\n", err)
		}
		//    ip nei del fe80::1 lladdr 0:0:0:0:0:1 dev $intf
		neigh := netlink.Neigh{LinkIndex: index, IP: via}
		if err := netlink.NeighDel(&neigh); err != nil {
			fmt.Printf("NeighDel fe80::1 failed: %s\n", err)
		}		

		// XXX delete ACLs?
		// XXX delete hosts from /etc/host?
	} else {
		// Delete everything for overlay
		// XXX need EID for route deletion? Only for IsZedmanager case
		for olNum := 1; olNum <= maxOlNum; olNum++ {
			fmt.Printf("handleDelete olNum %d\n", olNum)
			olIfname := "bo" + strconv.Itoa(olNum) + "_" +
				strconv.Itoa(appNum)
			fmt.Printf("Deleting olIfname %s\n", olIfname)
			attrs := netlink.NewLinkAttrs()
			attrs.Name = olIfname
			oLink := &netlink.Bridge{LinkAttrs: attrs}
	
			// Start clean
			netlink.LinkDel(oLink)

			cfgFilename := "radvd." + olIfname + ".conf"
			cfgPathname := "/etc/" + cfgFilename

			pkillUserArgs("radvd", cfgFilename, true)
			cmd := "rm"
			args := []string{
				"-f",
				cfgPathname,
				}
			_, err := exec.Command(cmd, args...).Output()
			if err != nil {
				fmt.Printf("Command %v %v failed: %s\n",
					cmd, args, err)
			}
		}

		// Delete everything in underlay
		for ulNum := 1; ulNum <= maxUlNum; ulNum++ {
			fmt.Printf("handleDelete ulNum %d\n", ulNum)
			ulIfname := "bu" + strconv.Itoa(appNum)
			fmt.Printf("Deleting ulIfname %s\n", ulIfname)
	
			attrs := netlink.NewLinkAttrs()
			attrs.Name = ulIfname
			uLink := &netlink.Bridge{LinkAttrs: attrs}
			netlink.LinkDel(uLink)
		}
	}
	// Write out what we modified to AppNetworkStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
}

func pkillUserArgs(userName string, match string, printOnError bool) {
	cmd := "pkill"
	args := []string{
		"-u",
		userName,
		"-f",
		match,
	}
	_, err := exec.Command(cmd, args...).Output()
	if err != nil && printOnError {
		fmt.Printf("Command %v %v failed: %s\n", cmd, args, err)
	}
}
