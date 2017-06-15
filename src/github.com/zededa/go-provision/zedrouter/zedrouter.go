// Process input changes from a config directory containing json encoded files
// with AppNetworkConfig and compare against AppNetworkStatus in the status
// dir.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"net"
	"os"
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
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("modified", baseName
					fileChanges <- "M " + baseName

				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("deleted", baseName
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

// Need some initial state to track the progress with the AppNum and
// creation of the configlets
// struct plus var with collection; indexed by UUID?
type app struct {
	AppNum int
}

var apps map[uuid.UUID]app

var globalConfig types.DeviceNetworkConfig
var globalStatus types.DeviceNetworkStatus
var globalStatusFilename string

func handleInit(configFilename string, statusFilename string) {
	apps = make(map[uuid.UUID]app)

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
	err = ioutil.WriteFile(globalStatusFilename, b, os.ModePerm)
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
	err = ioutil.WriteFile(statusFilename, b, os.ModePerm)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func handleCreate(statusFilename string, config types.AppNetworkConfig) {
	fmt.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	uuid := config.UUIDandVersion.UUID

	fmt.Printf("pre app %v\n", apps[uuid])
	if _, ok := apps[uuid]; ok {
		log.Printf("apps[%v] already exists\n", uuid)
		return
	}
	appNum := globalStatus.AppNumAllocator
	globalStatus.AppNumAllocator += 1
	writeGlobalStatus()

	apps[uuid] = app{AppNum: appNum}
	fmt.Printf("post app %v\n", apps[uuid])

	status := types.AppNetworkStatus{
		UUIDandVersion: config.UUIDandVersion,
		AppNum:         appNum,
		PendingAdd:     true,
		OlNum:          len(config.OverlayNetworkList),
		UlNum:          len(config.UnderlayNetworkList),
		IsZedmanager:   config.IsZedmanager,
	}
	writeAppNetworkStatus(&status, statusFilename)

	for i, olConfig := range config.OverlayNetworkList {
		olNum := i + 1
		fmt.Printf("olNum %d ACLs %v\n", olNum, olConfig.ACLs)

		olAddr2 := olConfig.EID
		olIfname := "bo" + strconv.Itoa(olNum) + "_" +
			strconv.Itoa(appNum)
		fmt.Printf("olIfname %s\n", olIfname)
		olAddr1 := "fd00::" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		fmt.Printf("olAddr1 %s olAddr2 %s\n", olAddr1, olAddr2)
		olMac := "00:16:3e:1:" + strconv.FormatInt(int64(olNum), 16) +
			":" + strconv.FormatInt(int64(appNum), 16)
		fmt.Printf("olMac %s\n", olMac)

		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Bridge{LinkAttrs: attrs}

		// Start clean
		netlink.LinkDel(oLink)

		attrs = netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink = &netlink.Bridge{LinkAttrs: attrs}

		//    ip link add ${olIfname} type bridge
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

		//    ip -6 route add ${olAddr2}/128 dev ${olIfname}
		_, ipnet, err := net.ParseCIDR(olAddr2.String() + "/128")
		if err != nil {
			fmt.Printf("ParseCIDR %s failed: %v\n", olAddr2, err)
		}
		fmt.Printf("oLink.Index %d\n", oLink.Index)
		rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
		if err := netlink.RouteAdd(&rt); err != nil {
			fmt.Printf("RouteAdd %s failed: %s\n", olAddr2, err)
		}
		// Write radvd configlet; start radvd
		//    Start clean
		//    pkill -u radvd -f radvd.${OLIFNAME}.conf
		//    Enable radvd on interface
		//    cat <<EOF >>/etc/radvd.${OLIFNAME}.conf
		//interface ${OLIFNAME} {
		//	IgnoreIfMissing on;
		//	AdvSendAdvert on;
		//	MaxRtrAdvInterval 1800;
		//	AdvManagedFlag on;
		//};
		//EOF
		//    radvd -u radvd -C /etc/radvd.${OLIFNAME}.conf -p /var/run/radvd.${OLIFNAME}.pid

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

		attrs := netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		uLink := &netlink.Bridge{LinkAttrs: attrs}

		// Start clean
		netlink.LinkDel(uLink)

		attrs = netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		uLink = &netlink.Bridge{LinkAttrs: attrs}
		//    ip link add ${ulIfname} type bridge
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
	// What if we have no internal state? Restarted but Status
	// (and configlets) still in place? Need to rebuild from status?
	uuid := config.UUIDandVersion.UUID

	fmt.Printf("pre app %v\n", apps[uuid])
	if _, ok := apps[uuid]; !ok {
		log.Printf("apps[%v] missing\n", uuid)
		return
	}
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
}

// Need the olNum and ulNum to delete and EID route to delete
func handleDelete(statusFilename string, status types.AppNetworkStatus) {
	fmt.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	// What if we have no internal state? Restarted but Status
	// (and configlets) still in place? Need to rebuild from status?
	uuid := status.UUIDandVersion.UUID

	fmt.Printf("pre app %v\n", apps[uuid])
	if _, ok := apps[uuid]; !ok {
		log.Printf("apps[%v] missing\n", uuid)
		return
	}
	appNum := status.AppNum
	fmt.Printf("handleDelete appNum %d\n", appNum)

	// Delete everything for overlay
	// XXX need EID for route deletion?
	for i, _ := range status.OverlayNetworkList {
		olNum := i + 1
		fmt.Printf("handleDelete olNum %d\n", olNum)
		olIfname := "bo" + strconv.Itoa(olNum) + "_" +
			strconv.Itoa(appNum)
		fmt.Printf("olIfname %s\n", olIfname)
		attrs := netlink.NewLinkAttrs()
		attrs.Name = olIfname
		oLink := &netlink.Bridge{LinkAttrs: attrs}

		// Start clean
		netlink.LinkDel(oLink)
	}
	// Look for ACL changes in underlay
	// XXX flag others as errors; need lastError in status?
	// XXX flag change in olNum as error
	for i, _ := range status.UnderlayNetworkList {
		ulNum := i + 1
		fmt.Printf("handleDelete ulNum %d\n", ulNum)
		ulIfname := "bu" + strconv.Itoa(appNum)
		fmt.Printf("ulIfname %s\n", ulIfname)

		attrs := netlink.NewLinkAttrs()
		attrs.Name = ulIfname
		uLink := &netlink.Bridge{LinkAttrs: attrs}
		netlink.LinkDel(uLink)
	}
	// Write out what we modified to AppNetworkStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
}
