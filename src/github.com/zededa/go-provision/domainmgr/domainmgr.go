// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Manage Xen guest domains based on the collection of DomainConfig structs
// in /var/tmp/domainmgr/config/*.json and report on status in the
// collection of DomainStatus structs in /var/run/domainmgr/status/*.json

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var rwImgDirname string    // We store images here
var xenDirname string      // We store xen cfg files here
var verifiedDirname string // Read-only images named based on sha256 hash
// each in its own directory

func main() {
	log.Printf("Starting domainmgr\n")

	// Keeping status in /var/run to be clean after a crash/reboot
	baseDirname := "/var/tmp/domainmgr"
	runDirname := "/var/run/domainmgr"
	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"
	rwImgDirname = baseDirname + "/img" // Note that /var/run is small
	xenDirname = runDirname + "/xen"
	imgCatalogDirname := "/var/tmp/zedmanager/downloads"
	verifiedDirname = imgCatalogDirname + "/verified"

	if _, err := os.Stat(baseDirname); err != nil {
		if err := os.Mkdir(baseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(configDirname); err != nil {
		if err := os.Mkdir(configDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(runDirname); err != nil {
		if err := os.Mkdir(runDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(statusDirname); err != nil {
		if err := os.Mkdir(statusDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	// Remove any files from old guests which might have run
	if err := os.RemoveAll(rwImgDirname); err != nil {
		log.Fatal(err)
	}
	if err := os.RemoveAll(xenDirname); err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(rwImgDirname); err != nil {
		if err := os.Mkdir(rwImgDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(xenDirname); err != nil {
		if err := os.Mkdir(xenDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(imgCatalogDirname); err != nil {
		if err := os.Mkdir(imgCatalogDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(verifiedDirname); err != nil {
		if err := os.Mkdir(verifiedDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// XXX this is common code except for the types used with json
	fileChanges := make(chan string)
	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)
	for {
		change := <-fileChanges
		watch.HandleConfigStatusEvent(change,
			configDirname, statusDirname,
			&types.DomainConfig{},
			&types.DomainStatus{},
			handleCreate, handleModify, handleDelete, nil)
	}
}

func writeDomainStatus(status *types.DomainStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal DomainStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func xenCfgFilename(appNum int) string {
	return xenDirname + "/xen" + strconv.Itoa(appNum) + ".cfg"
}

func handleCreate(statusFilename string, configArg interface{}) {
	var config *types.DomainConfig

	switch configArg.(type) {
	default:
		log.Fatal("Can only handle DomainConfig")
	case *types.DomainConfig:
		config = configArg.(*types.DomainConfig)
	}
	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Name of Xen domain must be unique; uniqify AppNum
	name := config.DisplayName + "." + strconv.Itoa(config.AppNum)

	// Start by marking with PendingAdd
	status := types.DomainStatus{
		UUIDandVersion: config.UUIDandVersion,
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
		DomainName:     name,
		AppNum:         config.AppNum,
	}
	status.DiskStatusList = make([]types.DiskStatus,
		len(config.DiskConfigList))
	writeDomainStatus(&status, statusFilename)

	if err := configToStatus(*config, &status); err != nil {
		log.Printf("Failed to create DomainStatus from %v\n", config)
		status.PendingAdd = false
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		writeDomainStatus(&status, statusFilename)
		return
	}
	// Write any Location so that it can later be deleted based on status
	writeDomainStatus(&status, statusFilename)

	// Do we need to copy any rw files? !Preserve ones are copied upon
	// activation.
	for _, ds := range status.DiskStatusList {
		if ds.ReadOnly || !ds.Preserve {
			continue
		}
		log.Printf("Copy from %s to %s\n", ds.FileLocation, ds.Target)
		if _, err := os.Stat(ds.Target); err == nil && ds.Preserve {
			log.Printf("Preserve and target exists - skip copy\n")
		} else if err := cp(ds.Target, ds.FileLocation); err != nil {
			log.Printf("Copy failed from %s to %s: %s\n",
				ds.FileLocation, ds.Target, err)
			status.PendingAdd = false
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			writeDomainStatus(&status, statusFilename)
			return
		}
		log.Printf("Copy DONE from %s to %s\n",
			ds.FileLocation, ds.Target)
	}

	if config.Activate {
		doActivate(*config, &status)
	}
	// work done
	status.PendingAdd = false
	writeDomainStatus(&status, statusFilename)
	log.Printf("handleCreate(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

func doActivate(config types.DomainConfig, status *types.DomainStatus) {
	log.Printf("doActivate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Do we need to copy any rw files? Preserve ones are copied upon
	// creation
	for _, ds := range status.DiskStatusList {
		if ds.ReadOnly || ds.Preserve {
			continue
		}
		log.Printf("Copy from %s to %s\n", ds.FileLocation, ds.Target)
		if _, err := os.Stat(ds.Target); err == nil && ds.Preserve {
			log.Printf("Preserve and target exists - skip copy\n")
		} else if err := cp(ds.Target, ds.FileLocation); err != nil {
			log.Printf("Copy failed from %s to %s: %s\n",
				ds.FileLocation, ds.Target, err)
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			return
		}
		log.Printf("Copy DONE from %s to %s\n",
			ds.FileLocation, ds.Target)
	}

	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("os.Create for ", filename, err)
	}
	defer file.Close()

	if err := configToXencfg(config, *status, file); err != nil {
		log.Printf("Failed to create DomainStatus from %v\n", config)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}

	// Invoke xl create
	// XXX how do we wait for guest to boot?
	domainId, err := xlCreate(status.DomainName, filename)
	if err != nil {
		log.Printf("xl create for %s: %s\n", status.DomainName, err)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}
	log.Printf("created domainId %d for %s\n", domainId, status.DomainName)
	status.DomainId = domainId
	status.Activated = true

	// XXX dump status to log
	xlStatus(status.DomainName, status.DomainId)

	log.Printf("doActivate(%v) done for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
// XXX this should run in a goroutine to prevent handling other operations
// XXX one goroutine per UUIDandVersion to also handle copy and xlCreate?
func doInactivate(status *types.DomainStatus) {
	log.Printf("doInactivate(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	if status.DomainId != 0 {
		if err := xlShutdown(status.DomainName,
			status.DomainId); err != nil {
			log.Printf("xl shutdown %s failed: %s\n",
				status.DomainName, err)
		} else {
			// Wait for the domain to go away
			log.Printf("handleDelete(%v) for %s: waiting for domain to shutdown\n",
				status.UUIDandVersion, status.DisplayName)
		}
		gone := waitForDomainGone(*status)
		if gone {
			status.DomainId = 0
		}
	}
	if status.DomainId != 0 {
		err := xlDestroy(status.DomainName, status.DomainId)
		if err != nil {
			log.Printf("xl shutdown %s failed: %s\n",
				status.DomainName, err)
		}
		// Even if destroy failed we wait again
		log.Printf("handleDelete(%v) for %s: waiting for domain to be destroyed\n",
			status.UUIDandVersion, status.DisplayName)

		gone := waitForDomainGone(*status)
		if gone {
			status.DomainId = 0
		}
	}
	// If everything failed we leave it marked as Activated
	if status.DomainId == 0 {
		status.Activated = false

		// Do we need to delete any rw files that should
		// not be preserved across reboots?
		for _, ds := range status.DiskStatusList {
			if !ds.ReadOnly && !ds.Preserve {
				log.Printf("Delete copy at %s\n", ds.Target)
				if err := os.Remove(ds.Target); err != nil {
					log.Println(err)
					// XXX return? Cleanup status?
				}
			}
		}
	}

	log.Printf("doInactivate(%v) done for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// Produce DomainStatus based on the config
func configToStatus(config types.DomainConfig, status *types.DomainStatus) error {
	log.Printf("configToStatus(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	for i, dc := range config.DiskConfigList {
		ds := &status.DiskStatusList[i]
		ds.ImageSha256 = dc.ImageSha256
		ds.ReadOnly = dc.ReadOnly
		ds.Preserve = dc.Preserve
		ds.Format = dc.Format
		ds.Devtype = dc.Devtype
		// map from i=1 to xvda, 2 to xvdb etc
		xv := "xvd" + string(int('a')+i)
		ds.Vdev = xv
		locationDir := verifiedDirname + "/" + dc.ImageSha256
		log.Printf("configToStatus(%v) processing disk img %s for %s\n",
			config.UUIDandVersion, locationDir, config.DisplayName)
		location, err := locationFromDir(locationDir)
		if err != nil {
			return err
		}
		ds.FileLocation = location
		target := location
		if !dc.ReadOnly {
			// Pick new location for a per-guest copy
			dstFilename := fmt.Sprintf("%s/%s-%d.%s",
				rwImgDirname, dc.ImageSha256, config.AppNum,
				dc.Format)
			target = dstFilename
		}
		ds.Target = target
	}
	return nil
}

// Produce the xen cfg file based on the config and status created above
// XXX or produce output to a string instead of file to make comparison
// easier?
func configToXencfg(config types.DomainConfig,
	status types.DomainStatus, file *os.File) error {
	file.WriteString("# This file is automatically generated by domainmgr\n")
	file.WriteString(fmt.Sprintf("name = \"%s\"\n", status.DomainName))
	file.WriteString(fmt.Sprintf("builder = \"pv\"\n"))
	file.WriteString(fmt.Sprintf("uuid = \"%s\"\n",
		config.UUIDandVersion.UUID))
	// XXX where do we override? 
	if config.Kernel != "" {
		file.WriteString(fmt.Sprintf("kernel = \"%s\"\n",
			config.Kernel))
	}
	if config.Ramdisk != "" {
		file.WriteString(fmt.Sprintf("ramdisk = \"%s\"\n",
			config.Ramdisk))
	}
	if config.BootLoader != "" {
		file.WriteString(fmt.Sprintf("bootloader = \"%s\"\n",
			config.BootLoader))
	}
	// Go from kbytes to mbytes
	kbyte2mbyte := func(kbyte int) int {
		return (kbyte + 1023) / 1024
	}
	file.WriteString(fmt.Sprintf("memory = %d\n",
		kbyte2mbyte(config.Memory)))
	if config.MaxMem != 0 {
		file.WriteString(fmt.Sprintf("maxmem = %d\n",
			kbyte2mbyte(config.MaxMem)))
	}
	vCpus := config.VCpus
	if vCpus == 0 {
		vCpus = 1
	}
	file.WriteString(fmt.Sprintf("vcpus = %d\n", vCpus))
	maxCpus := config.MaxCpus
	if maxCpus == 0 {
		maxCpus = vCpus
	}
	file.WriteString(fmt.Sprintf("maxcpus = %d\n", maxCpus))
	if config.CPUs != "" {
		file.WriteString(fmt.Sprintf("cpus = \"%s\"\n", config.CPUs))
	}
	if config.DeviceTree != "" {
		file.WriteString(fmt.Sprintf("device_tree = \"%s\"\n",
			config.DeviceTree))
	}
	dtString := ""
	for _, dt := range config.DtDev {
		if dtString != "" {
			dtString += ","
		}
		dtString += fmt.Sprintf("\"%s\"", dt)
	}
	if dtString != "" {
		file.WriteString(fmt.Sprintf("dtdev = [%s]\n", dtString))
	}
	irqString := ""
	for _, irq := range config.IRQs {
		if irqString != "" {
			irqString += ","
		}
		irqString += fmt.Sprintf("%d", irq)
	}
	if irqString != "" {
		file.WriteString(fmt.Sprintf("irqs = [%s]\n", irqString))
	}
	imString := ""
	for _, im := range config.IOMem {
		if imString != "" {
			imString += ","
		}
		imString += fmt.Sprintf("\"%s\"", im)
	}
	if imString != "" {
		file.WriteString(fmt.Sprintf("iomem = [%s]\n", imString))
	}
	// Note that qcow2 images might have partitions hence xvda1 by default
	if config.RootDev == "" {
		file.WriteString(fmt.Sprintf("root = \"/dev/xvda1\"\n"))
	} else {
		file.WriteString(fmt.Sprintf("root = \"%s\"\n",
			config.RootDev))
	}
	extra := "console=hvc0 " + config.ExtraArgs
	file.WriteString(fmt.Sprintf("extra = \"%s\"\n", extra))
	file.WriteString(fmt.Sprintf("serial = \"%s\"\n", "pty"))
	file.WriteString(fmt.Sprintf("boot = \"%s\"\n", "c"))

	diskString := ""
	for i, dc := range config.DiskConfigList {
		ds := status.DiskStatusList[i]
		access := "rw"
		if dc.ReadOnly {
			access = "ro"
		}
		oneDisk := fmt.Sprintf("'%s,%s,%s,%s'",
			ds.Target, dc.Format, ds.Vdev, access)
		fmt.Printf("Processing disk %d: %s\n", i, oneDisk)
		if diskString == "" {
			diskString = oneDisk
		} else {
			diskString = diskString + ", " + oneDisk
		}
	}
	file.WriteString(fmt.Sprintf("disk = [%s]\n", diskString))

	vifString := ""
	for _, net := range config.VifList {
		oneVif := fmt.Sprintf("'bridge=%s,vifname=%s,mac=%s'",
			net.Bridge, net.Vif, net.Mac)
		if vifString == "" {
			vifString = oneVif
		} else {
			vifString = vifString + ", " + oneVif
		}
	}
	file.WriteString(fmt.Sprintf("vif = [%s]\n", vifString))
	return nil
}

func cp(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	// no need to check errors on read only file, we already got everything
	// we need from the filesystem, so nothing can go wrong now.
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// Need to compare what might have changed. If any content change
// then we need to reboot. Thus version can change but can't handle disk or
// vif changes.
// XXX should we reboot if there are such changes? Or reject with error?
// XXX to save statusFilename when the goroutine is created.
// XXX separate goroutine to run cp? Add "copy complete" status?
func handleModify(statusFilename string, configArg interface{},
	statusArg interface{}) {
	var config *types.DomainConfig
	var status *types.DomainStatus

	switch configArg.(type) {
	default:
		log.Fatal("Can only handle DomainConfig")
	case *types.DomainConfig:
		config = configArg.(*types.DomainConfig)
	}
	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DomainStatus")
	case *types.DomainStatus:
		status = statusArg.(*types.DomainStatus)
	}
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	status.PendingModify = true
	writeDomainStatus(status, statusFilename)

	// XXX should we check if there is an error?
	if status.LastErr != "" {
		log.Printf("handleModify(%v) existing error for %s\n",
			config.UUIDandVersion, config.DisplayName)
		status.PendingModify = false
		writeDomainStatus(status, statusFilename)
		return
	}
	changed := false
	if config.Activate && !status.Activated {
		doActivate(*config, status)
		changed = true
	} else if !config.Activate && status.Activated {
		doInactivate(status)
		changed = true
	}
	if changed {
		status.PendingModify = false
		writeDomainStatus(status, statusFilename)
		log.Printf("handleModify(%v) DONE for %s\n",
			config.UUIDandVersion, config.DisplayName)
		return
	}

	// XXX check if we have status.LastErr != "" and delete and retry
	// even if same version. XXX won't the above Activate/Activated checks
	// result in redoing things? Could have failures during copy i.e.
	// before activation.

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		fmt.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		status.PendingModify = false
		writeDomainStatus(status, statusFilename)
		return
	}
	// XXX dump status to log
	xlStatus(status.DomainName, status.DomainId)

	status.PendingModify = true
	writeDomainStatus(status, statusFilename)
	// XXX Any work?
	// XXX create tmp xen cfg and diff against existing xen cfg
	// If different then stop and start. XXX xl shutdown takes a while
	// need to watch status using a go routine?

	status.PendingModify = false
	status.UUIDandVersion = config.UUIDandVersion
	writeDomainStatus(status, statusFilename)
	log.Printf("handleModify(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

var maxDelay = time.Second * 600 // 10 minutes

// Used to wait both after shutdown and destroy
func waitForDomainGone(status types.DomainStatus) bool {
	gone := false
	var delay time.Duration
	for {
		log.Printf("waitForDomainGone(%v) for %s: waiting for %v\n",
			status.UUIDandVersion, status.DisplayName, delay)
		time.Sleep(delay)
		if err := xlStatus(status.DomainName, status.DomainId); err != nil {
			log.Printf("waitForDomainGone(%v) for %s: domain is gone\n",
				status.UUIDandVersion, status.DisplayName)
			gone = true
			break
		} else {
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				// Give up
				log.Printf("waitForDomainGone(%v) for %s: giving up\n",
					status.UUIDandVersion, status.DisplayName)
				break
			}
		}
	}
	return gone
}

func handleDelete(statusFilename string, statusArg interface{}) {
	var status *types.DomainStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DomainStatus")
	case *types.DomainStatus:
		status = statusArg.(*types.DomainStatus)
	}
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// XXX dump status to log
	xlStatus(status.DomainName, status.DomainId)

	status.PendingDelete = true
	writeDomainStatus(status, statusFilename)

	if status.Activated {
		doInactivate(status)
	}
	writeDomainStatus(status, statusFilename)

	// Delete xen cfg file for good measure
	filename := xenCfgFilename(status.AppNum)
	if err := os.Remove(filename); err != nil {
		log.Println(err)
	}

	// Do we need to delete any rw files that were not deleted during
	// inactivation i.e. those preserved across reboots?
	for _, ds := range status.DiskStatusList {
		if !ds.ReadOnly && ds.Preserve {
			log.Printf("Delete copy at %s\n", ds.Target)
			if err := os.Remove(ds.Target); err != nil {
				log.Println(err)
				// XXX return? Cleanup status?
			}
		}
	}
	status.PendingDelete = false
	writeDomainStatus(status, statusFilename)
	// Write out what we modified to AppNetworkStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println(err)
	}
	log.Printf("handleDelete(%v) DONE for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

func xlCreate(domainName string, xenCfgFilename string) (int, error) {
	fmt.Printf("xlCreate %s %s\n", domainName, xenCfgFilename)
	cmd := "xl"
	args := []string{
		"create",
		xenCfgFilename,
	}
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl create failed ", err)
		log.Println("xl create output ", string(stdoutStderr))
		return 0, errors.New(fmt.Sprintf("xl create failed: %s\n",
			string(stdoutStderr)))
	}
	fmt.Printf("xl create done\n")

	args = []string{
		"domid",
		domainName,
	}
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("xl domid failed ", err)
		return 0, err
	}
	res := strings.TrimSpace(string(out))
	domainId, err := strconv.Atoi(res)
	if err != nil {
		log.Printf("Can't extract domainId from %s: %s\n", res, err)
		return 0, errors.New(fmt.Sprintf("Can't extract domainId from %s: %s\n", res, err))
	}
	return domainId, nil
}

func xlStatus(domainName string, domainId int) error {
	fmt.Printf("xlStatus %s %d\n", domainName, domainId)
	// XXX xl list -l domainId returns json. XXX but state not included!
	cmd := "xl"
	args := []string{
		"list",
		"-l",
		strconv.Itoa(domainId),
	}
	res, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("xl list failed ", err)
		return err
	}
	// XXX parse json to look at state?
	fmt.Printf("xl list done. Result %s\n", string(res))
	return nil
}

func xlShutdown(domainName string, domainId int) error {
	fmt.Printf("xlShutdown %s %d\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"shutdown",
		strconv.Itoa(domainId),
	}
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl shutdown failed ", err)
		log.Println("xl shutdown output ", string(stdoutStderr))
		return err
	}
	fmt.Printf("xl shutdown done\n")
	return nil
}

func xlDestroy(domainName string, domainId int) error {
	fmt.Printf("xlDestroy %s %d\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"destroy",
		strconv.Itoa(domainId),
	}
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl destroy failed ", err)
		log.Println("xl destroy output ", string(stdoutStderr))
		return err
	}
	fmt.Printf("xl destroy done\n")
	return nil
}

func locationFromDir(locationDir string) (string, error) {
	if _, err := os.Stat(locationDir); err != nil {
		log.Printf("Missing directory: %s, %s\n", locationDir, err)
		return "", err
	}
	// locationDir is a directory. Need to find single file inside
	// which the verifier ensures.
	locations, err := ioutil.ReadDir(locationDir)
	if err != nil {
		log.Printf("ReadDir(%s) %s\n", locationDir, err)
		return "", err
	}
	if len(locations) != 1 {
		log.Printf("Multiple files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("Multiple files in %s\n",
			locationDir))
	}
	if len(locations) == 0 {
		log.Printf("No files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("No files in %s\n",
			locationDir))
	}
	return locationDir + "/" + locations[0].Name(), nil
}
