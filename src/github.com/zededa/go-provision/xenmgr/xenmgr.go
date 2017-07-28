// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Manage Xen guest domains based on the collection of DomainConfig structs
// in /var/tmp/xenmgr/config/*.json and report on status in the
// collection of DomainStatus structs in /var/run/xenmgr/status/*.json

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

var rwImgDirname string	// We store images here
var xenDirname string	// We store xen cfg files here
var verifiedDirname string // Read-only images named based on sha256 hash
			// each in its own directory
			
func main() {
	// Keeping status in /var/run to be clean after a crash/reboot
	baseDirname := "/var/tmp/xenmgr"
	runDirname := "/var/run/xenmgr"
	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"
	rwImgDirname = baseDirname + "/img"	// Note that /var/run is small
	xenDirname = runDirname + "/xen"
	imgCatalogDirname := "/var/tmp/zedmanager/downloads"
	verifiedDirname = imgCatalogDirname + "/verified"
	
	if _, err := os.Stat(baseDirname); err != nil {
		if err := os.Mkdir(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(configDirname); err != nil {
		if err := os.Mkdir(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(runDirname); err != nil {
		if err := os.Mkdir(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(statusDirname); err != nil {
		if err := os.Mkdir(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
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
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]
		if !strings.HasSuffix(fileName, ".json") {
			log.Printf("Ignoring file <%s>\n", fileName)
			continue
		}
		if operation == "D" {
			statusFile := statusDirname + "/" + fileName
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
			status := types.DomainStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s DomainStatus file: %s\n",
					err, statusFile)
				continue
			}
			uuid := status.UUIDandVersion.UUID
			if uuid.String()+".json" != fileName {
				log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
					fileName, uuid.String())
				continue
			}
			statusName := statusDirname + "/" + fileName
			handleDelete(statusName, status)
			continue
		}
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}
		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		config := types.DomainConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s DomainConfig file: %s\n",
				err, configFile)
			continue
		}
		uuid := config.UUIDandVersion.UUID
		if uuid.String()+".json" != fileName {
			log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
				fileName, uuid.String())
			continue
		}
		statusFile := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFile); err != nil {
			// File does not exist in status hence new
			statusName := statusDirname + "/" + fileName
			handleCreate(statusName, config)
			continue
		}
		// Compare Version string
		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFile)
			continue
		}
		status := types.DomainStatus{}
		if err := json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s DomainStatus file: %s\n",
				err, statusFile)
			continue
		}
		uuid = status.UUIDandVersion.UUID
		if uuid.String()+".json" != fileName {
			log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
				fileName, uuid.String())
			continue
		}
		// Look for pending* in status and repeat that operation.
		// XXX After that do a full ReadDir to restart ...
		if status.PendingAdd {
			statusName := statusDirname + "/" + fileName
			handleCreate(statusName, config)
			// XXX set something to rescan?
			continue
		}
		if status.PendingDelete {
			statusName := statusDirname + "/" + fileName
			handleDelete(statusName, status)
			// XXX set something to rescan?
			continue
		}
		if status.PendingModify {
			statusName := statusDirname + "/" + fileName
			handleModify(statusName, config, status)
			// XXX set something to rescan?
			continue
		}
			
		if config.UUIDandVersion.Version ==
			status.UUIDandVersion.Version {
			fmt.Printf("Same version %s for %s\n",
				config.UUIDandVersion.Version,
				fileName)
			continue
		}
		statusName := statusDirname + "/" + fileName
		handleModify(statusName, config, status)
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
	// XXX which permissions?
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func xenCfgFilename(appNum int) string {
	return xenDirname + "/xen" + strconv.Itoa(appNum) + ".cfg"
}

func handleCreate(statusFilename string, config types.DomainConfig) {
	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Name of Xen domain must be unique; uniqify AppNum
	name := config.DisplayName + "." + strconv.Itoa(config.AppNum)

	// Start by marking with PendingAdd
	status := types.DomainStatus{
		UUIDandVersion: config.UUIDandVersion,
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
		DomainName:	name,
		AppNum:		config.AppNum,
	}
	status.DiskStatusList = make([]types.DiskStatus,
		len(config.DiskConfigList))
	writeDomainStatus(&status, statusFilename)

	// XXX defer this until activate; could be activate up front
	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("os.Create for ", filename, err)
	}
	defer file.Close()
	// XXX split into configToStatus which allocates name etc and
	// generateXenCfg(config, status, file); latter once activated
	if err := configToStatusAndXencfg(config, &status, file); err != nil {
		log.Printf("Failed to create DomainStatus from %v\n", config)
		// XXX should we clear PendingAdd?
		status.PendingAdd = false
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		writeDomainStatus(&status, statusFilename)
		return
	}
	// Write any Location so that it can later be deleted based on status
	// XXX need to calculate ds.Target even if we don't have a vif
	writeDomainStatus(&status, statusFilename)

	// Do we need to copy any rw files?
	for _, ds := range status.DiskStatusList {
		if !ds.ReadOnly {
			log.Printf("Copy from %s to %s\n",
				ds.FileLocation, ds.Target)
			if _, err := os.Stat(ds.Target); err == nil && ds.Preserve {
				log.Printf("Preserve and target exists - skip copy\n");
			} else if err := cp(ds.Target, ds.FileLocation); err != nil {
				log.Printf("Copy failed from %s to %s: %s\n",
					ds.FileLocation, ds.Target, err)
				// XXX return? Cleanup status? Will never retry
				// XXX should we clear PendingAdd?
				status.PendingAdd = false
				status.LastErr = fmt.Sprintf("%v", err)
				status.LastErrTime = time.Now()
				writeDomainStatus(&status, statusFilename)
				return
			}
			log.Printf("Copy DONE from %s to %s\n",
				ds.FileLocation, ds.Target)
		}
	}
	// Invoke xl create; XXX how do we wait for it to complete?
	// XXX report back state from xl list?
	domainId, err := xlCreate(status.DomainName, filename)
	if err != nil {
		log.Printf("xl create for %s: %s\n", status.DomainName, err)
		status.PendingAdd = false
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		writeDomainStatus(&status, statusFilename)
		return
	}
	log.Printf("created domainId %d for %s\n", domainId, status.DomainName)
	status.DomainId = domainId
	status.Activated = true
	// XXX what do we do with console? Add the ability to send to a local
	// file? Or vnc over mgmt overlay

	// XXX have a go routine to watch xl status?
	xlStatus(status.DomainName, status.DomainId)

	// work done
	status.PendingAdd = false
	writeDomainStatus(&status, statusFilename)
	log.Printf("handleCreate(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

// Produce DomainStatus and the xen cfg file based on the config
// XXX or produce output to a string instead of file to make comparison
// easier?
func configToStatusAndXencfg(config types.DomainConfig,
     status *types.DomainStatus, file *os.File) error {
	file.WriteString("# This file is automatically generated by xenmgr\n")
	file.WriteString(fmt.Sprintf("name = \"%s\"\n", status.DomainName))
	file.WriteString(fmt.Sprintf("builder = \"pv\"\n"))
	file.WriteString(fmt.Sprintf("uuid = \"%s\"\n",
		config.UUIDandVersion.UUID))
	file.WriteString(fmt.Sprintf("kernel = \"%s\"\n", config.Kernel))
	if config.Ramdisk != "" {
		file.WriteString(fmt.Sprintf("ramdisk = \"%s\"\n",
			config.Ramdisk))
	}
	// Go from kbytes to mbytes
	kbyte2mbyte := func (kbyte int) int {
		return (kbyte+1023)/1024
	}
	file.WriteString(fmt.Sprintf("memory = %d\n",
		kbyte2mbyte(config.Memory)))
	if config.MaxMem != 0 {
		file.WriteString(fmt.Sprintf("maxmem = %d\n",
			kbyte2mbyte(config.MaxMem)))
	}
	file.WriteString(fmt.Sprintf("vcpus = %d\n", config.VCpus))
	// XXX should add pinning somehow. Need status of available CPUs to
	// zedcloud?
	// XXX cpus=string
	// XXX also device passthru?
	// XXX note that qcow2 images might have partitions hence xvda1
	extra := "console=hvc0 root=/dev/xvda1 " + config.ExtraArgs
	file.WriteString(fmt.Sprintf("extra = \"%s\"\n", extra))
	file.WriteString(fmt.Sprintf("serial = \"%s\"\n", "pty"))
	file.WriteString(fmt.Sprintf("boot = \"%s\"\n", "c"))

	diskString := ""
	for i, dc := range config.DiskConfigList {
		ds := &status.DiskStatusList[i]
		ds.ImageSha256 = dc.ImageSha256
		ds.ReadOnly = dc.ReadOnly
		ds.Preserve = dc.Preserve
		ds.Format = dc.Format
		ds.Devtype = dc.Devtype
		// map from i=1 to xvda, 2 to xvdb etc
		xv := "xvd" + string(int('a') + i )
		ds.Vdev = xv
		locationDir := verifiedDirname + "/" + dc.ImageSha256
		if _, err := os.Stat(locationDir); err != nil {
			log.Printf("Missing directory: %s, %s\n",
				locationDir, err)
			return err
		}
		// locationDir is a directory. Need to find single file inside
		// XXX this can fail if same image downloaded from different
		// URLs. Can reduce probability if ... basename instead of
		// safename. But can we merge to common name somewhere?
		locations, err := ioutil.ReadDir(locationDir)
		if err != nil {
			log.Printf("ReadDir(%s) %s\n",
				locationDir, err)
			return err
		}
		if len(locations) != 1 {
			log.Printf("Multiple files in %s\n",
				locationDir)
			return errors.New(fmt.Sprintf("Multiple files in %s\n",
				locationDir))
		}
		location := locationDir + "/" + locations[0].Name()
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
// then we need to reboot. Thus version by itself can change but nothing
// else. Such a version change would be e.g. due to an ACL change.
// XXX to save statusFilename when the gorouting is created.
// XXX send "m" to channel
// XXX channel handler looks at activate and starts/stops
// XXX separate goroutine to run cp? Add "copy complete" status?
func handleModify(statusFilename string, config types.DomainConfig,
	status types.DomainStatus) {
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// XXX dump status
	xlStatus(status.DomainName, status.DomainId)

	status.PendingModify = true
	writeDomainStatus(&status, statusFilename)
	// XXX Any work?
	// XXX create tmp xen cfg and diff against existing xen cfg
	// If different then stop and start. XXX xl shutdown takes a while
	// need to watch status using a go routine?
	
	status.PendingModify = false
	writeDomainStatus(&status, statusFilename)
	log.Printf("handleModify(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

// Need the olNum and ulNum to delete and EID route to delete
func handleDelete(statusFilename string, status types.DomainStatus) {
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// XXX dump status
	xlStatus(status.DomainName, status.DomainId)

	status.PendingDelete = true
	writeDomainStatus(&status, statusFilename)
	if status.DomainId != 0 {
		if err := xlShutdown(status.DomainName, status.DomainId); err != nil {
			log.Printf("xl shutdown %s failed: %s\n",
				status.DomainName, err)
			// XXX shutdown never fails; how do we have a timeout
			// and a deferred destroy without risk clobbering a
			// new instance? Have to wait to report in status that
			// it is gone in any case.
			err := xlDestroy(status.DomainName, status.DomainId)
			if err != nil {
				log.Printf("xl shutdown %s failed: %s\n",
					status.DomainName, err)
			}
		}
		status.DomainId = 0
		writeDomainStatus(&status, statusFilename)
	}
	// Delete xen cfg file for good measure
	filename := xenCfgFilename(status.AppNum)
	if err := os.Remove(filename); err != nil {
		log.Println("Failed to remove", filename, err)
	}
	
	// Do we need to delete any rw files?
	for _, ds := range status.DiskStatusList {
		if !ds.ReadOnly {
			log.Printf("Delete copy at %s\n", ds.Target)
			// XXX even with Preserve set needs to remove here
			if true {
				log.Printf("XXX - skip remove\n");
			} else if err := os.Remove(ds.Target); err != nil {
				log.Printf("Remove failed %s: %s\n",
					ds.Target, err)
				// XXX return? Cleanup status?
				// XXX cleanup rest instead of return?
				// Means leaving an error somewhere?
				// XXX should we clear PendingDelete?
				status.PendingDelete = false
				writeDomainStatus(&status, statusFilename)
				return
			}
		}
	}
	status.PendingDelete = false
	writeDomainStatus(&status, statusFilename)
	// Write out what we modified to AppNetworkStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
	log.Printf("handleDelete(%v) DONE for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

func xlCreate(domainName string, xenCfgFilename string)(int, error) {
	fmt.Printf("xlCreate %s %s\n", domainName, xenCfgFilename)     
	cmd := "xl"
	args := []string{
		"create",
		xenCfgFilename,
	}
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl create failed ", err)
		log.Println("xl create output ", out)
		return 0, errors.New(fmt.Sprintf("xl create failed: %s\n",
				string(out)))
	}
	fmt.Printf("xl create done\n")

	args = []string{
		"domid",
		domainName,
	}
	out, err = exec.Command(cmd, args...).Output()
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
	// XXX parse json to look at 
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
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("xl shutdown failed ", err)
		return err
	}
	fmt.Printf("xl shutdown done\n")
	return nil
}

func xlDestroy(domainName string, domainId int) error {
	fmt.Printf("xlDestroy %s %s\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"destroy",
		strconv.Itoa(domainId),
	}
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("xl destroy failed ", err)
		return err
	}
	fmt.Printf("xl destroy done\n")
	return nil
}
