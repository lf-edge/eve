// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// lisp configlet for overlay interface towards domU

package zedrouter

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	log "github.com/sirupsen/logrus"
)

// Template per map server. Pass in (dns-name, authentication-key)
// Use this for the Mgmt IID
const lispMStemplateMgmt = `
lisp map-resolver {
	dns-name = %s
}
lisp map-server {
    dns-name = %s
    authentication-key = %s
    want-map-notify = yes
}
`

// Template per map server. Pass in (IID, dns-name, authentication-key)
const lispMStemplate = `
lisp map-server {
    ms-name = ms-%d
    dns-name = %s
    authentication-key = %s
    want-map-notify = yes
}
`

// Need to fill in IID in 1 place
const lispIIDtemplate = `
lisp map-cache {
    prefix {
        instance-id = %d
        eid-prefix = fd00::/8
        send-map-request = yes
    }
}
`

// Need to fill in IID and IPv4 mask
const lispIPv4IIDtemplate = `
lisp map-cache {
    prefix {
        instance-id = %d
        eid-prefix = %s
        send-map-request = yes
    }
}
`

// Need to fill in (signature, additional, olIfname, IID)
// Use this for the Mgmt IID/EID
const lispEIDtemplateMgmt = `
lisp json {
    json-name = signature
    json-string = { "signature-eid": "%s", "signature" : "%s" }
}

lisp json {
    json-name = additional-info
    json-string = %s
}

lisp interface {
    interface-name = overlay-mgmt
    device = %s
    instance-id = %d
}
`

// Need to pass in (IID, EID, rlocs), where rlocs is a string with
// sets of ports info with:
// rloc {
//        interface = %s
// }
// rloc {
//        address = %s
// }
const lispDBtemplateMgmt = `
lisp database-mapping {
    prefix {
        instance-id = %d
        eid-prefix = %s/128
        signature-eid = yes
    }
    rloc {
        json-name = signature
        priority = 255
    }
    rloc {
        json-name = additional-info
        priority = 255
    }
%s
}
`

// Need to fill in (tag, signature, tag, additional, olifname, olifname, IID)
// Use this for the application EIDs
const lispEIDtemplate = `
lisp json {
    json-name = signature-%s
    json-string = { "signature-eid":"%s", "signature" : "%s" }
}

lisp json {
    json-name = additional-info-%s
    json-string = %s
}

lisp interface {
    interface-name = overlay-%s
    device = %s
    instance-id = %d
}
`

// Need to fill in (IID, EID, IID, tag, tag, rlocs) where
// rlocs is a string with sets of ports info with:
// rloc {
//        interface = %s
// }
// rloc {
//        address = %s
//        priority = %d
// }
// rlocs could also include additional IPv4 prefix stanzas
const lispDBtemplate = `
lisp database-mapping {
    prefix {
        instance-id = %d
        eid-prefix = %s/128
        ms-name = ms-%d
    }
    rloc {
        json-name = signature-%s
        priority = 255
    }
    rloc {
        json-name = additional-info-%s
        priority = 255
    }
%s
}
`
const (
	baseFilename = types.TmpDirname + "/lisp.config.base"

	lispDirname  = "/opt/zededa/lisp"
	destFilename = "/run/lisp.config"
	RLFilename   = "/run/lisp.config.sh"
	RestartCmd   = "/bin/true"
	StopCmd      = "/bin/true"
)

// We write files with the IID-specifics (and not EID) to files
// in <runDirname>/lisp/<iid>.
// We write files with the EID-specifics to files named
// <runDirname>/lisp/<eid>.
// We concatenate all of those to baseFilename and store the result
// in destFilename
//
// Would be more polite to return an error then to Fatal
func createLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, AppIPAddr net.IP, lispSignature string,
	globalStatus types.DeviceNetworkStatus,
	tag string, olIfname string, additionalInfo string,
	mapservers []types.MapServer, legacyDataPlane bool) {

	log.Debugf("createLispConfiglet: %s %v %d %s %v %v %s %s %s %v\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, globalStatus,
		tag, olIfname, additionalInfo, mapservers)

	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(IID), 10)
	file1, err := os.Create(cfgPathnameIID)
	if err != nil {
		log.Fatal("createListConfiglet failed ", err)
	}
	defer file1.Close()

	var cfgPathnameEID string
	if isMgmt {
		// LISP gets confused if the management "lisp interface"
		// isn't first in the list. Force that for now.
		cfgPathnameEID = lispRunDirname + "/0-" + EID.String()
	} else {
		cfgPathnameEID = lispRunDirname + "/" + EID.String()
	}
	file2, err := os.Create(cfgPathnameEID)
	if err != nil {
		log.Fatal("createLispConfiglet failed ", err)
	}
	defer file2.Close()
	rlocString := ""
	for _, u := range globalStatus.Ports {
		if globalStatus.Version >= types.DPCIsMgmt &&
			!u.IsMgmt {
			continue
		}
		// Skip interfaces which are not free or have no usable address
		if !u.Free {
			continue
		}
		if len(u.AddrInfoList) == 0 {
			continue
		}
		found := false
		for _, i := range u.AddrInfoList {
			if !i.Addr.IsLinkLocalUnicast() {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		one := fmt.Sprintf("    rloc {\n        interface = %s\n    }\n",
			u.IfName)
		rlocString += one
		for _, i := range u.AddrInfoList {
			prio := 0
			if i.Addr.IsLinkLocalUnicast() {
				prio = 2
			}
			one := fmt.Sprintf("    rloc {\n        address = %s\n        priority = %d\n    }\n", i.Addr, prio)
			rlocString += one
		}
	}
	// XXX if !isMgmt need to preserve mapservers from network. How?
	for _, ms := range mapservers {
		if isMgmt {
			file1.WriteString(fmt.Sprintf(lispMStemplateMgmt,
				ms.NameOrIp, ms.NameOrIp, ms.Credential))
		} else {
			file1.WriteString(fmt.Sprintf(lispMStemplate,
				IID, ms.NameOrIp, ms.Credential))
		}
	}
	file1.WriteString(fmt.Sprintf(lispIIDtemplate, IID))
	if isMgmt {
		signatureEid := fmt.Sprintf("[%d]%s", IID, EID)
		file2.WriteString(fmt.Sprintf(lispEIDtemplateMgmt,
			signatureEid, lispSignature, additionalInfo, olIfname, IID))
		file2.WriteString(fmt.Sprintf(lispDBtemplateMgmt,
			IID, EID, rlocString))
	} else {
		// Append to rlocString based on AppIPAddr
		log.Infof("lisp: EID %s AppIPAddr %s\n",
			EID.String(), AppIPAddr.String())
		if AppIPAddr != nil && !EID.Equal(AppIPAddr) {
			one := fmt.Sprintf("    prefix {\n        instance-id = %d\n        eid-prefix = %s/32\n        ms-name = ms-%d\n    }\n",
				IID, AppIPAddr.String(), IID)
			rlocString += one
		}
		signatureEid := fmt.Sprintf("[%d]%s", IID, EID.String())
		file2.WriteString(fmt.Sprintf(lispEIDtemplate,
			tag, signatureEid, lispSignature, tag, additionalInfo, olIfname,
			olIfname, IID))
		file2.WriteString(fmt.Sprintf(lispDBtemplate,
			IID, EID, IID, tag, tag, rlocString))
	}
	updateLisp(lispRunDirname, &globalStatus, legacyDataPlane)
}

func createLispEidConfiglet(lispRunDirname string,
	IID uint32, EID net.IP, AppIPAddr net.IP, lispSignature string,
	globalStatus types.DeviceNetworkStatus,
	tag string, olIfname string, additionalInfo string,
	mapservers []types.MapServer, legacyDataPlane bool) {

	log.Debugf("createLispEidConfiglet: %s %d %s %v %v %s %s %s %v\n",
		lispRunDirname, IID, EID, lispSignature, globalStatus,
		tag, olIfname, additionalInfo, mapservers)

	var cfgPathnameEID string
	cfgPathnameEID = lispRunDirname + "/" + EID.String()
	file, err := os.Create(cfgPathnameEID)
	if err != nil {
		log.Fatal("createLispEidConfiglet ", err)
	}
	defer file.Close()

	rlocString := ""
	for _, u := range globalStatus.Ports {
		if globalStatus.Version >= types.DPCIsMgmt &&
			!u.IsMgmt {
			continue
		}
		// Skip interfaces which are not free or have no usable address
		if !u.Free {
			continue
		}
		if len(u.AddrInfoList) == 0 {
			continue
		}
		found := false
		for _, i := range u.AddrInfoList {
			if !i.Addr.IsLinkLocalUnicast() {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		one := fmt.Sprintf("    rloc {\n        interface = %s\n    }\n",
			u.IfName)
		rlocString += one
		for _, i := range u.AddrInfoList {
			prio := 0
			if i.Addr.IsLinkLocalUnicast() {
				prio = 2
			}
			one := fmt.Sprintf("    rloc {\n        address = %s\n        priority = %d\n    }\n", i.Addr, prio)
			rlocString += one
		}
	}
	// Append to rlocString based on AppIPAddr
	log.Infof("lisp: EID %s AppIPAddr %s\n",
		EID.String(), AppIPAddr.String())
	if AppIPAddr != nil && !EID.Equal(AppIPAddr) {
		one := fmt.Sprintf("    prefix {\n        instance-id = %d\n        eid-prefix = %s/32\n        ms-name = ms-%d\n    }\n",
			IID, AppIPAddr.String(), IID)
		rlocString += one
	}
	signatureEid := fmt.Sprintf("[%d]%s", IID, EID.String())
	file.WriteString(fmt.Sprintf(lispEIDtemplate,
		tag, signatureEid, lispSignature, tag, additionalInfo, olIfname,
		olIfname, IID))
	file.WriteString(fmt.Sprintf(lispDBtemplate,
		IID, EID, IID, tag, tag, rlocString))
	updateLisp(lispRunDirname, &globalStatus, legacyDataPlane)
}

func updateLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, AppIPAddr net.IP, lispSignature string,
	globalStatus types.DeviceNetworkStatus,
	tag string, olIfname string, additionalInfo string,
	mapservers []types.MapServer,
	legacyDataPlane bool) {

	log.Debugf("updateLispConfiglet: %s %v %d %s %v %v %s %s %s %v\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, globalStatus,
		tag, olIfname, additionalInfo, mapservers)

	createLispConfiglet(lispRunDirname, isMgmt, IID, EID, AppIPAddr,
		lispSignature, globalStatus, tag, olIfname, additionalInfo,
		mapservers, legacyDataPlane)
}

func deleteLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, AppIPAddr net.IP, globalStatus types.DeviceNetworkStatus,
	legacyDataPlane bool) {

	log.Debugf("deleteLispConfiglet: %s %d %s %s %v\n",
		lispRunDirname, IID, EID, AppIPAddr, globalStatus)

	var cfgPathnameEID string
	if isMgmt {
		// LISP gets confused if the management "lisp interface"
		// isn't first in the list. Force that for now.
		cfgPathnameEID = lispRunDirname + "/0-" + EID.String()
	} else {
		cfgPathnameEID = lispRunDirname + "/" + EID.String()
	}
	if err := os.Remove(cfgPathnameEID); err != nil {
		log.Errorln(err)
	}

	// XXX can't delete IID file unless refcnt since other EIDs
	// can refer to it.
	// cfgPathnameIID := lispRunDirname + "/" +
	//	strconv.FormatUint(uint64(IID), 10)

	updateLisp(lispRunDirname, &globalStatus, legacyDataPlane)
}

func updateLisp(lispRunDirname string,
	globalStatus *types.DeviceNetworkStatus,
	legacyDataPlane bool) {

	log.Debugf("updateLisp: %s %v\n",
		lispRunDirname, globalStatus.Ports)

	if deferUpdate {
		log.Infof("updateLisp deferred\n")
		deferLispRunDirname = lispRunDirname
		deferGlobalStatus = globalStatus
		return
	}

	tmpfile, err := ioutil.TempFile("/run/", "lisp.config.")
	if err != nil {
		log.Errorln("TempFile ", err)
		return
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	log.Debugf("Copying from %s to %s\n", baseFilename, tmpfile.Name())
	content, err := ioutil.ReadFile(baseFilename)
	if err != nil {
		log.Errorf("Reading base configuration file %s failed: %s\n",
			baseFilename, err)
		return
	}
	baseConfig := string(content)
	if !legacyDataPlane {
		tmpfile.WriteString(fmt.Sprintf(baseConfig, "yes"))
	} else {
		tmpfile.WriteString(fmt.Sprintf(baseConfig, "no"))
	}

	var cnt int64
	files, err := ioutil.ReadDir(lispRunDirname)
	if err != nil {
		log.Errorf("ReadDir %s failed %s\n", lispRunDirname, err)
		return
	}
	eidCount := 0
	for _, file := range files {
		// The IID files are named by the IID hence an integer
		if _, err := strconv.Atoi(file.Name()); err != nil {
			eidCount += 1
		}
		filename := lispRunDirname + "/" + file.Name()
		log.Debugf("Copying from %s to %s\n",
			filename, tmpfile.Name())
		s, err := os.Open(filename)
		if err != nil {
			log.Errorln("os.Open ", filename, err)
			return
		}
		defer s.Close()
		if cnt, err = io.Copy(tmpfile, s); err != nil {
			log.Errorln("io.Copy ", filename, err)
			return
		}
		log.Debugf("Copied %d bytes from %s\n", cnt, filename)
	}
	tmpfile.Sync()
	if err := tmpfile.Close(); err != nil {
		log.Errorln("Close ", tmpfile.Name(), err)
		return
	}

	// This seems safer; make sure it is stopped before rewriting file
	stopLisp()

	if err := os.Rename(tmpfile.Name(), destFilename); err != nil {
		log.Errorln(err)
		return
	}
	// XXX We write configuration to lisp.config.orig for debugging
	// lispers.net lisp.config file overwrite issue.
	if dat, err := ioutil.ReadFile(destFilename); err == nil {
		f, err := os.Create(destFilename + ".orig")
		if err == nil {
			f.WriteString(string(dat))
			f.Sync()
			f.Close()
		}
	}

	// Determine the set of devices from the above config file
	grep := wrap.Command("grep", "device = ", destFilename)
	awk := wrap.Command("awk", "{print $NF}")
	awk.Stdin, _ = grep.StdoutPipe()
	if err := grep.Start(); err != nil {
		log.Errorln("grep.Start failed: ", err)
		return
	}
	intfs, err := awk.Output()
	if err != nil {
		log.Errorln("awk.Output failed: ", err)
		return
	}
	_ = grep.Wait()
	_ = awk.Wait()
	devices := strings.TrimSpace(string(intfs))
	devices = strings.Replace(devices, "\n", " ", -1)
	log.Debugf("updateLisp: found %d EIDs devices <%v>\n",
		eidCount, devices)
	freeMgmtPorts := types.GetMgmtPortsFreeNoLinkLocal(*globalStatus)
	for _, u := range freeMgmtPorts {
		devices += " " + u.IfName
	}
	// Check how many EIDs we have configured. If none we stop lisp
	if eidCount == 0 {
		stopLisp()

		// XXX We have changed the design to have lisp-ztr dataplane
		// always run and not do anything unless zedrouter sends `Legacy = false`
		// configuration to lisp-ztr process via pubsub.
		// When legacyDataPlane flag is false zedrouter sends `Legacy = false`
		// to lisp-ztr dataplane.
		// The below code that stops dataplane should be removed at some point of time.
		if false {
			if !legacyDataPlane {
				maybeStopLispDataPlane()
			}
		}
	} else {
		// XXX We have changed the design to have lisp-ztr dataplane
		// always run and not do anything unless zedrouter sends `Legacy = false`
		// configuration to lisp-ztr process via pubsub.
		// When legacyDataPlane flag is false zedrouter sends `Legacy = false`
		// to lisp-ztr dataplane.
		// The below code that stops dataplane should be removed at some point of time.
		if false {
			if !legacyDataPlane {
				maybeStartLispDataPlane()
			}
		}
		restartLisp(globalStatus.Ports, devices)
	}
}

var deferUpdate = false
var deferLispRunDirname = ""
var deferGlobalStatus *types.DeviceNetworkStatus

func handleLispRestart(done bool, legacyDataPlane bool) {

	log.Debugf("handleLispRestart(%v)\n", done)
	if done {
		if deferUpdate {
			deferUpdate = false
			if deferLispRunDirname != "" {
				updateLisp(deferLispRunDirname,
					deferGlobalStatus, legacyDataPlane)
				deferLispRunDirname = ""
				deferGlobalStatus = nil
			}
		}
	} else {
		deferUpdate = true
	}
}

func restartLisp(portStatus []types.NetworkPortStatus, devices string) {

	log.Debugf("restartLisp: %v %s\n", portStatus, devices)
	if len(portStatus) == 0 {
		log.Errorf("Can not restart lisp with no ports\n")
		return
	}
	// XXX how to restart with multiple ports?
	// Find first free port with a non-link-local IPv6, or an IPv4 address
	port := portStatus[0]
	found := false
	for _, u := range portStatus {
		// Skip interfaces which are not free or have no usable address
		if !u.Free {
			continue
		}
		if len(u.AddrInfoList) == 0 {
			continue
		}
		for _, i := range u.AddrInfoList {
			if !i.Addr.IsLinkLocalUnicast() {
				port = u
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		log.Errorf("Can not restart lisp - no usable IP addresses on free ports\n")
		return
	}

	itrTimeout := 1

	// Save the lisp startup settings before restarting
	// Make sure the ITR doesn't give up to early; maybe it should
	// wait forever? Will we be dead for this time?
	const RLTemplate = "# Automatically generated by zedrouter\n" +
		"export LISP_NO_IPTABLES=\n" +
		"export LISP_PCAP_LIST='%s'\n" +
		"export LISP_ITR_WAIT_TIME=%d\n" +
		"export LISP_PORT_IFNAME=%s\n"

	b := []byte(fmt.Sprintf(RLTemplate, devices, itrTimeout, port.IfName))
	err := ioutil.WriteFile(RLFilename, b, 0744)
	if err != nil {
		log.Fatal("WriteFile", err, RLFilename)
		return
	}
	log.Debugf("Wrote %s\n", RLFilename)

	log.Debugf("Restarting LISP\n")
	cmd := wrap.Command(RestartCmd)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorln("restarting lisp failed ", err)
		log.Errorf("restarting list produced %s\n", string(stdoutStderr))
		return
	}
	log.Infof("restartLisp done: output %s\n", string(stdoutStderr))
}

func maybeStartLispDataPlane() {

	log.Debugf("maybeStartLispDataPlane: %s\n", "/opt/zededa/bin/lisp-ztr")
	isRunning, _ := isLispDataPlaneRunning()
	if isRunning {
		return
	}
	// Dataplane is currently not running. Start it.
	cmd := "nohup"
	args := []string{
		"/opt/zededa/bin/lisp-ztr",
	}
	go wrap.Command(cmd, args...).Output()
}

// Stop if dataplane(lisp-ztr) is running
// return true if dataplane was running and we stopped it.
// false otherwise
func maybeStopLispDataPlane() bool {
	isRunning, pids := isLispDataPlaneRunning()
	if isRunning {
		// kill all the dataplane processes
		for _, pid := range pids {
			cmd := wrap.Command("kill", "-9", pid)
			_, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("maybeStopLispDataPlane: Killing pid %s failed: %s\n",
					pid, err)
			}
		}
		return true
	}
	return false
}

func isLispDataPlaneRunning() (bool, []string) {

	prog := DataPlaneName

	// create pgrep command to see if dataplane is running
	cmd := wrap.Command("pgrep", prog)

	// pgrep returns 0 when there is atleast one matching program running
	// cmd.Output returns nil when pgrep returns 0, otherwise pids.
	out, err := cmd.Output()

	if err != nil {
		log.Infof("isLispDataPlaneRunning: %s process is not running: %s\n",
			prog, err)
		return false, []string{}
	}
	log.Infof("isLispDataPlaneRunning: Instances of %s is running.\n", prog)
	pids := strings.Split(string(out), "\n")

	// The last entry returned by strings.Split is an empty string.
	// splice the last entry out.
	pids = pids[:len(pids)-1]

	return true, pids
}

func stopLisp() {

	log.Debugf("stopLisp\n")
	cmd := wrap.Command(StopCmd)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorln("stopping lisp failed ", err)
		log.Errorf("stopping list produced %s\n", string(stdoutStderr))
		return
	}
	log.Debugf("stopLisp done: output %s\n", string(stdoutStderr))
}
