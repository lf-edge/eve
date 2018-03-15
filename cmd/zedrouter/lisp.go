// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// lisp configlet for overlay interface towards domU

package main

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// Template per map server. Pass in (dns-name, authentication-key)
// Use this for the Mgmt IID
const lispMStemplateMgmt = `
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

// Need to fill in (signature, additional, olIfname, IID)
// Use this for the Mgmt IID/EID
const lispEIDtemplateMgmt = `
lisp json {
    json-name = signature
    json-string = { "signature" : "%s" }
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
// sets of uplink info with:
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
    json-string = { "signature" : "%s" }
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
// rlocs is a string with sets of uplink info with:
// rloc {
//        interface = %s
// }
// rloc {
//        address = %s
//        priority = %d
// }
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
	identityDirname = "/config"
	baseFilename    = identityDirname + "/lisp.config.base"

	lispDirname  = "/opt/zededa/lisp"
	destFilename = lispDirname + "/lisp.config"
	RestartCmd   = lispDirname + "/RESTART-LISP"
	StopCmd      = lispDirname + "/STOP-LISP"
	RLFilename   = lispDirname + "/RL"
)

// We write files with the IID-specifics (and not EID) to files
// in <globalRunDirname>/lisp/<iid>.
// We write files with the EID-specifics to files named
// <globalRunDirname>/lisp/<eid>.
// We concatenate all of those to baseFilename and store the result
// in destFilename
//
// Would be more polite to return an error then to Fatal
func createLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, lispSignature string,
	globalStatus types.DeviceNetworkStatus,
	tag string, olIfname string, additionalInfo string,
	lispServers []types.LispServerInfo) {
	log.Printf("createLispConfiglet: %s %v %d %s %v %s %s %s %s %v\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, globalStatus,
		tag, olIfname, additionalInfo, lispServers)
	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(IID), 10)
	file1, err := os.Create(cfgPathnameIID)
	if err != nil {
		log.Fatal("os.Create for ", cfgPathnameIID, err)
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
		log.Fatal("os.Create for ", cfgPathnameEID, err)
	}
	defer file2.Close()
	rlocString := ""
	for _, u := range globalStatus.UplinkStatus {
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
	for _, ms := range lispServers {
		if isMgmt {
			file1.WriteString(fmt.Sprintf(lispMStemplateMgmt,
				ms.NameOrIp, ms.Credential))
		} else {
			file1.WriteString(fmt.Sprintf(lispMStemplate,
				IID, ms.NameOrIp, ms.Credential))
		}
	}
	file1.WriteString(fmt.Sprintf(lispIIDtemplate, IID))
	if isMgmt {
		file2.WriteString(fmt.Sprintf(lispEIDtemplateMgmt,
			lispSignature, additionalInfo, olIfname, IID))
		file2.WriteString(fmt.Sprintf(lispDBtemplateMgmt,
			IID, EID, rlocString))
	} else {
		file2.WriteString(fmt.Sprintf(lispEIDtemplate,
			tag, lispSignature, tag, additionalInfo, olIfname,
			olIfname, IID))
		file2.WriteString(fmt.Sprintf(lispDBtemplate,
			IID, EID, IID, tag, tag, rlocString))
	}
	updateLisp(lispRunDirname, globalStatus.UplinkStatus)
}

func updateLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, lispSignature string,
	globalStatus types.DeviceNetworkStatus,
	tag string, olIfname string, additionalInfo string,
	lispServers []types.LispServerInfo) {
	log.Printf("updateLispConfiglet: %s %v %d %s %v %s %s %s %s %v\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, globalStatus,
		tag, olIfname, additionalInfo, lispServers)
	createLispConfiglet(lispRunDirname, isMgmt, IID, EID, lispSignature,
		globalStatus, tag, olIfname, additionalInfo, lispServers)
}

func deleteLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, globalStatus types.DeviceNetworkStatus) {
	log.Printf("deleteLispConfiglet: %s %d %s %v\n",
		lispRunDirname, IID, EID, globalStatus)

	var cfgPathnameEID string
	if isMgmt {
		// LISP gets confused if the management "lisp interface"
		// isn't first in the list. Force that for now.
		cfgPathnameEID = lispRunDirname + "/0-" + EID.String()
	} else {
		cfgPathnameEID = lispRunDirname + "/" + EID.String()
	}
	if err := os.Remove(cfgPathnameEID); err != nil {
		log.Println(err)
	}

	// XXX can't delete IID file unless refcnt since other EIDs
	// can refer to it.
	// cfgPathnameIID := lispRunDirname + "/" +
	//	strconv.FormatUint(uint64(IID), 10)

	updateLisp(lispRunDirname, globalStatus.UplinkStatus)
}

func updateLisp(lispRunDirname string, upLinkStatus []types.NetworkUplink) {
	log.Printf("updateLisp: %s %v\n", lispRunDirname, upLinkStatus)

	if deferUpdate {
		log.Printf("updateLisp deferred\n")
		deferLispRunDirname = lispRunDirname
		deferUpLinkStatus = upLinkStatus
		return
	}

	tmpfile, err := ioutil.TempFile("/tmp/", "lisp")
	if err != nil {
		log.Println("TempFile ", err)
		return
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	log.Printf("Copying from %s to %s\n", baseFilename, tmpfile.Name())
	s, err := os.Open(baseFilename)
	if err != nil {
		log.Println("os.Open ", baseFilename, err)
		return
	}
	defer s.Close()
	var cnt int64
	if cnt, err = io.Copy(tmpfile, s); err != nil {
		log.Println("io.Copy ", baseFilename, err)
		return
	}
	log.Printf("Copied %d bytes from %s\n", cnt, baseFilename)
	files, err := ioutil.ReadDir(lispRunDirname)
	if err != nil {
		log.Println(err)
		return
	}
	eidCount := 0
	for _, file := range files {
		// The IID files are named by the IID hence an integer
		if _, err := strconv.Atoi(file.Name()); err != nil {
			eidCount += 1
		}
		filename := lispRunDirname + "/" + file.Name()
		log.Printf("Copying from %s to %s\n", filename, tmpfile.Name())
		s, err := os.Open(filename)
		if err != nil {
			log.Println("os.Open ", filename, err)
			return
		}
		defer s.Close()
		if cnt, err = io.Copy(tmpfile, s); err != nil {
			log.Println("io.Copy ", filename, err)
			return
		}
		log.Printf("Copied %d bytes from %s\n", cnt, filename)
	}
	if err := tmpfile.Close(); err != nil {
		log.Println("Close ", tmpfile.Name(), err)
		return
	}
	// This seems safer; make sure it is stopped before rewriting file
	stopLisp()

	if err := os.Rename(tmpfile.Name(), destFilename); err != nil {
		log.Println("Rename ", tmpfile.Name(), destFilename, err)
		return
	}

	// Determine the set of devices from the above config file
	grep := wrap.Command("grep", "device = ", destFilename)
	awk := wrap.Command("awk", "{print $NF}")
	awk.Stdin, _ = grep.StdoutPipe()
	if err := grep.Start(); err != nil {
		log.Println("grep.Start failed: ", err)
		return
	}
	intfs, err := awk.Output()
	if err != nil {
		log.Println("awk.Output failed: ", err)
		return
	}
	_ = grep.Wait()
	_ = awk.Wait()
	devices := strings.TrimSpace(string(intfs))
	devices = strings.Replace(devices, "\n", " ", -1)
	log.Printf("updateLisp: found %d EIDs devices <%v>\n", eidCount, devices)

	// Check how many EIDs we have configured. If none we stop lisp
	if eidCount == 0 {
		stopLisp()
	} else {
		restartLisp(upLinkStatus, devices)
	}
}

var deferUpdate = false
var deferLispRunDirname = ""
var deferUpLinkStatus []types.NetworkUplink = nil

func handleLispRestart(done bool) {
	log.Printf("handleLispRestart(%v)\n", done)
	if done {
		if deferUpdate {
			deferUpdate = false
			if deferLispRunDirname != "" {
				updateLisp(deferLispRunDirname,
					deferUpLinkStatus)
				deferLispRunDirname = ""
				deferUpLinkStatus = nil
			}
		}
	} else {
		deferUpdate = true
	}
}

func restartLisp(upLinkStatus []types.NetworkUplink, devices string) {
	log.Printf("restartLisp: %v %s\n",
		upLinkStatus, devices)
	if len(upLinkStatus) == 0 {
		log.Printf("Can not restart lisp with no uplinks\n")
		return
	}
	// XXX hack to avoid hang in pslisp on Erik's laptop
	if broken {
		// Issue pkill -f lisp-core.pyo
		log.Printf("Calling pkill -f lisp-core.pyo\n")
		cmd := wrap.Command("pkill", "-f", "lisp-core.pyo")
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			log.Println("pkill failed ", err)
			log.Printf("pkill output %s\n", string(stdoutStderr))
		}
	}
	// XXX how to restart with multiple uplinks?
	// Find first free uplink with a non-link-local IPv6, or an IPv4 address
	uplink := upLinkStatus[0]
	found := false
	for _, u := range upLinkStatus {
		// Skip interfaces which are not free or have no usable address
		if !u.Free {
			continue
		}
		if len(u.AddrInfoList) == 0 {
			continue
		}
		for _, i := range u.AddrInfoList {
			if !i.Addr.IsLinkLocalUnicast() {
				uplink = u
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		log.Printf("Can not restart lisp - no usable IP addresses on free uplinks\n")
		return
	}

	args := []string{
		RestartCmd,
		"8080",
		uplink.IfName,
	}
	itrTimeout := 1
	cmd := wrap.Command(RestartCmd)
	cmd.Args = args
	env := os.Environ()
	env = append(env, fmt.Sprintf("LISP_NO_IPTABLES="))
	env = append(env, fmt.Sprintf("LISP_PCAP_LIST=%s", devices))
	// Make sure the ITR doesn't give up to early; maybe it should
	// wait forever? Will we be dead for this time?
	env = append(env, fmt.Sprintf("LISP_ITR_WAIT_TIME=%d", itrTimeout))
	cmd.Env = env
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("RESTART-LISP failed ", err)
		log.Printf("RESTART-LISP output %s\n", string(stdoutStderr))
		return
	}
	log.Printf("restartLisp done: output %s\n", string(stdoutStderr))

	// Save the restart as a bash command called RL
	const RLTemplate = "#!/bin/bash\n" +
		"# Automatically generated by zedrouter\n" +
		"cd `dirname $0`\n" +
		"export LISP_NO_IPTABLES=\n" +
		"export LISP_PCAP_LIST='%s'\n" +
		"export LISP_ITR_WAIT_TIME=%d\n" +
		"%s 8080 %s\n"

	b := []byte(fmt.Sprintf(RLTemplate, devices, itrTimeout, RestartCmd,
		uplink.IfName))
	err = ioutil.WriteFile(RLFilename, b, 0744)
	if err != nil {
		log.Fatal("WriteFile", err, RLFilename)
		return
	}
	log.Printf("Wrote %s\n", RLFilename)
}

func stopLisp() {
	log.Printf("stopLisp\n")
	// XXX hack to avoid hang in pslisp on Erik's laptop
	if broken {
		// Issue pkill -f lisp-core.pyo
		log.Printf("Calling pkill -f lisp-core.pyo\n")
		cmd := wrap.Command("pkill", "-f", "lisp-core.pyo")
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			log.Println("pkill failed ", err)
			log.Printf("pkill output %s\n", string(stdoutStderr))
		}
	}

	cmd := wrap.Command(StopCmd)
	env := os.Environ()
	env = append(env, fmt.Sprintf("LISP_NO_IPTABLES="))
	cmd.Env = env
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("STOP-LISP failed ", err)
		log.Printf("STOP-LISP output %s\n", string(stdoutStderr))
		return
	}
	log.Printf("stopLisp done: output %s\n", string(stdoutStderr))
	if err = os.Remove(RLFilename); err != nil {
		log.Println(err)
		return
	}
	log.Printf("Removed %s\n", RLFilename)
}
