// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// lisp configlet for overlay interface towards domU

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Need to fill in IID in 2 places
// Use this for the Mgmt IID
// XXX need to be able to set the ms name? Not needed for demo
const lispIIDtemplateMgmt = `
lisp map-server {
    dns-name = ms1.zededa.net
    authentication-key = test1_%d
    want-map-notify = yes
}

lisp map-server {
    dns-name = ms2.zededa.net
    authentication-key = test2_%d
    want-map-notify = yes
}
`

// Need to fill in IID in 4 places
// Use this for the application IIDs
const lispIIDtemplate = `
lisp map-server {
    ms-name = ms-%d
    dns-name = ms1.zededa.net
    authentication-key = test1_%d
    want-map-notify = yes
}

lisp map-server {
    ms-name = ms-%d
    dns-name = ms2.zededa.net
    authentication-key = test2_%d
    want-map-notify = yes
}
`

// Need to fill in (signature, additional, IID, EID, UplinkIfname, olIfname, IID)
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

lisp database-mapping {
    prefix {
        instance-id = %d
        eid-prefix = %s/128
    }
    rloc {
        interface = %s
    }
    rloc {
        json-name = signature
	priority = 255
    }
    rloc {
        json-name = additional-info
	priority = 255
    }
}
lisp interface {
	interface-name = overlay-mgmt
	device = %s
	instance-id = %d
}
`

// Need to fill in (tag, signature, tag, additional, IID, EID, IID,
// UplinkIfname, tag, tag, olifname, olifname, IID)
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

lisp database-mapping {
    prefix {
        instance-id = %d
        eid-prefix = %s/128
	ms-name = ms-%d
    }
    rloc {
        interface = %s
    }
    rloc {
        json-name = signature-%s
	priority = 255
    }
    rloc {
        json-name = additional-info-%s
	priority = 255
    }
}
lisp interface {
    interface-name = overlay-%s
    device = %s
    instance-id = %d
}
`

const baseFilename = "/opt/zededa/etc/lisp.config.base"
const destFilename = "/opt/zededa/lisp/lisp.config"
const RestartCmd = "/opt/zededa/lisp/RESTART-LISP"
const StopCmd = "/opt/zededa/lisp/STOP-LISP"
const RLFilename = "/opt/zededa/lisp/RL"

// We write files with the IID-specifics (and not EID) to files
// in <globalRunDirname>/lisp/<iid>.
// We write files with the EID-specifics to files named
// <globalRunDirname>/lisp/<eid>.
// We concatenate all of those to baseFilename and store the result
// in destFilename
//
// Would be more polite to return an error then to Fatal
func createLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, lispSignature string, upLinkIfname string,
	tag string, olIfname string, additionalInfo string) {
	fmt.Printf("createLispConfiglet: %s %v %d %s %s %s %s %s %s\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, upLinkIfname,
		tag, olIfname, additionalInfo)
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
	if isMgmt {
		file1.WriteString(fmt.Sprintf(lispIIDtemplateMgmt, IID, IID))
		file2.WriteString(fmt.Sprintf(lispEIDtemplateMgmt,
			lispSignature, additionalInfo, IID, EID,
			upLinkIfname, olIfname, IID))
	} else {
		file1.WriteString(fmt.Sprintf(lispIIDtemplate,
			IID, IID, IID, IID))
		file2.WriteString(fmt.Sprintf(lispEIDtemplate,
			tag, lispSignature, tag, additionalInfo, IID, EID, IID,
			upLinkIfname, tag, tag, olIfname, olIfname, IID))
	}
	updateLisp(lispRunDirname, upLinkIfname)
}

func updateLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, lispSignature string, upLinkIfname string,
	tag string, olIfname string, additionalInfo string) {
	fmt.Printf("updateLispConfiglet: %s %v %d %s %s %s %s %s %s\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, upLinkIfname,
		tag, olIfname, additionalInfo)
	createLispConfiglet(lispRunDirname, isMgmt, IID, EID, lispSignature,
		upLinkIfname, tag, olIfname, additionalInfo)
}

func deleteLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
	EID net.IP, upLinkIfname string) {
	fmt.Printf("deleteLispConfiglet: %s %d %s %s\n",
		lispRunDirname, IID, EID, upLinkIfname)

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

	updateLisp(lispRunDirname, upLinkIfname)
}

func updateLisp(lispRunDirname string, upLinkIfname string) {
	fmt.Printf("updateLisp: %s %s\n", lispRunDirname, upLinkIfname)

	if deferUpdate {
		log.Printf("updateLisp deferred\n")
		deferLispRunDirname = lispRunDirname
		deferUpLinkIfname = upLinkIfname
		return
	}

	tmpfile, err := ioutil.TempFile("/tmp/", "lisp")
	if err != nil {
		log.Println("TempFile ", err)
		return
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	fmt.Printf("Copying from %s to %s\n", baseFilename, tmpfile.Name())
	s, err := os.Open(baseFilename)
	if err != nil {
		log.Println("os.Open ", baseFilename, err)
		return
	}
	var cnt int64
	if cnt, err = io.Copy(tmpfile, s); err != nil {
		log.Println("io.Copy ", baseFilename, err)
		return
	}
	fmt.Printf("Copied %d bytes from %s\n", cnt, baseFilename)
	files, err := ioutil.ReadDir(lispRunDirname)
	if err != nil {
		log.Println("ReadDir ", lispRunDirname, err)
		return
	}
	eidCount := 0
	for _, file := range files {
		// The IID files are named by the IID hence an integer
		if _, err := strconv.Atoi(file.Name()); err != nil {
			eidCount += 1
		}
		filename := lispRunDirname + "/" + file.Name()
		fmt.Printf("Copying from %s to %s\n", filename, tmpfile.Name())
		s, err := os.Open(filename)
		if err != nil {
			log.Println("os.Open ", filename, err)
			return
		}
		if cnt, err = io.Copy(tmpfile, s); err != nil {
			log.Println("io.Copy ", filename, err)
			return
		}
		fmt.Printf("Copied %d bytes from %s\n", cnt, filename)
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
	grep := exec.Command("grep", "device = ", destFilename)
	awk := exec.Command("awk", "{print $NF}")
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
	fmt.Printf("updateLisp: found %d EIDs devices <%v>\n", eidCount, devices)

	// Check how many EIDs we have configured. If none we stop lisp
	if eidCount == 0 {
		stopLisp()
	} else {
		restartLisp(upLinkIfname, devices)
	}
}

var deferUpdate = false
var deferLispRunDirname = ""
var deferUpLinkIfname = ""

func handleLispRestart(done bool) {
	log.Printf("handleLispRestart(%v)\n", done)
	if done {
		if deferUpdate {
			deferUpdate = false
			updateLisp(deferLispRunDirname, deferUpLinkIfname)
			deferLispRunDirname = ""
			deferUpLinkIfname = ""
		}
	} else {
		deferUpdate = true
	}
}

func restartLisp(upLinkIfname string, devices string) {
	log.Printf("restartLisp: %s %s\n",
		upLinkIfname, devices)
	args := []string{
		RestartCmd,
		"8080",
		upLinkIfname,
	}
	itrTimeout := 1
	cmd := exec.Command(RestartCmd)
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
	const RLTemplate = "#!/bin/bash\n# Automatically generated by zedrouter\ncd `dirname $0`\nLISP_NO_IPTABLES=,LISP_PCAP_LIST='%s',LISP_ITR_WAIT_TIME=%d %s 8080 %s\n"
	b := []byte(fmt.Sprintf(RLTemplate, devices, itrTimeout, RestartCmd,
		upLinkIfname))
	err = ioutil.WriteFile(RLFilename, b, 0744)
	if err != nil {
		log.Fatal("WriteFile", err, RLFilename)
		return
	}
	fmt.Printf("Wrote %s\n", RLFilename)
}

func stopLisp() {
	log.Printf("stopLisp\n")
	cmd := exec.Command(StopCmd)
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
