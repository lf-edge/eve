// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// lisp configlet for overlay interface towards domU

package main

import (
	"fmt"       
	"log"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Need to fill in IID in 2 places
// Use this for the Mgmt IID
// XXX need to be able to set the ms name? Not needed for demo
const lispIIDtemplateMgmt=`
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
const lispIIDtemplate=`
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

// Need to fill in (signature, IID, EID, IID, UplinkIfname, olIfname, IID)
// Use this for the Mgmt IID/EID
// XXX need to be able to set the username dummy? not needed for demo
const lispEIDtemplateMgmt=`
lisp json {
    json-name = signature
    json-string = { "signature" : "%s" }
}

lisp database-mapping {
    prefix {
        instance-id = %d
        eid-prefix = %s/128
    }
    prefix {
        instance-id = %d
        eid-prefix = 'dummy@zededa.com'
    }
    rloc {
        interface = %s
    }
    rloc {
        json-name = signature
	priority = 255
    }
}
lisp interface {
	interface-name = overlay-mgmt
	device = %s
	instance-id = %d
}
`

// Need to fill in (tag, signature, IID, EID, IID, IID, IID, UplinkIfname, tag,
// olifname, olifname, IID)
// Use this for the application EIDs
const lispEIDtemplate=`
lisp json {
    json-name = signature-%s
    json-string = { "signature" : "%s" }
}

lisp database-mapping {
    prefix {
        instance-id = %d
        eid-prefix = %s/128
	ms-name = ms-%d
    }
    prefix {
        instance-id = %d
        eid-prefix = 'dummy@zededa.com'
        ms-name = ms-%d
    }
    rloc {
        interface = %s
    }
    rloc {
        json-name = signature-%s
	priority = 255
    }
}
lisp interface {
    interface-name = overlay-%s
    device = %s
    instance-id = %d
}
`

const baseFilename = "/usr/local/etc/zededa/lisp.config.base"
const destFilename = "/usr/local/bin/lisp/lisp.config"
const RestartCmd =  "/usr/local/bin/lisp/RESTART-LISP"
const StopCmd =  "/usr/local/bin/lisp/STOP-LISP"

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
			tag string, olIfname string) {
	fmt.Printf("createLispConfiglet: %s %v %d %s %s %s %s %s\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, upLinkIfname,
		tag, olIfname)
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
	}  else {
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
			lispSignature, IID, EID, IID, upLinkIfname, olIfname,
			IID))
	} else {
		file1.WriteString(fmt.Sprintf(lispIIDtemplate,
			IID, IID, IID, IID))
		file2.WriteString(fmt.Sprintf(lispEIDtemplate,
			tag, lispSignature, IID, EID, IID, IID, IID,
			upLinkIfname, tag, olIfname, olIfname, IID))
	}
	updateLisp(lispRunDirname, upLinkIfname)
}

func updateLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
			EID net.IP, lispSignature string, upLinkIfname string,
			tag string, olIfname string) {
	fmt.Printf("updateLispConfiglet: %s %v %d %s %s %s %s %s\n",
		lispRunDirname, isMgmt, IID, EID, lispSignature, upLinkIfname,
		tag, olIfname)
	createLispConfiglet(lispRunDirname, isMgmt, IID, EID, lispSignature,
		upLinkIfname, tag, olIfname)
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
	}  else {
		cfgPathnameEID = lispRunDirname + "/" + EID.String()
	}
	if err := os.Remove(cfgPathnameEID); err != nil {
		log.Println("os.Remove ", cfgPathnameEID, err)
	}

	// XXX can't delete IID file unless refcnt since other EIDs
	// can refer to it.
	// cfgPathnameIID := lispRunDirname + "/" +
	//	strconv.FormatUint(uint64(IID), 10)

	updateLisp(lispRunDirname, upLinkIfname)
}


func updateLisp(lispRunDirname string, upLinkIfname string) {
	fmt.Printf("updateLisp: %s %s\n", lispRunDirname, upLinkIfname)

	tmpfile, err := ioutil.TempFile("/tmp/", "lisp")
	if err != nil {
		log.Println("TempFile ", err)
		return
	}
	defer os.Remove(tmpfile.Name())
	
	content, err := ioutil.ReadFile(baseFilename)
	if err != nil {
		log.Println("ReadFile ", baseFilename, err)
		return
	}
	if _, err := tmpfile.Write(content); err != nil {
		log.Println("Write ", tmpfile.Name(), err)
		return
	}
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
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Println("ReadFile ", filename, err)
			return
		}
		if _, err := tmpfile.Write(content); err != nil {
			log.Println("Write ", tmpfile.Name(), err)
			return
		}
	}	
	if err := tmpfile.Close(); err != nil {
		log.Println("Close ", tmpfile.Name(), err)
		return
	}
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
		stopLisp(lispRunDirname)
	} else {
		restartLisp(lispRunDirname, upLinkIfname, devices)
	}
}

// XXX cd `dirname $0` in STOP-LISP
// XXX sleep 10 in RESTART-LISP; wait for kill
// XXX would like to limit number of restarts of LISP. Somehow do at end of loop
// main event loop in zedrouter.go??
// XXX shouldn't need to restart unless we are removing or replacing something
// XXX also need to restart when adding an overlay interface
// Adds should be ok without. How can we tell?
func restartLisp(lispRunDirname string, upLinkIfname string, devices string) {
	fmt.Printf("restartLisp: %s %s\n", lispRunDirname, upLinkIfname)
	args := []string{
		RestartCmd,
		"8080",
		upLinkIfname,
	}
	cmd := exec.Command(RestartCmd)
	cmd.Args = args
	env := os.Environ()
	env = append(env, fmt.Sprintf("LISP_NO_IPTABLES="))
	env = append(env, fmt.Sprintf("LISP_PCAP_LIST=\"%s\"", devices))
	cmd.Env = env
	_, err := cmd.Output()
	if err != nil {
		log.Println("RESTART-LISP failed ", err)
	}
	fmt.Printf("restartLisp done\n")
}

func stopLisp(lispRunDirname string) {
	fmt.Printf("stopLisp: %s\n", lispRunDirname)
	cmd := exec.Command(StopCmd)
	env := os.Environ()
	env = append(env, fmt.Sprintf("LISP_NO_IPTABLES="))
	cmd.Env = env
	_, err := cmd.Output()
	if err != nil {
		log.Println("STOP-LISP failed ", err)
	}
	fmt.Printf("stopLisp done\n")
}
