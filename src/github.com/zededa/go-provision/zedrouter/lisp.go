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
)

// Need to fill in IID in 2 places
// Use this for the Mgmt IID
// XXX need to be able to set the ms name?
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

// Need to fill in (signature, IID, EID, IID, UplinkIfname)
// Use this for the Mgmt IID/EID
// XXX need to be able to set the username dummy?
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
`

// Need to fill in (tag, signature, IID, EID, IID, IID, IID, UplinkIfname, tag)
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

// XXX would be more polite to return an error then to Fatal
func createLispConfiglet(lispRunDirname string, isMgmt bool, IID uint32,
			EID net.IP, signature string, upLinkIfname string,
			tag string) {
	fmt.Printf("createLispConfiglet: %s %v %d %s %s %s %s\n",
		lispRunDirname, isMgmt, IID, EID, signature, upLinkIfname,
		tag)
	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(IID), 10)
	file1, err := os.Create(cfgPathnameIID)
	if err != nil {
		log.Fatal("os.Create for ", cfgPathnameIID, err)
	}
	defer file1.Close()

	cfgPathnameEID := lispRunDirname + "/" + EID.String()
	file2, err := os.Create(cfgPathnameEID)
	if err != nil {
		log.Fatal("os.Create for ", cfgPathnameEID, err)
	}
	defer file2.Close()
	if isMgmt {
		file1.WriteString(fmt.Sprintf(lispIIDtemplateMgmt, IID, IID))
		file2.WriteString(fmt.Sprintf(lispEIDtemplateMgmt,
			signature, IID, EID, IID, upLinkIfname))
	} else {
		file1.WriteString(fmt.Sprintf(lispIIDtemplate,
			IID, IID, IID, IID))
		file2.WriteString(fmt.Sprintf(lispEIDtemplate,
			tag, signature, IID, EID, IID, IID, IID, upLinkIfname,
			tag))
	}
	updateLisp(lispRunDirname, upLinkIfname)
}

func deleteLispConfiglet(lispRunDirname string, IID uint32,
			EID net.IP, upLinkIfname string) {
	fmt.Printf("deleteLispConfiglet: %s %d %s %s\n",
		lispRunDirname, IID, EID, upLinkIfname)

	cfgPathnameEID := lispRunDirname + "/" + EID.String()
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
	for _, file := range files {
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
	restartLisp(lispRunDirname, upLinkIfname)
}

// XXX would like to limit number of restarts of LISP. Do at end of loop
// main event loop in zedrouter.go??
func restartLisp(lispRunDirname string, upLinkIfname string) {
	fmt.Printf("restartLisp: %s %s\n", lispRunDirname, upLinkIfname)
	cmd := RestartCmd
	args := []string{
		"8080",
		upLinkIfname,
	}
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("RESTART-LISP failed ", err)
	}
}

// XXX need cwd change; get this error:
// python: can't open file 'remove-lisp-locks.pyo': [Errno 2] No such file or directory
func stopLisp(lispRunDirname string) {
	fmt.Printf("stopLisp: %s\n", lispRunDirname)
	cmd := StopCmd
	_, err := exec.Command(cmd).Output()
	if err != nil {
		log.Println("STOP-LISP failed ", err)
	}
}
