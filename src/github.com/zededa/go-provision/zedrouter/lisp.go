// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// lisp configlet for overlay interface towards domU

package main

import (
	"fmt"       
//XXX	"log"
	"net"
//	"os"
//	"os/exec"
//	"path"
)

// Need to fill in IID in 2 places
// Use this for the Mgmt IID
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

// XXX would be more polite to return an error then to Fatal
func createLispConfiglet(globalRunDirname string, IID uint32,
			EID net.IP, Signature string) {
	fmt.Printf("createLispConfiglet: %s %d %s %s\n",
		globalRunDirname, IID, EID, Signature)
	// XXX Implement
}

// XXX would be more polite to return an error then to Fatal
func deleteLispConfiglet(globalRunDirname string, IID uint32,
			EID net.IP, Signature string) {
	fmt.Printf("deleteLispConfiglet: %s %d %s %s\n",
		globalRunDirname, IID, EID, Signature)
	// XXX Implement

	// XXX can't delete IID configlet unless refcnt
}


// XXX would like to limit number of restarts of LISP. Do at end of loop??
func restartLisp(globalRunDirname string) {
	fmt.Printf("restartLisp: %s\n", globalRunDirname)
	// XXX Implement

	// XXX need LISP install pathname and uplink and 8080!
}

func stopLisp(globalRunDirname string) {
	fmt.Printf("stopLisp: %s\n", globalRunDirname)
	// XXX Implement
}
