// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"github.com/satori/go.uuid"
	"net"
	"log"
	"strings"
)

// XXX rename to DeviceHwResources
// XXX also add the measure free memory and storage as DeviceHwStatus
// That new DeviceHwStatus should include the underlay information (set of IPv4, and IPv6 addresses)
type DeviceHwStatus struct {
	// XXX add timestamp? for last update? when sent?
	Machine    string // From uname -m
	Processor  string // From uname -p
	Platform   string // From uname -i
	Compatible string // From device-tree's compatible node
	Cpus       uint   // nproc --all
	Memory     uint   // Total memory in Kbyte
	Storage    uint   // Total flash in Kbyte
	// From dmidecode
	SystemManufacturer string
	SystemProductName  string
	SystemVersion      string
	SystemSerialNumber string
	SystemUUID         uuid.UUID
	// From the server we talked to we get our own public IP
	PublicIP net.IP
	// Geolocation information from client based on its public IP
	// XXX could also be based on GPS?
	AdditionalInfoDevice AdditionalInfoDevice
}

// XXX replace by actual AIConfig and AIStatus
// XXX need special flags to report as AIStatus?
type DeviceSwConfig struct {
	// XXX add timestamp for last update? When sent?
	// XXX add hash for merkel tree
	ApplicationConfig []SwConfig
}

// XXX replace by actual SwConfig and SwStatus
type DeviceSwStatus struct {
	// XXX add timestamp for last update? When sent?
	// XXX add lastReceivedHash and currentHash for merkel tree
	ApplicationStatus []SwStatus
}

// Actual state of sofware on device. Flows from device to ZedCloud.
// Includes all software; applications and Zededa infrastructure
// Need to restucture, since a given EID/DisplayName can have multiple versions.
// Ditto for SwConfig.
type SwStatus struct {
	// XXX add lastReceivedHash and currentHash for merkel tree
	Infra       bool   // Set for Zededa software which does not have an EID
	EID         net.IP // If one assigned. UUID alternative?
	DisplayName string
	Version     string
	Description string // optional
	State       SwState
	Activated   bool
}

// Intended state of sofware on device. Flows from ZedCloud to device.
// Includes all software; applications and Zededa infrastructure
// Note that SwConfig might make private+cert, plus EID, or allow EID generation
// Does that mean we need a cert in SwStatus? Or separate out EID allocation?
// SwConfig would have a Url, DigestAlg, and Digest as well.
type SwConfig struct {
	// XXX add hash for merkel tree
	Infra       bool   // Set for Zededa software which does not have an EID
	EID         net.IP // If one assigned. UUID alternative?
	DisplayName string
	Version     string
	Description string // optional
	State       SwState
	Activate    bool
}

// Enum names from OMA-TS-LWM2M_SwMgmt-V1_0-20151201-C
type SwState uint8

const (
	INITIAL          SwState = iota + 1
	DOWNLOAD_STARTED         // Really download in progress
	DOWNLOADED
	DELIVERED // Package integrity verified
	INSTALLED // Available to be activated
	MAXSTATE  //
)

func UrlToSafename(url string, sha string) string {

	var safename string

	if sha != "" {
		safename = strings.Replace(url, "/", " ", -1) + "." + sha
	} else {
		names := strings.Split(url, "/")
	        for _, name := range names {
		    safename = name + ".sha"
		}
	}
    return safename
}

// Remove initial part up to last '/' in URL. Note that '/' was converted
// to ' ' in Safename
func SafenameToFilename(safename string) string {
	comp := strings.Split(safename, " ")
	last := comp[len(comp)-1]
	// Drop "."sha256 tail part of Safename
	i := strings.LastIndex(last, ".")
	if i == -1 {
		log.Fatal("Malformed safename with no .sha256",
			safename)
	}
	last = last[0:i]
	return last
}

func UrlToFilename(urlName string) string {
	comp := strings.Split(urlName, "/")
	last := comp[len(comp)-1]
	return last
}
