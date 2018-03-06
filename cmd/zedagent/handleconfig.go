// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/types"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	MaxReaderSmall      = 1 << 16 // 64k
	MaxReaderMaxDefault = MaxReaderSmall
	MaxReaderMedium     = 1 << 19 // 512k
	MaxReaderHuge       = 1 << 21 // two megabytes
	configTickTimeout   = 1       // in minutes
)

var configApi string = "api/v1/edgedevice/config"
var statusApi string = "api/v1/edgedevice/info"
var metricsApi string = "api/v1/edgedevice/metrics"

// This is set once at init time and not changed
var serverName string

const (
	identityDirname = "/config"
	serverFilename  = identityDirname + "/server"
	deviceCertName  = identityDirname + "/device.cert.pem"
	deviceKeyName   = identityDirname + "/device.key.pem"
	rootCertName    = identityDirname + "/root-certificate.pem"
	uuidFileName    = identityDirname + "/uuid"
)

// A value of zero means we should use the default
// All times are in seconds.
type configItems struct {
	configInterval          uint32
	metricInterval          uint32
	resetIfCloudGoneTime    uint32
	fallbackIfCloudGoneTime uint32
}

var configItemDefaults = configItems{configInterval: 60, metricInterval: 60,
	resetIfCloudGoneTime: 168 * 3600, fallbackIfCloudGoneTime: 600}

// tlsConfig is initialized once i.e. effectively a constant
var tlsConfig *tls.Config

// devUUID is set in handleConfigInit and never changed
var devUUID uuid.UUID

// XXX need to support recreating devices. Remove when zedcloud preserves state
var zcdevUUID uuid.UUID

// Really a constant
var nilUUID uuid.UUID

func handleConfigInit() {

	// get the server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		log.Fatal(err)
	}
	strTrim := strings.TrimSpace(string(bytes))
	serverName = strings.Split(strTrim, ":")[0]

	deviceCert, err := tls.LoadX509KeyPair(deviceCertName, deviceKeyName)
	if err != nil {
		log.Fatal(err)
	}
	// Load CA cert
	caCert, err := ioutil.ReadFile(rootCertName)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{deviceCert},
		ServerName:   serverName,
		RootCAs:      caCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	b, err := ioutil.ReadFile(uuidFileName)
	if err != nil {
		log.Fatal("ReadFile", err, uuidFileName)
	}
	uuidStr := strings.TrimSpace(string(b))
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Fatal("uuid.FromString", err, string(b))
	}
	fmt.Printf("Read UUID %s\n", devUUID)
	zcdevUUID = devUUID
}

// got a trigger for new config. check the present version and compare
// if this is a new version, initiate update
//  compare the old version config with the new one
// delete if some thing is not present in the old config
// for the new config create entries in the zMgerConfig Dir
// for each of the above buckets
// XXX Combine with being able to change the timer intervals
func configTimerTask(handleChannel chan interface{}) {
	configUrl := serverName + "/" + configApi
	iteration := 0
	checkConnectivity := isZbootAvailable() && isCurrentPartitionStateInProgress()
	rebootFlag := getLatestConfig(configUrl, iteration, &checkConnectivity)

	// Make this configurable from zedcloud and call update on ticker
	max := float64(time.Minute * configTickTimeout)
	min := max * 0.3
	configTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	// Return handle to caller
	handleChannel <- configTicker
	for range configTicker.C {
		iteration += 1
		if rebootFlag == false {
			rebootFlag = getLatestConfig(configUrl, iteration, &checkConnectivity)
		}
	}
}

func triggerGetConfig(handle interface{}) {
	log.Printf("triggerGetConfig()\n")
	flextimer.TickNow(handle)
}

// Start by trying the all the free uplinks and then all the non-free
// until one succeeds in communicating with the cloud.
// We use the iteration argument to start at a different point each time.
func getLatestConfig(url string, iteration int, checkConnectivity *bool) bool {
	resp, err := sendOnAllIntf(url, nil, iteration)
	if err != nil {
		log.Printf("getLatestConfig failed: %s\n", err)
		return false
	} else {
		defer resp.Body.Close()

		// now cloud connectivity is good, mark partition state as
		// active if it was inprogress
		// XXX down the road we want more diagnostics and validation
		// before we do this.
		if *checkConnectivity && isCurrentPartitionStateInProgress() {
			curPart := getCurrentPartition()
			log.Printf("Config Fetch Task, curPart %s inprogress\n",
				curPart)
			if err := markPartitionStateActive(); err != nil {
				log.Println(err)
			} else {
				*checkConnectivity = false
			}
		}

		// Each time we hear back from the cloud we assume
		// the device and connectivity is ok so we advance the
		// watchdog timer.
		// We should only require this connectivity once every 24 hours
		// or so using a setable policy in the watchdog, but have
		// a short timeout during validation of a image post upgrade.
		zbootWatchdogOK()

		if err := validateConfigMessage(url, resp); err != nil {
			log.Println("validateConfigMessage: ", err)
			// Inform ledmanager about cloud connectivity
			types.UpdateLedManagerConfig(3)
			return false
		}

		changed, config, err := readDeviceConfigProtoMessage(resp)
		if err != nil {
			log.Println("readDeviceConfigProtoMessage: ", err)
			// Inform ledmanager about cloud connectivity
			types.UpdateLedManagerConfig(3)
			return false
		}

		// Inform ledmanager about config received from cloud
		types.UpdateLedManagerConfig(4)
		if !changed {
			if debug {
				log.Printf("Configuration from zedcloud is unchanged\n")
			}
			return false
		}
		return inhaleDeviceConfig(config)
	}
}

func validateConfigMessage(url string, r *http.Response) error {

	var ctTypeStr = "Content-Type"
	var ctTypeProtoStr = "application/x-proto-binary"

	ct := r.Header.Get(ctTypeStr)
	if ct == "" {
		return fmt.Errorf("No content-type")
	}
	mimeType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("Get Content-type error")
	}
	switch mimeType {
	case ctTypeProtoStr:
		return nil
	default:
		return fmt.Errorf("Content-type %s not supported",
			mimeType)
	}
}

var prevConfigHash []byte

// Returns changed, config, error. The changed is based on a comparison of
// the hash of the protobuf message.
func readDeviceConfigProtoMessage(r *http.Response) (bool, *zconfig.EdgeDevConfig, error) {

	var config = &zconfig.EdgeDevConfig{}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return false, nil, err
	}
	// compute sha256 of the image and match it
	// with the one in config file...
	h := sha256.New()
	h.Write(b)
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, prevConfigHash)
	prevConfigHash = configHash

	//log.Println(" proto bytes(config) received from cloud: ", fmt.Sprintf("%s",bytes))
	//log.Printf("parsing proto %d bytes\n", len(b))
	err = proto.Unmarshal(b, config)
	if err != nil {
		log.Println("Unmarshalling failed: %v", err)
		return false, nil, err
	}
	return !same, config, nil
}

func inhaleDeviceConfig(config *zconfig.EdgeDevConfig) bool {
	log.Printf("Inhaling config %v\n", config)

	// if they match return
	var devId = &zconfig.UUIDandVersion{}

	devId = config.GetId()
	if devId != nil {
		id, err := uuid.FromString(devId.Uuid)
		if err != nil {
			log.Printf("Invalid UUID %s from cloud: %s\n",
				devId.Uuid, err)
			return false
		}
		if id != devUUID {
			// XXX logic to handle re-registering a device private
			// key with zedcloud. We accept a new UUID from the
			// cloud and use that in our reports, but we do
			// not update the hostname nor LISP.
			// XXX remove once zedcloud preserves state.
			if id != zcdevUUID {
				log.Printf("XXX Device UUID changed from %s to %s\n",
					zcdevUUID.String(), id.String())
				zcdevUUID = id
			}

		}
	}
	handleLookUpParam(config)

	// delete old app configs, if any
	checkCurrentAppFiles(config)

	// delete old base os configs, if any
	checkCurrentBaseOsFiles(config)

	// add new App instances
	return parseConfig(config)
}

func checkCurrentAppFiles(config *zconfig.EdgeDevConfig) {

	// get the current set of App files
	curAppFilenames, err := ioutil.ReadDir(zedmanagerConfigDirname)
	if err != nil {
		log.Printf("%v for %s\n", err, zedmanagerConfigDirname)
		curAppFilenames = nil
	}

	Apps := config.GetApps()
	// delete any app instances which are not present in the new set
	for _, curApp := range curAppFilenames {
		curAppFilename := curApp.Name()

		// file type json
		if strings.HasSuffix(curAppFilename, ".json") {
			found := false
			for _, app := range Apps {
				appFilename := app.Uuidandversion.Uuid + ".json"
				if appFilename == curAppFilename {
					found = true
					break
				}
			}
			// app instance not found, delete
			if !found {
				log.Printf("Remove app config %s\n", curAppFilename)
				err := os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
				if err != nil {
					log.Println("Old config: ", err)
				}
				// also remove the certifiates holder config
				os.Remove(zedagentCertObjConfigDirname + "/" + curAppFilename)
			}
		}
	}
}

func checkCurrentBaseOsFiles(config *zconfig.EdgeDevConfig) {

	// get the current set of baseOs files
	curBaseOsFilenames, err := ioutil.ReadDir(zedagentBaseOsConfigDirname)
	if err != nil {
		log.Printf("%v for %s\n", err, zedagentBaseOsConfigDirname)
		curBaseOsFilenames = nil
	}

	baseOses := config.GetBase()
	// delete any baseOs config which is not present in the new set
	for _, curBaseOs := range curBaseOsFilenames {
		curBaseOsFilename := curBaseOs.Name()

		// file type json
		if strings.HasSuffix(curBaseOsFilename, ".json") {
			found := false
			for _, baseOs := range baseOses {
				baseOsFilename := baseOs.Uuidandversion.Uuid + ".json"
				if baseOsFilename == curBaseOsFilename {
					found = true
					break
				}
			}
			// baseOS instance not found, delete
			if !found {
				removeBaseOsEntry(curBaseOsFilename)
			}
		}
	}
}

func removeBaseOsEntry(baseOsFilename string) {

	uuidStr := strings.Split(baseOsFilename, ".")[0]
	log.Printf("%s, remove baseOs entry\n", uuidStr)

	// remove partition map entry
	resetPersistentPartitionInfo(uuidStr)

	// remove the certificates holder config
	os.Remove(zedagentCertObjConfigDirname + "/" + baseOsFilename)

	// remove Config File
	os.Remove(zedagentBaseOsConfigDirname + "/" + baseOsFilename)
}

func stapledCheck(connState *tls.ConnectionState) bool {
	issuer := connState.VerifiedChains[0][1]
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		log.Println("error parsing response: ", err)
		return false
	}
	now := time.Now()
	age := now.Unix() - resp.ProducedAt.Unix()
	remain := resp.NextUpdate.Unix() - now.Unix()
	if debug {
		log.Printf("OCSP age %d, remain %d\n", age, remain)
	}
	if remain < 0 {
		log.Println("OCSP expired.")
		return false
	}
	if resp.Status == ocsp.Good {
		if debug {
			log.Println("Certificate Status Good.")
		}
	} else if resp.Status == ocsp.Unknown {
		log.Println("Certificate Status Unknown")
	} else {
		log.Println("Certificate Status Revoked")
	}
	return resp.Status == ocsp.Good
}
