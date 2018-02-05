// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"mime"
	"net"
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

// XXX remove global variables
// XXX shouldn't we know our own deviceId? Get from some global struct?
var deviceId string

// These URLs are effectively constants; depends on the server name
var configUrl string
var metricsUrl string
var statusUrl string

const (
	identityDirname   = "/config"
	serverFilename    = identityDirname + "/server"
	deviceCertName    = identityDirname + "/device.cert.pem"
	deviceKeyName     = identityDirname + "/device.key.pem"
	rootCertName      = identityDirname + "/root-certificate.pem"

	ledConfigDirName  = "/var/tmp/ledmanager/config"
	ledConfigFileName = ledConfigDirName + "/ledconfig.json"
)

// tlsConfig is initialized once i.e. effectively a constant
var tlsConfig *tls.Config

func getCloudUrls() {

	// get the server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		log.Fatal(err)
	}
	strTrim := strings.TrimSpace(string(bytes))
	serverName := strings.Split(strTrim, ":")[0]

	configUrl = serverName + "/" + configApi
	statusUrl = serverName + "/" + statusApi
	metricsUrl = serverName + "/" + metricsApi

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
}

func UpdateLedManagerConfigFile(count int) {
	blinkCount := types.LedBlinkCounter{
		BlinkCounter: count,
	}
	b, err := json.Marshal(blinkCount)
	if err != nil {
		log.Fatal(err, "json Marshal blinkCount")
	}
	err = ioutil.WriteFile(ledConfigFileName, b, 0644)
	if err != nil {
		log.Fatal("err: ", err, ledConfigFileName)
	}
}

// got a trigger for new config. check the present version and compare
// if this is a new version, initiate update
//  compare the old version config with the new one
// delete if some thing is not present in the old config
// for the new config create entries in the zMgerConfig Dir
// for each of the above buckets

func configTimerTask() {
	iteration := 0
	log.Println("starting config fetch timer task")
	getLatestConfig(configUrl, iteration)

	ticker := time.NewTicker(time.Minute * configTickTimeout)

	for t := range ticker.C {
		log.Println(t)
		iteration += 1
		getLatestConfig(configUrl, iteration)
	}
}

// Each iteration we try a different uplink. For each uplink we try all
// its local IP addresses until we get a success.
func getLatestConfig(configUrl string, iteration int) {
	intf, err := types.GetUplinkAny(deviceNetworkStatus, iteration)
	if err != nil {
		log.Printf("getLatestConfig: %s\n", err)
		return
	}
	UpdateLedManagerConfigFile(2) //XXX FIXME Just for testing...
	addrCount := types.CountLocalAddrAny(deviceNetworkStatus, intf)
	// XXX makes logfile too long; debug flag?
	log.Printf("Connecting to %s using intf %s interation %d #sources %d\n",
		configUrl, intf, iteration, addrCount)
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(deviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		// XXX makes logfile too long; debug flag?
		fmt.Printf("Connecting to %s using intf %s source %v\n",
			configUrl, intf, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}
		resp, err := client.Get("https://" + configUrl)
		if err != nil {
			log.Printf("URL get fail: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		if err := validateConfigMessage(configUrl, intf, localTCPAddr,
			resp); err != nil {
			log.Println("validateConfigMessage: ", err)
			return
		}

		//inform ledmanager about cloud connectivity...
		UpdateLedManagerConfigFile(3)

		config, err := readDeviceConfigProtoMessage(resp)
		if err != nil {
			log.Println("readDeviceConfigProtoMessage: ", err)
			return
		}
		//inform ledmanager about config received from cloud...
		UpdateLedManagerConfigFile(4)

		inhaleDeviceConfig(config)
		return
	}
	log.Printf("All attempts to connect to %s using intf %s failed\n",
		configUrl, intf)
}

func validateConfigMessage(configUrl string, intf string,
	localTCPAddr net.TCPAddr, r *http.Response) error {

	var ctTypeStr = "Content-Type"
	var ctTypeProtoStr = "application/x-proto-binary"

	switch r.StatusCode {
	case http.StatusOK:
		// XXX makes logfile too long; debug flag?
		fmt.Printf("validateConfigMessage %s using intf %s source %v StatusOK\n",
			configUrl, intf, localTCPAddr)
	default:
		fmt.Printf("validateConfigMessage %s using intf %s source %v statuscode %d %s\n",
			configUrl, intf, localTCPAddr,
			r.StatusCode, http.StatusText(r.StatusCode))
		fmt.Printf("received response %v\n", r)
		return fmt.Errorf("http status %d %s",
			r.StatusCode, http.StatusText(r.StatusCode))
	}
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

func readDeviceConfigProtoMessage(r *http.Response) (*zconfig.EdgeDevConfig, error) {

	var config = &zconfig.EdgeDevConfig{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	//log.Println(" proto bytes(config) received from cloud: ", fmt.Sprintf("%s",bytes))
	log.Printf("parsing proto %d bytes\n", len(bytes))
	err = proto.Unmarshal(bytes, config)
	if err != nil {
		log.Println("Unmarshalling failed: %v", err)
		return nil, err
	}
	return config, nil
}

func inhaleDeviceConfig(config *zconfig.EdgeDevConfig) {
	activeVersion := ""

	log.Printf("Inhaling config %v\n", config)

	// if they match return
	var devId = &zconfig.UUIDandVersion{}

	devId = config.GetId()
	if devId != nil {
		// store the device id
		deviceId = devId.Uuid
		if devId.Version == activeVersion {
			log.Printf("Same version, skipping:%v\n", config.Id.Version)
			return
		}
		activeVersion = devId.Version
	}
	handleLookUpParam(config)

	// delete old app configs, if any
	checkCurrentAppFiles(config)

	// delete old base os configs, if any
	checkCurrentBaseOsFiles(config)

	// add new App instances
	parseConfig(config)
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
				log.Printf("Remove baseOs config %s\n", curBaseOsFilename)
				err := os.Remove(zedagentBaseOsConfigDirname + "/" + curBaseOsFilename)
				if err != nil {
					log.Printf("Old config:%v\n", err)
				}
			}
		}
	}
}
