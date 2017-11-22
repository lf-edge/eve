// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"crypto/x509"
	"io/ioutil"
	"github.com/golang/protobuf/proto"
	"github.com/zededa/api/zconfig"
	"strings"
	"log"
	"net/http"
	"mime"
	"time"
	"crypto/tls"
	"bytes"
	"os"
)

const (
		MaxReaderSmall      = 1 << 16 // 64k
		MaxReaderMaxDefault = MaxReaderSmall
		MaxReaderMedium     = 1 << 19 // 512k
		MaxReaderHuge       = 1 << 21 // two megabytes
		configTickTimeout   = 1 // in minutes
)

var configApi	string	= "api/v1/edgedevice/config"
var statusApi	string	= "api/v1/edgedevice/info"
var metricsApi	string	= "api/v1/edgedevice/metrics"

// XXX remove global variables
var activeVersion	string
var configUrl		string
var deviceId		string
var metricsUrl		string
var statusUrl		string

var serverFilename	string = "/opt/zededa/etc/server"

var dirName		string = "/opt/zededa/etc"
var deviceCertName	string = dirName + "/device.cert.pem"
var deviceKeyName	string = dirName + "/device.key.pem"
var rootCertName	string = dirName + "/root-certificate.pem"

// XXX remove global variables
var deviceCert		tls.Certificate
var cloudClient		*http.Client

func getCloudUrls () {

	// get the server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		log.Fatal(err)
	}
	strTrim := strings.TrimSpace(string(bytes))
	serverName := strings.Split(strTrim, ":")[0]

	configUrl	=	serverName + "/" + configApi
	statusUrl	=	serverName + "/" + statusApi
	metricsUrl	=	serverName + "/" + metricsApi

	deviceCert, err = tls.LoadX509KeyPair(deviceCertName, deviceKeyName)
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

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{deviceCert},
		ServerName:   serverName,
		RootCAs:      caCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	tlsConfig.BuildNameToCertificate()

	log.Printf("Connecting to %s\n", serverName)

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	cloudClient = &http.Client{Transport: transport, Timeout: 90 * time.Second} //XXX FIXME remove timeout...
}

// got a trigger for new config. check the present version and compare
// if this is a new version, initiate update
//  compare the old version config with the new one
// delete if some thing is not present in the old config
// for the new config create entries in the zMgerConfig Dir
// for each of the above buckets

func configTimerTask() {

	fmt.Println("starting config fetch timer task");
	getLatestConfig(nil);

	ticker := time.NewTicker(time.Minute  * configTickTimeout)

	for t := range ticker.C {
		fmt.Println(t)
		getLatestConfig(nil);
	}
}

func getLatestConfig(deviceCert []byte) {

	fmt.Printf("config-url: %s\n", configUrl)
	resp, err := cloudClient.Get("https://" + configUrl)

	if err != nil {
		log.Printf("URL get fail: %v\n", err)
	} else {
		log.Println("got response for config from zedcloud: ",resp)
		// XXX don't have validate also parse and save!
		validateConfigMessage(resp)
	}
}

func validateConfigMessage(r *http.Response) error {

	var ctTypeStr		= "Content-Type"
	var ctTypeProtoStr	= "application/x-proto-binary"

	var ct = r.Header.Get(ctTypeStr)

	if ct == "" {
		if r.Body == nil || r.ContentLength == 0 {
			return fmt.Errorf("Header content empty")
		}

		if r.ContentLength >= MaxReaderMaxDefault {
			return bytes.ErrTooLarge
		}
	}

	mimeType, _,err := mime.ParseMediaType(ct)

	if err != nil {
		return fmt.Errorf("Get Content-type error")
	}
	switch mimeType {
	case ctTypeProtoStr: {
			return readDeviceConfigProtoMessage(r)
		}
	default: {
			return fmt.Errorf("Content-type not supported", mimeType)
		}
	}
}

func readDeviceConfigProtoMessage (r *http.Response) error {

	var config= &zconfig.EdgeDevConfig{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}
	//log.Println(" proto bytes(config) received from cloud: ", fmt.Sprintf("%s",bytes))
	log.Printf("parsing proto %d bytes\n", len(bytes))
	err = proto.Unmarshal(bytes, config)
	if err != nil {
		log.Println("Unmarshalling failed: %v", err)
		return err
	}

	return publishDeviceConfig(config)
}

func  publishDeviceConfig(config *zconfig.EdgeDevConfig)  error {

	log.Printf("Publishing config %v\n", config)

	// if they match return
	var devId  =  &zconfig.UUIDandVersion{};

	devId  = config.GetId()
	if devId != nil {
		// store the device id
		deviceId = devId.Uuid
		if devId.Version == activeVersion {
			log.Printf("Same version, skipping:%v\n", config.Id.Version)
			return nil
		}
		activeVersion	= devId.Version
	}
	// get the current set of App files
	curAppFilenames, err := ioutil.ReadDir(zedmanagerConfigDirname)

	if  err != nil {
		log.Printf("read dir %s fail, err: %v\n", zedmanagerConfigDirname, err)
	}

	Apps := config.GetApps()

	if len(Apps) == 0 {

		// No valid Apps, in the new configuration
		// delete all current App instancess
		log.Printf("No apps in new config\n")
		if len(curAppFilenames) != 0 {

			for _, curApp := range curAppFilenames {

				var curAppFilename	= curApp.Name()

				// file type json
				if strings.HasSuffix(curAppFilename, ".json") {
					log.Printf("No apps in config; removing %s\n",
						curAppFilename)
					os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
				}
			}
		}

	} else {

		// delete an app instance, if not present in the new set
		if len(curAppFilenames) != 0 {

			for _, curApp := range curAppFilenames {

				curAppFilename	:=	curApp.Name()

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
					if found == false {
						log.Printf("Remove app config %s\n",
							curAppFilename)
						os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
					}
				}
			}
		}

		// add new App instances
		handleLookUpParam(config)
		parseConfig(config)
	}

	return nil
}
