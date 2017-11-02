// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"github.com/golang/protobuf/proto"
	"shared/proto/devcommon"
	"shared/proto/zconfig"
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
	configTickTimeout   = 3 // in minutes
)

var configApi	string	= "api/v1/edgedevice/config"
var statusApi	string	= "api/v1/edgedevice/info"
var metricsApi	string	= "api/v1/edgedevice/metrics"

var serverName	string	= "zedcloud.zededa.net"


var activeVersion	string
var configUrl		string
var deviceId		string
var metricsUrl		string
var statusUrl		string

var serverFilename	string = "/opt/zededa/etc/server"

var dirName		string = "/opt/zededa/etc"
var deviceCertName	string = dirName + "/device.cert.pem"
var deviceKeyName	string = dirName + "/device.key.pem"

var deviceCert		tls.Certificate
var cloudClient		*http.Client

func getCloudUrls () {

	// get the server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		err = ioutil.WriteFile(serverFilename, []byte(serverName), 0644)
	} else {
		strTrim := strings.TrimSpace(string(bytes))
		serverName = strings.Split(strTrim, ":")[0]
	}

	configUrl	=	serverName + "/" + configApi
	statusUrl	=	serverName + "/" + statusApi
	metricsUrl	=	serverName + "/" + metricsApi

	deviceCert, err = tls.LoadX509KeyPair(deviceCertName, deviceKeyName)

	if err != nil {
	        log.Fatal(err)
	}
	cloudClient = &http.Client {
	                Transport: &http.Transport {
	                        TLSClientConfig: &tls.Config {
									InsecureSkipVerify:true,
	                                Certificates: []tls.Certificate{deviceCert},
	                        },
	                },
		}
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
		fmt.Printf("URL get fail: %v\n", err)
	} else {
		validateConfigMessage(resp)
	}
}

func validateConfigMessage(r *http.Response) error {

	var ctTypeStr		= "Content-Type"
	var ctTypeProtoStr	= "application/x-proto-binary"
	var ctTypeJsonStr	= "application/json"

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
	case ctTypeJsonStr: {
			return readDeviceConfigJsonMessage(r)
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

	err = proto.Unmarshal(bytes, config)
	if err != nil {
		fmt.Println("Unmarshalling failed: %v", err)
		return err
	}

	return publishDeviceConfig(config)
}

func readDeviceConfigJsonMessage (r *http.Response) error {

	var config = &zconfig.EdgeDevConfig{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = json.Unmarshal(bytes, config)
	if err != nil {
		fmt.Println("Unmarshalling failed, %v", err)
		return err
	}

	return publishDeviceConfig(config)
}

func  publishDeviceConfig(config *zconfig.EdgeDevConfig)  error {

	fmt.Printf("%v\n", config)

	// if they match return
	var devId  =  &devcommon.UUIDandVersion{};

	devId  = config.GetId()
	if devId != nil {
		// store the device id
		deviceId = devId.Uuid
		if devId.Version == activeVersion {
			fmt.Printf("Same version, skipping:%v\n", config.Id.Version)
			return nil
		}
		activeVersion	= devId.Version
	}
	// get the current set of App files
	curAppFilenames, err := ioutil.ReadDir(zedmanagerConfigDirname)

	if  err != nil {
		fmt.Printf("read dir %s fail, err: %v\n", zedmanagerConfigDirname, err)
	}

	Apps := config.GetApps()

	if Apps == nil {

		// No valid Apps, in the new configuration
		// delete all current App instancess

		for idx :=	range curAppFilenames {

			var curApp			=	curAppFilenames[idx]
			var curAppFilename	=	curApp.Name()

			// file type json
			if strings.HasSuffix(curAppFilename, ".json") {

				os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
			}
		}

	} else {

		// delete an app instance, if not present in the new set
		for idx :=	range curAppFilenames {

			curApp			:=	curAppFilenames[idx]
			curAppFilename	:=	curApp.Name()

			// file type json
			if strings.HasSuffix(curAppFilename, ".json") {

				found := false

				for app := range Apps {

					appFilename := Apps[app].Uuidandversion.Uuid + ".json"

					if appFilename == curAppFilename {
						found = true
						break
					}
				}

				// app instance not found, delete
				if found == false {
					os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
				}
			}
		}

		// publish the new config to zedmanager
		parseConfig(config)
	}

	return nil
}
