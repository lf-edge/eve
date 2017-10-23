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
)

var configApi		string	=	"api/v1/edgedevice/name"
var	statusApi		string	=	"api/v1/edgedevice/info"
var	metricsApi		string	=	"api/v1/edgedevice/metrics"

//var trMethod		string	=	"https"
var serverName		string	=	"zedcloud.zededa.net"
var deviceName		string	=	"testDevice"

var deviceId		string
var activeVersion	string
var configUrl		string
var	statusUrl		string
var	metricsUrl		string

var deviceFilename		string	= "/opt/zededa/etc/device"
var serverFilename		string	= "/opt/zededa/etc/server"

func getCloudUrls () {

	// get the server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		err = ioutil.WriteFile(serverFilename, []byte(serverName), 0644)
	} else {
		strTrim := strings.TrimSpace(string(bytes))
		serverName = strings.Split(strTrim, ":")[0]
	}

	bytes, err = ioutil.ReadFile(deviceFilename)
	if err != nil {
		ioutil.WriteFile(deviceFilename, []byte(deviceName), 0644)
	} else {
		strTrim := strings.TrimSpace(string(bytes))
		deviceName = strTrim
	}

	configUrl	=	serverName + "/" + configApi + "/" + deviceName +  "/config"
	statusUrl	=	serverName + "/" + statusApi
	metricsUrl	=	serverName + "/" + metricsApi
}

// got a trigger for new config. check the present version and compare
// if this is a new version, initiate update
//  compare the old version config with the new one
// delete if some thing is not present in the old config
// for the new config create entries in the zMgerConfig Dir
// for each of the above buckets

func configTimerTask() {

	fmt.Println("starting config getch timer task");
	getLatestConfig(nil);

	ticker := time.NewTicker(time.Minute  * 3)

	for t := range ticker.C {
		fmt.Println("Tick at", t)
		getLatestConfig(nil);
	}
}

func getLatestConfig(deviceCert []byte) {

	fmt.Printf("config-url: %s\n", configUrl)

	client := &http.Client {
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
        }

	resp, err := client.Get("https://" + configUrl)

	if err != nil {
		fmt.Printf("Failed to get URL: %v\n", err)
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
			return nil
		}
	}

	mimeType, _,err := mime.ParseMediaType(ct)

	if err != nil {
		return fmt.Errorf("Conent-Type specified (%s) must be %s",
			 ct, ctTypeProtoStr)
	}

	switch mimeType {
	case ctTypeProtoStr: {
			return readDeviceConfigProtoMessage(r)
		}
	case ctTypeJsonStr: {
			return readDeviceConfigJsonMessage(r)
		}
	default: {
			fmt.Printf("Conent-Type specified (%s)\n", ct)
			bytes, err := ioutil.ReadAll(r.Body)

			if err != nil {
				fmt.Printf("%s", bytes)
			}
			return fmt.Errorf("Conent-Type specified (%s) must be %s",
				 ct, ctTypeProtoStr)
		}
	}
}

func readDeviceConfigProtoMessage (r *http.Response) error {

	var configResp = &zconfig.EdgeDevConfResp{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = proto.Unmarshal(bytes, configResp)
	if err != nil {
		fmt.Println("failed unmarshalling %v", err)
		return err
	}

	return publishDeviceConfig(configResp.Config)
}

func readDeviceConfigJsonMessage (r *http.Response) error {

	var configResp = &zconfig.EdgeDevConfResp{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = json.Unmarshal(bytes, configResp)
	if err != nil {
		fmt.Println("failed unmarshalling %v", err)
		return err
	}

	return publishDeviceConfig(configResp.Config)
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

	// create the App files
	for app := range config.Apps {

		var configFilename = zedmanagerConfigDirname + "/" +
			 config.Apps[app].Uuidandversion.Uuid + ".json"

		bytes, err := json.Marshal(config.Apps[app])
		err = ioutil.WriteFile(configFilename, bytes, 0644)
		if err != nil {
			log.Fatal(err, configFilename)
		}
	}
	return nil
}
