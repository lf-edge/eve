// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	//"github.com/satori/go.uuid"
	"github.com/golang/protobuf/proto"
	"github.com/zededa/go-provision/types"
	"shared/proto/zconfig"
	//"errors"
	"log"
	//"os"
	"net/http"
	"mime"
	"time"
)

var configUrl string = "http://192.168.1.13:9069/api/v1/edgedevice/name/testDevice/config"

var activeVersion	string

func getCloudUrls () {

	var urlCloudCfg	= &types.UrlCloudCfg{}
	var configFile	= "/opt/zededa/etc/url-cfg.json"

	if bytes, err := ioutil.ReadFile(configFile); err != nil {
        log.Printf("Could not read configuration [%v]: %v", configFile, err)
        return
    } else {
        if err := json.Unmarshal(bytes, urlCloudCfg); err != nil {
            log.Printf("Failed to parse for external configuration: %v: error was: %v", string(bytes), err)
            return
        }
    }

	configUrl	= urlCloudCfg.ConfigUrl
	statusUrl	= urlCloudCfg.StatusUrl
	metricsUrl	= urlCloudCfg.MetricsUrl
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

	resp, err := http.Get(configUrl)

	if err != nil || resp == nil {
		fmt.Println("invalid response")
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Body)
	validateConfigMessage(resp)
}

func validateConfigMessage(r *http.Response) error {

	var ctTypeStr = "Content-Type"
	var ctTypeBinaryStr = "application/x-proto-binary"

	var ct = r.Header.Get(ctTypeStr)
	if ct == "" {
		if r.Body == nil || r.ContentLength == 0 {
			return nil
		}
	}

	mimeType, _,err := mime.ParseMediaType(ct)

	if err == nil && (mimeType == ctTypeBinaryStr) {
		return readDeviceConfigMessage(r)
	}

	fmt.Println("Conent-Type specified (%s) must be %s", ct, ctTypeBinaryStr)
	return fmt.Errorf("Conent-Type specified (%s) must be %s",
		 ct, ctTypeBinaryStr)
}

func readDeviceConfigMessage (r *http.Response) error {

	var configResp = &zconfig.EdgeDevConfResp{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("%s", bytes)

	err = proto.Unmarshal(bytes, configResp)
	if err != nil {
		fmt.Println("failed unmarshalling %v", err)
		return err
	}
	fmt.Println("%v", configResp)

	return publishDeviceConfig(configResp.Config)
}

func  publishDeviceConfig(config *zconfig.EdgeDevConfig)  error {

	// if they match return
	var devId  =  &zconfig.UUIDandVersion{};

	devId  = config.GetId()
	if devId != nil {
		if devId.Version == activeVersion {
			fmt.Printf("Same version, skipping:%v\n", config.Id.Version)
			return nil
		}
		activeVersion	= devId.Version
	}

	// create the App files
	for app := range config.Apps {

		configFilename := zedmanagerConfigDirname + "/" + config.Apps[app].Uuidandversion.Uuid + ".json"

		bytes, err := json.Marshal(config.Apps[app])
		err = ioutil.WriteFile(configFilename, bytes, 0644)
		if err != nil {
			log.Fatal(err, configFilename)
		}
	}
	return nil
}
