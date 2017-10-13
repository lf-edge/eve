// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
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

var configURL string = "http://192.168.1.15:9069/api/v1/edgedevice/testDevice/config"

var activeVersion types.UUIDandVersion

// got a trigger for new config. check the present version and compare
// if this is a new version, initiate update
//  compare the old version config with the new one
// delete if some thing is not present in the old config
// for the new config create entries in the zMgerConfig Dir
// for each of the above buckets

func configTimerTask() {

	getLatestConfig(nil);

	ticker := time.NewTicker(time.Minute  * 30)

	for t := range ticker.C {
		fmt.Println("Tick at", t)
		getLatestConfig(nil);
	}
}

func getLatestConfig(deviceCert []byte) {

	resp, err := http.Get(configURL)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(resp)
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

	return fmt.Errorf("Conent-Type specified (%s) must be %x",
		 ct, ctTypeBinaryStr)
}

func readDeviceConfigMessage (r *http.Response) error {

	var configMsg = &zconfig.EdgeDeviceConfig{}

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = proto.Unmarshal(bytes, configMsg)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return parseDeviceConfigMessage(configMsg)
}

func parseDeviceConfigMessage(configMsg *zconfig.EdgeDeviceConfig) error {
	var config types.DeviceConfigResponse

	fmt.Println("%v\n", configMsg)
	bytes, err := proto.MarshalMessageSetJSON(configMsg)
	if err != nil {
		fmt.Println(err)
		return err
	}
	// we have the JAON now
	fmt.Println("%v\n", bytes)

	if err := json.Unmarshal(bytes, config); err != nil {
		fmt.Println(err)
		return err
	}

	return publishDeviceConfig(config.Config)
}

func  publishDeviceConfig(config types.EdgeDevConfig)  error {

	// if they match return
	if (config.Id.Version == activeVersion.Version) {
		fmt.Printf("Same version, skipping:%v\n", config.Id.Version)
		return nil
	}

	activeVersion = config.Id

	// create the App files
	for app := range config.Apps {
		//fmt.Printf("App:%v\n", config.Apps[app])

		b, err := json.Marshal(config.Apps[app])
		if err != nil {
			log.Fatal(err, "json Marshal AppInstanceConfig" + config.Apps[app].DisplayName)
		}

		configFilename := zedmanagerConfigDirname + "/" + config.Apps[app].ConfigSha256 + ".json"

		err = ioutil.WriteFile(configFilename, b, 0644)
		if err != nil {
			log.Fatal(err, configFilename)
		}
	}
	return nil
}
