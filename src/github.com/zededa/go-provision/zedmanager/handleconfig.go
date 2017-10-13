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
	//"log"
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
	ticker := time.NewTicker(time.Second  * 5)
	for t := range ticker.C {
		fmt.Println("Tick at", t)
		zDeviceConfigGet(nil);
	}
}

func zDeviceConfigGet(deviceCert []byte) {

	resp, err := http.Get(configURL)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(resp)
	validateMessage(resp)
}

func validateMessage(r *http.Response) error {

	ct := r.Header.Get("Content-Type")

	if ct == "" {
		if r.Body == nil || r.ContentLength == 0 {
			return nil
		}
	}

	conentTypeBinary := "application/x-proto-binary"
	mimeType, _,  err := mime.ParseMediaType(ct)

	if err == nil && (mimeType == "application/x-proto-binary") {

		return fmt.Errorf("Conent-Type specified (%s) must be %x",
			 ct, conentTypeBinary)
		return readMessage(r)
	} else {
		return fmt.Errorf("Conent-Type specified (%s) must be %x",
			 ct, conentTypeBinary)
	}
}

func readMessage (r *http.Response) error {

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	 configMsg := &zconfig.EdgeDeviceConfig{}
	 ret := proto.Unmarshal(b, configMsg)
	if ret != nil {
		return ret
	}

	return zDeviceCloudConfigParse(configMsg)
}

func zDeviceConfigVersionCheck(oldVersion types.UUIDandVersion, newVersion types.UUIDandVersion) bool {

	// if they match return true
	if (oldVersion.Version != newVersion.Version) {
		return true
	}
	return false
}

func zDeviceCloudConfigParse(configMsg *zconfig.EdgeDeviceConfig) error {
	var config types.DeviceConfigResponse

	fmt.Println("%v\n", configMsg)
	bytes, err := proto.MarshalMessageSetJSON(configMsg)
	if err != nil {
		fmt.Println(err)
	}
	// we have the JAON now
	fmt.Println("%v\n", bytes)

	if err := json.Unmarshal(bytes, config); err != nil {
		fmt.Println(err)
		return err
	}

	return ConfigPublish(config.Config)
}

func  ConfigPublish(config types.EdgeDevConfig)  error {

	// if they match return
	if (config.Id.Version == activeVersion.Version) {
		return nil
	}
	activeVersion = config.Id

	// create the App files
	for app := range config.Apps {
		fmt.Printf("App:%v\n", app)
	}
	return nil
}
