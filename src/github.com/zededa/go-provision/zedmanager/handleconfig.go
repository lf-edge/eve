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
	"shared/proto/devcommon"
	"shared/proto/zconfig"
	//"errors"
	"log"
	//"os"
	"net/http"
	"mime"
	"time"
	"crypto/tls"
)

var configUrl string = "http://192.168.1.8:9069/api/v1/edgedevice/config"

var activeVersion	string
var urlConfigFilename	= "/opt/zededa/etc/url-cfg.json"

func getCloudUrls () {

	var urlCloudCfg		= &types.UrlCloudCfg{}

	if bytes, err := ioutil.ReadFile(urlConfigFilename); err != nil {
        log.Printf("Could not read configuration [%v]: %v", urlConfigFilename, err)
		writeCloudUrls()
        return
    } else {
        if err := json.Unmarshal(bytes, urlCloudCfg); err != nil {
            log.Printf("Failed to parse %v: error was: %v", string(bytes), err)
			writeCloudUrls()
            return
        }
    }

	configUrl	= urlCloudCfg.ConfigUrl
	statusUrl	= urlCloudCfg.StatusUrl
	metricsUrl	= urlCloudCfg.MetricsUrl
}

func writeCloudUrls() {

	var urlCloudCfg		= &types.UrlCloudCfg{}

	urlCloudCfg.ConfigUrl	=	configUrl
	urlCloudCfg.StatusUrl	=	statusUrl
	urlCloudCfg.MetricsUrl	=	metricsUrl

	b, err := json.Marshal(urlCloudCfg)
	if err != nil {
		log.Fatal(err, "json Marshal cloudConfig")
	}

	err = ioutil.WriteFile(urlConfigFilename, b, 0644)
	if err != nil {
		log.Fatal(err, urlConfigFilename)
	}
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

	/*resp, err := http.Get(configUrl)

	if err != nil || resp == nil {
		fmt.Println("invalid response")
		fmt.Println(err)
		return
	}*/
	client := &http.Client{
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{
                                InsecureSkipVerify: true,
                        },
                },
        }
        resp, err := client.Get("https://" + configUrl)
        if err != nil {
                log.Fatalf("Failed to get URL: %v", err)
        }
        defer resp.Body.Close()
	validateConfigMessage(resp)
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
