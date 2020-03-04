// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Return UUID, hardwaremodel, enterprise, and devicename
func parseConfig(configUrl string, resp *http.Response, contents []byte) (uuid.UUID, string, string, string, error) {
	var devUUID uuid.UUID
	var hardwaremodel string
	var enterprise string
	var name string

	if err := validateConfigMessage(configUrl, resp); err != nil {
		log.Errorln("validateConfigMessage: ", err)
		return devUUID, hardwaremodel, enterprise, name, err
	}

	if resp.StatusCode == http.StatusNotModified {
		log.Debugf("StatusNotModified len %d", len(contents))
		// Return as error since we are not returning any useful values.
		return devUUID, hardwaremodel, enterprise, name,
			fmt.Errorf("Unchanged StatusNotModified")
	}

	configResponse, err := readConfigResponseProtoMessage(contents)
	if err != nil {
		log.Errorln("readConfigResponseProtoMessage: ", err)
		return devUUID, hardwaremodel, enterprise, name, err
	}
	hash := configResponse.GetConfigHash()
	if hash == prevConfigHash {
		log.Debugf("Same ConfigHash %s len %d", hash, len(contents))
		// Return as error since we are not returning any useful values.
		return devUUID, hardwaremodel, enterprise, name,
			fmt.Errorf("Unchanged config hash")
	}
	log.Infof("Change in ConfigHash from %s to %s", prevConfigHash, hash)
	prevConfigHash = hash
	config := configResponse.GetConfig()

	// Check if we have an override from the device config
	manufacturer := config.GetManufacturer()
	productName := config.GetProductName()
	if manufacturer != "" && productName != "" {
		hardwaremodel = hardware.FormatModel(manufacturer, productName,
			"")
	}
	uuidStr := strings.TrimSpace(config.GetId().Uuid)
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Errorf("uuid.FromString(%s): %s\n", uuidStr, err)
		return devUUID, hardwaremodel, enterprise, name, err
	}
	enterprise = strings.TrimSpace(config.GetEnterprise())
	name = strings.TrimSpace(config.GetName())
	return devUUID, hardwaremodel, enterprise, name, nil
}

// From zedagent/handleconfig.go
func validateConfigMessage(configUrl string, r *http.Response) error {

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

func readConfigResponseProtoMessage(contents []byte) (*zconfig.ConfigResponse, error) {
	var configResponse = &zconfig.ConfigResponse{}

	err := proto.Unmarshal(contents, configResponse)
	if err != nil {
		log.Errorf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return configResponse, nil
}

// The most recent config hash we received
var prevConfigHash string

func generateConfigRequest() ([]byte, error) {
	log.Debugf("generateConfigRequest() sending hash %s", prevConfigHash)
	configRequest := &zconfig.ConfigRequest{
		ConfigHash: prevConfigHash,
	}
	b, err := proto.Marshal(configRequest)
	if err != nil {
		log.Errorln(err)
		return b, err
	}
	return b, nil
}
