// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/eve/pkg/pillar/hardware"
	"github.com/zededa/eve/sdk/go/zconfig"
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

	config, err := readDeviceConfigProtoMessage(contents)
	if err != nil {
		log.Errorln("readDeviceConfigProtoMessage: ", err)
		return devUUID, hardwaremodel, enterprise, name, err
	}
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

// Returns changed, config, error. The changed is based on a comparison of
// the hash of the protobuf message.
func readDeviceConfigProtoMessage(contents []byte) (*zconfig.EdgeDevConfig, error) {
	var config = &zconfig.EdgeDevConfig{}

	err := proto.Unmarshal(contents, config)
	if err != nil {
		log.Errorf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return config, nil
}
