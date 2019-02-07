// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package client

import (
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/hardware"
)

// Return UUID and hardwaremodel
func parseConfig(configUrl string, resp *http.Response, contents []byte) (uuid.UUID, string, error) {
	var devUUID uuid.UUID
	var hardwaremodel string

	if err := validateConfigMessage(configUrl, resp); err != nil {
		log.Errorln("validateConfigMessage: ", err)
		return devUUID, hardwaremodel, err
	}

	config, err := readDeviceConfigProtoMessage(contents)
	if err != nil {
		log.Errorln("readDeviceConfigProtoMessage: ", err)
		return devUUID, hardwaremodel, err
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
		return devUUID, hardwaremodel, err
	}
	return devUUID, hardwaremodel, nil
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
