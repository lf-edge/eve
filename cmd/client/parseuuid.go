// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zconfig"
	"log"
	"mime"
	"net/http"
	"strings"
)

func parseUUID(configUrl string, resp *http.Response, contents []byte) (uuid.UUID, error) {
	var devUUID uuid.UUID

	if err := validateConfigMessage(configUrl, resp); err != nil {
		log.Println("validateConfigMessage: ", err)
		return devUUID, err
	}

	config, err := readDeviceConfigProtoMessage(contents)
	if err != nil {
		log.Println("readDeviceConfigProtoMessage: ", err)
		return devUUID, err
	}
	uuidStr := strings.TrimSpace(config.GetId().Uuid)
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Printf("uuid.FromString(%s): %s\n", uuidStr, err)
		return devUUID, err
	}
	return devUUID, nil
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
		log.Println("Unmarshalling failed: %v", err)
		return nil, err
	}
	return config, nil
}
