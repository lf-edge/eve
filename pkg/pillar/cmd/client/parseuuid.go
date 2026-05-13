// Copyright (c) 2017-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"strings"

	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

// parseUUIDResponse extracts the device UUID and the controller-provided
// hardwaremodel override (if any) from a /uuid response body.
func parseUUIDResponse(resp *http.Response, contents []byte) (uuid.UUID, string, error) {
	var hardwaremodel string
	var devUUID uuid.UUID
	var uuidResponse = &eveuuid.UuidResponse{}
	err := proto.Unmarshal(contents, uuidResponse)
	if err != nil {
		log.Errorf("Unmarshalling uuidResponse failed: %v", err)
		return devUUID, hardwaremodel, err
	}
	productName := uuidResponse.GetProductName()
	manufacturer := uuidResponse.GetManufacturer()
	if manufacturer != "" && productName != "" {
		hardwaremodel = hardware.FormatModel(manufacturer, productName, "")
	}
	uuidStr := strings.TrimSpace(uuidResponse.GetUuid())
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Errorf("uuid.FromString(%s): %s", uuidStr, err)
		return devUUID, hardwaremodel, err
	}
	return devUUID, hardwaremodel, err
}

func generateUUIDRequest() ([]byte, error) {
	uuidRequest := &eveuuid.UuidRequest{}
	b, err := proto.Marshal(uuidRequest)
	if err != nil {
		return b, err
	}
	return b, nil
}
