// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"encoding/base64"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/vcom"
)

func handleTPM(data []byte) ([]byte, error) {
	tpmReq, err := decodeTpmRequest(data)
	if err != nil {
		return nil, fmt.Errorf("unable to decode TPM request: %w", err)
	}

	switch tpmReq.Request {
	case uint(vcom.RequestTpmGetEk):
		return handleTpmGetEk()
	default:
		return nil, fmt.Errorf("unknown request: %d", tpmReq.Request)
	}
}

func handleTpmGetEk() ([]byte, error) {
	ek, err := getEkPub()
	if err != nil {
		return nil, fmt.Errorf("unable to get EK public key: %w", err)
	}

	resp := encodeTpmResponseEk(ek)
	if resp == nil {
		return nil, fmt.Errorf("unable to encode response")
	}

	return resp, nil
}

func getEkPub() (string, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return "", fmt.Errorf("unable to open TPM: %w", err)
	}
	defer rw.Close()

	ek, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEKHdl)
	if err != nil {
		return "", fmt.Errorf("unable to read EK public: %w", err)
	}
	ekBytes, err := ek.Encode()
	if err != nil {
		return "", fmt.Errorf("unable to encode EK public: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ekBytes), nil
}
