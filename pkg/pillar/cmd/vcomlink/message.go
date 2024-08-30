// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"encoding/json"

	"github.com/lf-edge/eve/pkg/pillar/vcom"
)

func getChannel(data []byte) (uint, error) {
	var msg vcom.Base
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return 0, err
	}

	return uint(msg.Channel), nil
}

func encodeError(msg string) []byte {
	data, err := json.Marshal(vcom.Error{
		Base: vcom.Base{
			Channel: int(vcom.ChannelError),
		},
		Error: msg,
	})

	if err != nil {
		return nil
	}

	return data
}

func encodeTpmResponseEk(ek string) []byte {
	data, err := json.Marshal(vcom.TpmResponseEk{
		Base: vcom.Base{
			Channel: int(vcom.ChannelTpm),
		},
		Ek: ek,
	})

	if err != nil {
		return nil
	}

	return data
}

func decodeTpmRequest(data []byte) (*vcom.TpmRequest, error) {
	tpmReq := new(vcom.TpmRequest)
	err := json.Unmarshal(data, tpmReq)
	if err != nil {
		return nil, err
	}

	return tpmReq, nil
}
