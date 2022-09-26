// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// Must match fields of EthVF in devcommon.proto
type EthVF struct {
	Index   uint8
	PciLong string // BFD notation
	Mac     string
	VlanId  uint16
}

// VFList is list of VF for given PF (Eth device)
type VFList struct {
	Count uint8
	Data  []EthVF
}

func (vfl *VFList) GetInfo(idx uint8) *EthVF {
	for _, el := range vfl.Data {
		if el.Index == idx {
			return &el
		}
	}
	return nil
}
