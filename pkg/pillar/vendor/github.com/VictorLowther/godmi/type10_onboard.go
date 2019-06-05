/*
* File Name:	type10_onboard.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
)

type OnBoardDeviceTypeOfDevice byte

const (
	OnBoardDeviceOther OnBoardDeviceTypeOfDevice = 1 + iota
	OnBoardDeviceUnknown
	OnBoardDeviceVideo
	OnBoardDeviceSCSIController
	OnBoardDeviceEthernet
	OnBoardDeviceTokenRing
	OnBoardDeviceSound
	OnBoardDevicePATAController
	OnBoardDeviceSATAController
	OnBoardDeviceSASController
)

func (t OnBoardDeviceTypeOfDevice) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"Video",
		"SCSI Controller",
		"Ethernet",
		"Token Ring",
		"Sound",
		"PATA Controller",
		"SATA Controller",
		"SAS Controller",
	}
	return types[t-1]
}

type OnBoardDeviceType struct {
	status       bool
	typeOfDevice OnBoardDeviceTypeOfDevice
}

type OnBoardDeviceInformation struct {
	infoCommon
	Type        []OnBoardDeviceType
	Description []string
}

func (d OnBoardDeviceInformation) String() string {
	var info string
	title := "On Board Devices Information"
	for i, v := range d.Type {
		s := fmt.Sprintf("Device %d: Enabled: %v: Description: %s", i, v.status, v.typeOfDevice, d.Description[i])
		info += "\n\t\t" + s
	}
	return title + "\n\t\t" + info
}

func newOnBoardDeviceInformation(h dmiHeader) dmiTyper {
	var d OnBoardDeviceInformation
	data := h.data
	n := (data[0x01] - 4) / 2
	for i := byte(1); i <= n; i++ {
		var t OnBoardDeviceType
		index := 4 + 2*(i-1)
		sindex := 5 + 2*(i-1)
		t.status = data[index]&0x80 != 0
		t.typeOfDevice = OnBoardDeviceTypeOfDevice(data[index] & 0x7F)
		d.Type = append(d.Type, t)
		desc := h.FieldString(int(data[sindex]))
		d.Description = append(d.Description, desc)
	}
	return &d
}
