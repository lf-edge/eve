// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"crypto/md5"
	"encoding/hex"
)

// NaaWWN represents the World Wide Name of the SCSI device we are emulating, using the
// Network Address Authority standard.
type NaaWWN struct {
	// OUI is the first three bytes (six hex digits), in ASCII, of your
	// IEEE Organizationally Unique Identifier, eg, "05abcd".
	OUI string
	// The VendorID is the first four bytes(eight hex digits), in ASCII, of
	// the device's vendor-specific ID (perhaps a serial number), eg, "2416c05f".
	VendorID string
	// The VendorIDExt is an optional eight more bytes (16 hex digits) in the same format
	// as the above, if necessary.
	VendorIDExt string
}

// WWN provides two WWNs, one for the device itself and one for the loopback device created by the kernel.
type WWN interface {
	DeviceWWN() string
	NexusWWN() string
}

// DeviceWWN - get DeviceID
func (n NaaWWN) DeviceWWN() string {
	return n.genID("0")
}

// NexusWWN - get NexusID
func (n NaaWWN) NexusWWN() string {
	return n.genID("1")
}

func (n NaaWWN) genID(s string) string {
	n.assertCorrect()
	naa := "naa.5"
	vend := n.VendorID + n.VendorIDExt
	if len(n.VendorIDExt) == 16 {
		naa = "naa.6"
	}
	return naa + n.OUI + s + vend
}

func (n NaaWWN) assertCorrect() {
	if len(n.OUI) != 6 {
		panic("OUI needs to be exactly 6 hex characters")
	}
	if len(n.VendorID) != 8 {
		panic("VendorID needs to be exactly 8 hex characters")
	}
	if len(n.VendorIDExt) != 0 && len(n.VendorIDExt) != 16 {
		panic("VendorIDExt needs to be zero or 16 hex characters")
	}
}

// GenerateSerial - generate serial number
func GenerateSerial(name string) string {
	digest := md5.New()
	digest.Write([]byte(name))
	return hex.EncodeToString(digest.Sum([]byte{}))[:8]
}

// GenerateWWN - generate WWN
func GenerateWWN(name string) WWN {
	return NaaWWN{
		OUI:      "000000",
		VendorID: GenerateSerial(name),
	}
}
