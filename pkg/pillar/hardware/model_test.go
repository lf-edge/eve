// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestCompatible(t *testing.T) {
	logrus.Infof("TestCompatible: START\n")

	fromProc := []byte("hisilicon,hi6220-hikey\x00hisilicon,hi6220\x00")
	expected := "hisilicon,hi6220-hikey.hisilicon,hi6220"
	actual := string(massageCompatible(fromProc))
	if actual != expected {
		t.Errorf("Test Failed: Expected %v, Actual: %v\n",
			expected, actual)
	}
	logrus.Infof("TestCompatible: DONE\n")
}

// TestIsDMIPlaceholder pins the split between serials that identify a device
// and values every unit of a model reports identically. The "real" cases are
// serials observed on actual hardware, including a Supermicro system, baseboard
// and chassis serial from one machine and an HPE serial recovered from a Type 1
// UUID; none may ever be discarded. The "placeholder" cases are the values
// firmware ships for an unprogrammed field.
func TestIsDMIPlaceholder(t *testing.T) {
	deviceSerials := []string{
		"S279678X8335734",
		"WM179S000284",
		"CE101AG41A10040",
		"ZM143S051601",
		"ZM16AS024713",
		"CM144S013179",
		"MXQ93102WL",
		"0123456789A",
		"AB",
	}
	for _, s := range deviceSerials {
		if isDMIPlaceholder(s) {
			t.Errorf("isDMIPlaceholder(%q) = true, want false", s)
		}
	}

	placeholders := []string{
		"",
		"   ",
		"To be filled by O.E.M.",
		"To Be Filled By O.E.M.",
		"TO BE FILLED BY O.E.M",
		"Default string",
		"Not Specified",
		"Not Present",
		"Not Settable",
		"System Serial Number",
		"Chassis Serial Number",
		"SystemSerialNumb",
		"OEM_Serial",
		"None",
		"N/A",
		"Unknow",
		"INVALID",
		"0123456789",
		"1234567890",
		"SYS-1234567890",
		"0000000000",
		"1111",
		"-",
		"0",
		"xxxxxxxxxxx",
		"  0123456789  ",
		"\t0000000000\n",
	}
	for _, s := range placeholders {
		if !isDMIPlaceholder(s) {
			t.Errorf("isDMIPlaceholder(%q) = false, want true", s)
		}
	}
}

// TestIsRepeatedRuneEmpty pins the contract that isDMIPlaceholder relies on but
// cannot reach: the empty string is not repetition. Returning true here would
// be harmless today only because the caller short-circuits first.
func TestIsRepeatedRuneEmpty(t *testing.T) {
	if isRepeatedRune("") {
		t.Error(`isRepeatedRune("") = true, want false`)
	}
}
