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
