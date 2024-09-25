// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

func TestDeepCopyIoBundlError(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)

	errs := []error{
		fmt.Errorf("some error"),
		types.ErrOwnParent{},
		types.ErrParentAssigngrpMismatch{},
		types.ErrEmptyAssigngrpWithParent{},
		types.ErrCycleDetected{},
		types.ErrIOBundleCollision{
			Collisions: []types.IOBundleCollision{{
				Phylabel:   "phy1",
				USBAddr:    "usb1",
				USBProduct: "usbprod1",
				PCILong:    "pcilong",
				Assigngrp:  "assigngrp",
			},
			},
		},
	}
	iob := types.IoBundle{
		Error: types.IOBundleError{
			TimeOfError: time.Time{},
		},
	}

	for _, err := range errs {
		iob.Error.Append(err)
	}
	output := pubsub.DeepCopy(log, iob)

	t.Logf("copy: %v", output)

	for _, err := range errs {
		if !iob.Error.HasErrorByType(err) {
			t.Fatalf("error %v missing", err)
		}
	}

	if !cmp.Equal(output, iob) {
		t.Fatalf("not equal: %s", cmp.Diff(output, iob))
	}
}
