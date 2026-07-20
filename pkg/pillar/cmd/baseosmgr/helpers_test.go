// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"errors"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// errBoom is a generic test error.
var errBoom = errors.New("boom")

// initTestLog initialises the package-level log so tests can call
// production helpers that log unconditionally. Idempotent.
func initTestLog() {
	if log != nil {
		return
	}
	logger = logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	log = base.NewSourceLogObject(logger, "baseosmgr_test", 1)
}
