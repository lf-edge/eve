// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	logger = logrus.StandardLogger()
	logger.SetLevel(logrus.PanicLevel)
	log = base.NewSourceLogObject(logger, "client_test", 0)
	os.Exit(m.Run())
}
