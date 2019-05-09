// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmmgr

import (
	"flag"
	"github.com/google/go-tpm/tpm2"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/eve/pkg/pillar/agentlog"
)

const (
	TpmDevicePath = "/dev/tpm0"
)

func testOpen() error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()
	return nil
}

func Run() {
	curpartPtr := flag.String("c", "", "Current partition")
	curpart := *curpartPtr

	log.SetLevel(log.DebugLevel)

	// Sending json log format to stdout
	logf, err := agentlog.Init("tpmmgr", curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	err = testOpen()
	if err != nil {
		log.Errorln("TPM access test failed.")
	}
}
