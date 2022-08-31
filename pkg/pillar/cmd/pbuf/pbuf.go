// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pbuf

import (
	"flag"
	"io/ioutil"
	"os"

	zauth "github.com/lf-edge/eve/api/go/auth"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var debug bool
var logger *logrus.Logger
var log *base.LogObject

// Run is our main function called by zedbox
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	debugPtr := flag.Bool("d", false, "Debug flag")
	typePtr := flag.String("t", "AuthContainer", "Type to decode")
	flag.Parse()
	debug = *debugPtr
	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	for _, arg := range flag.Args() {
		log.Noticef("Handling %s type %s", arg, *typePtr)
		buf, err := ioutil.ReadFile(arg)
		if err != nil {
			log.Errorf("Read failed: %s", err)
			continue
		}
		switch *typePtr {
		case "AuthContainer":
			err = decodePrintAuthContainer(buf)
		default:
			log.Errorf("Unknown type to decode: %s", *typePtr)
			os.Exit(1)
		}
		if err != nil {
			log.Errorf("Decode type %s failed: %s", *typePtr, err)
		}
	}
	return 0
}

func decodePrintAuthContainer(buf []byte) error {
	sm := &zauth.AuthContainer{}
	err := proto.Unmarshal(buf, sm)
	if err != nil {
		return err
	}
	log.Noticef("AuthContainer.protectedPayload: %s", sm.ProtectedPayload)
	log.Noticef("AuthContainer.algo: %s", sm.Algo.String())
	log.Noticef("AuthContainer.senderCertHash: %v", sm.SenderCertHash)
	log.Noticef("AuthContainer.signatureHash: %v", sm.SignatureHash)
	return nil
}
