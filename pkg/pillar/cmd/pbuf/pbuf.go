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

const agentName = "pbuf"

var debug bool
var logger *logrus.Logger
var log *base.LogObject

// Run is our main function called by zedbox
func Run(_ *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg
	flagSet := flag.NewFlagSet(agentName, flag.ExitOnError)
	debugPtr := flagSet.Bool("d", false, "Debug flag")
	typePtr := flagSet.String("t", "AuthContainer", "Type to decode")
	if err := flagSet.Parse(arguments); err != nil {
		log.Fatal(err)
	}
	debug = *debugPtr
	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	for _, arg := range flagSet.Args() {
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
