// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pbuf

import (
	"flag"
	"io/ioutil"
	"os"

	zauth "github.com/lf-edge/eve/api/go/auth"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const agentName = "pbuf"

type pbufAgentState struct {
	agentbase.AgentBase
	// cli options
	typePtr *string
	args    []string
}

// AddAgentSpecificCLIFlags adds CLI options
func (state *pbufAgentState) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	state.typePtr = flagSet.String("t", "AuthContainer", "Type to decode")
}

var logger *logrus.Logger
var log *base.LogObject

// Run is our main function called by zedbox
func Run(_ *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	state := pbufAgentState{}
	agentbase.Init(&state, logger, log, agentName,
		agentbase.WithArguments(arguments))

	for _, arg := range state.args {
		log.Noticef("Handling %s type %s", arg, *state.typePtr)
		buf, err := ioutil.ReadFile(arg)
		if err != nil {
			log.Errorf("Read failed: %s", err)
			continue
		}
		switch *state.typePtr {
		case "AuthContainer":
			err = decodePrintAuthContainer(buf)
		default:
			log.Errorf("Unknown type to decode: %s", *state.typePtr)
			os.Exit(1)
		}
		if err != nil {
			log.Errorf("Decode type %s failed: %s", *state.typePtr, err)
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
