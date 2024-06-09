// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	verifierpubsub "github.com/lf-edge/eve/pkg/pillar/cmd/verifier/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

func Run(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject, arguments []string, baseDir string) int {
	ctx := verifierpubsub.NewVerifierContext(ps, logger, log)
	return ctx.Run(arguments, baseDir)
}
