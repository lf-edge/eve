// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/verifier"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/spf13/cobra"
)

func pubsubCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "pubsub",
		Short: "Listen for pubsub events and verify digests",
		Long: `Listen for pubsub events and verify digests. Listens on pubsub as if called from pillar.
		Can customize where the pubsub directory is located with the --base-path flag`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger, log := agentlog.Init("verifier")
			basePath := cmd.Flag("pubsub-base-path").Value.String()

			ps := pubsub.New(
				&socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: basePath},
				logger, log)
			_ = verifier.Run(ps, logger, log, nil, basePath)
			return nil
		},
	}
	flags := cmd.Flags()
	flags.String("pubsub-base-path", "", "base-path for pubsub; all pubsub files, directories, sockets and pidfiles are relative to this path")
	return cmd
}
