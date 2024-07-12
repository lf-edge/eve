// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	if err := execute(); err != nil {
		log.Fatal(err)
	}
}

func rootCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "verifier",
		Short: "Verify the digests of files and move to verified directory",
	}
	return cmd
}

func execute() error {
	r := rootCmd()
	r.AddCommand(oneShotCmd())
	r.AddCommand(pubsubCmd())
	return r.Execute()
}
