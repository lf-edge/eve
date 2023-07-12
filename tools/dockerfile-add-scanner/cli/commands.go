// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

// New get a new root cli command
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dockerfile-add-scanner",
		Short: "Scans Dockerfiles for ADD commands",
		Long: `Scan Dockerfiles for ADD commands and print the URLs to stdout.
		Can scan multiple at once. Output can be in list, spdx or spdx-json formats.
`,
	}
	cmd.AddCommand(scanCmd())
	return cmd
}
