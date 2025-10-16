// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"git-change-exec/pkg"
	"io"
	"log"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
)

func main() {
	var outputFile string

	rootCmd := cobra.Command{
		Args: cobra.MinimumNArgs(1),
		Use:  "run <path>",
		Run: func(_ *cobra.Command, args []string) {
			var err error

			gce := pkg.NewGitChangeExec()

			gce.G, err = git.PlainOpenWithOptions("./", &git.PlainOpenOptions{DetectDotGit: true})
			if err != nil {
				log.Fatalf("open git path %s failed: %v", gce.GitPath, err)
			}

			gce.LoadActions(args)
			defer gce.Close()

			var w io.WriteCloser = os.Stdout
			if outputFile != "" {
				w, err = os.Create(outputFile)
				if err != nil {
					log.Fatalf("could not open '%s' for writing: %v", outputFile, err)
				}
			}

			gce.GoToGitRootDir()
			defer gce.ChangeBackDir()

			if len(gce.ActionsToCheck) == 0 {
				fmt.Printf("no actions to check\n")
				os.Exit(0)
			}

			gce.FetchOrigin()

			gce.CalculateBaseCommit()
			gce.CollectActionsGitTree()
			gce.CollectDirtyGitTree()

			gce.Diff()

			gce.DumpActionToDos(w)

			if outputFile != "" {
				w.Close()
			}
		},
	}

	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file")

	err := rootCmd.Execute()
	if err != nil {
		log.Fatalf("corba failed with: %v", err)
	}

}
