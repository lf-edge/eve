// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"git-change-exec/pkg"
	"io"
	"log"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
)

var dryRun = false
var forceRun = false

func main() {
	runCmd := cobra.Command{
		Args: cobra.ExactArgs(0),
		Use:  "run <path>",
		Run: func(_ *cobra.Command, _ []string) {
			var err error

			bs, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatalf("failed to read from stdin: %+v", err)
			}

			actionToDos := pkg.ActionToDos{}

			err = json.Unmarshal(bs, &actionToDos)
			if err != nil {
				log.Fatalf("failed to unmarshal: %+v", err)
			}

			gce := pkg.NewGitChangeExec()

			gce.G, err = git.PlainOpenWithOptions("./", &git.PlainOpenOptions{DetectDotGit: true})
			if err != nil {
				log.Fatalf("open git path %s failed: %v", gce.GitPath, err)
			}

			args := make([]string, 0)
			for arg := range actionToDos.Actions {
				args = append(args, arg)
			}
			gce.LoadActions(args)
			defer gce.Close()

			gce.GoToGitRootDir()

			log.Printf("Running ...")
			if forceRun {
				gce.ForceRunActionDos()
				return
			}

			gce.FetchOrigin()

			gce.CalculateBaseCommit()
			gce.CollectActionsGitTree()
			gce.CollectDirtyGitTree()

			gce.ActionDos = actionToDos
			if dryRun {
				gce.DryRunActionDos()
				return
			}

			gce.RunActionDos()
		},
	}

	runCmd.PersistentFlags().BoolVarP(&dryRun, "dry-run", "d", false, "")
	runCmd.PersistentFlags().BoolVarP(&forceRun, "force", "f", false, "run all tests without check if necessary")

	err := runCmd.Execute()
	if err != nil {
		log.Fatalf("corba failed with: %v", err)
	}
}
