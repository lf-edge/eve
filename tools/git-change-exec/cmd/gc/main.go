// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"git-change-exec/pkg"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/pprof"

	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
)

func main() {
	var outputFile string
	var doPprof bool

	gcStr := fmt.Sprintf("gc-%d", os.Getpid())

	rootCmd := cobra.Command{
		Args: cobra.MinimumNArgs(1),
		Use:  "run <path>",
		Run: func(_ *cobra.Command, args []string) {
			var err error

			if doPprof {
				const pprofURL = "localhost:6060"
				go func() {
					log.Println(http.ListenAndServe(pprofURL, nil))
				}()
				log.Printf("Listening on %s for pprof", pprofURL)

				cpuFh, err := os.Create(gcStr + ".cpu")
				if err != nil {
					panic(err)
				}
				defer cpuFh.Close()

				pprof.StartCPUProfile(cpuFh)
				defer pprof.StopCPUProfile()
			}

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

			if len(gce.ActionsToCheck) == 0 {
				fmt.Printf("no actions to check\n")
				os.Exit(0)
			}

			log.Printf("Collecting info from git ...")
			gce.FetchOrigin()

			gce.CalculateBaseCommit()
			gce.CollectActionsGitTree()
			gce.CollectDirtyGitTree()
			log.Printf("Collecting info from git done")

			log.Printf("Diffing %d files", gce.CountRelPaths())
			gce.Diff()
			log.Printf("Diffing done")

			log.Printf("Dump Action Plan")
			gce.DumpActionToDos(w)

			if outputFile != "" {
				w.Close()
			}

			gce.ChangeBackDir()

			if doPprof {
				fh, err := os.Create(gcStr + ".mem")
				if err != nil {
					panic(err)
				}
				err = pprof.WriteHeapProfile(fh)
				if err != nil {
					panic(err)
				}
				err = fh.Close()
				if err != nil {
					panic(err)
				}

				log.Printf("mem profile written to %s", fh.Name())
			}
		},
	}

	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file")
	rootCmd.PersistentFlags().BoolVar(&doPprof, "pprof", false, "enable pprof")

	err := rootCmd.Execute()
	if err != nil {
		log.Fatalf("cobra failed with: %v", err)
	}
}
