// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package main is the only package of this tool
package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{}

func init() {
	rootCmd = &cobra.Command{
		Use:  "dockerfile-checker <dir>",
		Long: "dockerfile-checker scans recursively for Dockerfiles and checks if they have images with different tags",
		Args: cobra.ExactArgs(1),
		Run:  rootFunc,
	}
}

func rootFunc(cmd *cobra.Command, args []string) {
	var paths []string
	ignorePaths := make(map[string]struct{})

	ignoreRelPaths, err := rootCmd.Flags().GetStringSlice("ignore-files")
	if err != nil {
		log.Fatal(err)
	}
	for _, ign := range ignoreRelPaths {
		absPath, err := filepath.Abs(ign)
		if err != nil {
			log.Fatal(err)
		}

		ignorePaths[absPath] = struct{}{}
	}

	err = filepath.Walk(args[0], func(p string, info fs.FileInfo, err error) error {
		if info.Name() == "vendor" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}

		if info.Name() == "Dockerfile" {
			absPath, err := filepath.Abs(p)
			if err != nil {
				log.Fatal(err)
			}
			_, ok := ignorePaths[absPath]
			if !ok {
				// path is not on ignore list
				paths = append(paths, absPath)
			}
		}
		return nil
	})

	if err != nil {
		panic(err)
	}

	checkDockerfiles(paths)
}

func checkDockerfiles(paths []string) {
	var f *os.File
	var err error

	froms2dockerfile := make(map[string][]string)
	for _, filename := range paths {
		f, err = os.Open(filename)
		if err != nil {
			log.Fatalf("could not open %s: %+v", filename, err)
		}
		defer f.Close()

		dockerfileFroms := parseDockerfile(f)
		for _, from := range dockerfileFroms {
			fns := append(froms2dockerfile[from], filename)
			froms2dockerfile[from] = fns
		}
	}

	checkInconsistencies(froms2dockerfile)
}

func main() {
	rootCmd.Flags().StringSliceP("ignore-files", "i", []string{}, "ignores specified Dockerfile; can be used several times")

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func checkInconsistencies(froms2dockerfile map[string][]string) {
	type tagFile struct {
		tag      string
		file     string
		fullname string
	}

	image2TagFile := make(map[string][]tagFile)
	for from, files := range froms2dockerfile {
		for _, file := range files {
			splits := strings.Split(from, ":")
			if len(splits) < 1 {
				continue
			}
			tag := splits[len(splits)-1]
			image := strings.Join(splits[:len(splits)-1], "")
			if image == "" {
				continue
			}
			tf := tagFile{
				tag:      tag,
				file:     file,
				fullname: from,
			}
			image2TagFile[image] = append(image2TagFile[image], tf)
		}
	}

	for _, tfs := range image2TagFile {
		for i := 1; i < len(tfs); i++ {
			tf := tfs[i]
			if tf.tag != tfs[i-1].tag {
				fmt.Printf("tags differ for image %s in files %s and %s\n", tf.fullname, tf.file, tfs[i-1].file)
				os.Exit(1)
			}
		}
	}
}

func parseDockerfile(f *os.File) []string {
	var dockerfileFroms []string
	result, err := parser.Parse(f)
	if err != nil {
		log.Fatalf("parsing %s failed: %+v", f.Name(), err)
	}

	vars := parseVars(result)
	var next *parser.Node
	for _, node := range result.AST.Children {
		if node.Value == "FROM" {
			next = node.Next
			if next == nil {
				break
			}
			from := expandVariables(next, vars)
			dockerfileFroms = append(dockerfileFroms, from)
		}
	}

	return dockerfileFroms
}

func expandVariables(next *parser.Node, vars map[string]string) string {
	from := next.Value
	for key, val := range vars {
		from = strings.ReplaceAll(from, fmt.Sprintf("${%s}", key), val)
	}
	return from
}

func parseVars(result *parser.Result) map[string]string {
	vars := make(map[string]string)
	_, metaArgs, err := instructions.Parse(result.AST)
	if err != nil {
		log.Fatal(err)
	}

	for _, argCmd := range metaArgs {
		if argCmd.Name() != "ARG" {
			continue
		}
		for _, argCmdArg := range argCmd.Args {
			vars[argCmdArg.Key] = argCmdArg.ValueString()
		}
	}

	return vars
}
