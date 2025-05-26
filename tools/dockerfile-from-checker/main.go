// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package main is the only package of this tool
package main

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/pkglib"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/spf13/cobra"
)

const (
	defaultPkgCommit = "HEAD"
	defaultPkgTag    = "{{.Hash}}"
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

// gatherDirs returns:
// * an array with directories with Dockerfile
// * another array with build*.yml paths (potentially a linuxkit package)
func gatherDirs(dir string) ([]string, []string) {
	var dockerfileDirs []string
	var buildYmlPaths []string
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

	err = filepath.Walk(dir, func(p string, info fs.FileInfo, _ error) error {
		if info.Name() == "vendor" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}

		absPath, err := filepath.Abs(p)
		if err != nil {
			log.Fatal(err)
		}
		if info.Name() == "Dockerfile" {
			_, ok := ignorePaths[absPath]
			if !ok {
				// path is not on ignore list
				dockerfileDirs = append(dockerfileDirs, absPath)
			}
		}
		if strings.HasPrefix(info.Name(), "build") && filepath.Ext(info.Name()) == ".yml" {
			pkgName := absPath
			_, ok := ignorePaths[absPath]
			if !ok {
				// path is not on ignore list
				buildYmlPaths = append(buildYmlPaths, pkgName)
			}
		}
		return nil
	})

	if err != nil {
		panic(err)
	}

	return dockerfileDirs, buildYmlPaths
}

func rootFunc(cmd *cobra.Command, args []string) {
	dockerfileDirs, buildYmlPaths := gatherDirs(args[0])

	froms2dockerfile := dockerfileFroms(dockerfileDirs)
	linuxkitPkgs := linuxkitPackageTags(buildYmlPaths)
	checkInconsistencies(froms2dockerfile, linuxkitPkgs)
}

func dockerfileFroms(paths []string) map[string][]string {
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

	return froms2dockerfile
}

type linuxkitPkg struct {
	image string
	hash  string
}

func linuxkitPackageTags(buildYmlPaths []string) []linuxkitPkg {
	var tags []linuxkitPkg

	var pkgs []pkglib.Pkg
	for _, ymlPath := range buildYmlPaths {
		ymlBuildFile := filepath.Base(ymlPath)
		pkglibConfig := pkglib.PkglibConfig{
			BuildYML:   ymlBuildFile,
			HashCommit: defaultPkgCommit,
			Dev:        false,
			Tag:        defaultPkgTag,
		}
		pkg, err := pkglib.NewFromConfig(pkglibConfig, filepath.Dir(ymlPath))
		if err != nil {
			// silently ignore that this is not a linuxkit package
			continue
		}

		pkgs = append(pkgs, pkg...)
	}

	for _, p := range pkgs {
		tags = append(tags, linuxkitPkg{
			image: p.Image(),
			hash:  p.Hash(),
		})
	}

	return tags
}

func main() {
	rootCmd.Flags().StringSliceP("ignore-files", "i", []string{}, "ignores specified Dockerfile; can be used several times")

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

type tagFile struct {
	tag      string
	file     string
	fullname string
	image    string
}

func checkDockerFroms(tfs []tagFile) {
	image2TagFile := make(map[string][]tagFile)
	for _, tf := range tfs {
		image2TagFile[tf.image] = append(image2TagFile[tf.image], tf)

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

func pkgHashValid(hash string) bool {
	if hash == "" {
		return false
	}

	dst := make([]byte, len(hash)/2+1)
	_, err := hex.Decode(dst, []byte(hash))

	return err == nil
}

func checkLinuxkitPkgs(tfs []tagFile, lktPkgs []linuxkitPkg) {
	lktImageMap := make(map[string]string)
	for _, pkg := range lktPkgs {
		lktImageMap[pkg.image] = pkg.hash
	}

	for _, tf := range tfs {
		if !pkgHashValid(tf.tag) {
			continue
		}
		if !pkgHashValid(lktImageMap[tf.image]) {
			continue
		}
		if lktImageMap[tf.image] != tf.tag {
			fmt.Printf("%s uses %s but %s is built in this repo\n", tf.file, tf.fullname, lktImageMap[tf.image])
			os.Exit(1)
		}
	}
}

func checkInconsistencies(froms2dockerfile map[string][]string, lktlinuxkitPkgs []linuxkitPkg) {
	var tfs []tagFile

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
				image:    image,
			}

			tfs = append(tfs, tf)
		}
	}

	checkLinuxkitPkgs(tfs, lktlinuxkitPkgs)
	checkDockerFroms(tfs)
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
	_, metaArgs, err := instructions.Parse(result.AST, nil)
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
