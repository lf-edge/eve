// Copyright(c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/pkglib"
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/spec"
	buildkitClient "github.com/moby/buildkit/client"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	defaultPkgBuildYML  = "build.yml"
	defaultPkgCommit    = "HEAD"
	defaultBuilderImage = "moby/buildkit:v0.12.3"
)

// heavily inspired by src/cmd/linuxkit/pkglib/dockerdryrun.go
type buildArgsDockerRunner struct {
	buildArgs map[string]string
}

func (dr *buildArgsDockerRunner) Builder(
	ctx context.Context,
	dockerContext, builderImage, builderConfigPath, platform string,
	restart bool,
) (*buildkitClient.Client, error) {
	return nil, nil
}

func (dr *buildArgsDockerRunner) Pull(img string) (bool, error) {
	return false, errors.New("not implemented")
}

func (dr *buildArgsDockerRunner) Tag(ref, tag string) error {
	return errors.New("not implemented")
}

func (dr *buildArgsDockerRunner) Build(
	ctx context.Context,
	tag, pkg, dockerContext, builderImage, builderConfigPath, platform string,
	restart, preCacheImages bool,
	c spec.CacheProvider,
	r io.Reader,
	stdout io.Writer,
	sbomScan bool,
	sbomScannerImage, platformType string,
	imageBuildOpts spec.ImageBuildOptions,
) error {
	for k, v := range imageBuildOpts.BuildArgs {
		dr.buildArgs[k] = *v
	}

	return nil
}

func (dr *buildArgsDockerRunner) Save(tgt string, refs ...string) error {
	return errors.New("not implemented")
}

func (dr *buildArgsDockerRunner) Load(src io.Reader) error {
	return errors.New("not implemented")
}

func (dr *buildArgsDockerRunner) ContextSupportCheck() error {
	return nil
}

func lktBuildArgs(ymlPath string) map[string]string {

	ymlBuildFile := filepath.Base(ymlPath)

	pkglibConfig := pkglib.PkglibConfig{
		BuildYML:   ymlBuildFile,
		HashCommit: defaultPkgCommit,
		Dev:        false,
		// Tag intentionally omitted: use the tag template from build.yml.
	}
	pkgs, err := pkglib.NewFromConfig(pkglibConfig, filepath.Dir(ymlPath))
	if err != nil {
		panic(err)
		// silently ignore that this is not a linuxkit package
	}

	var opts []pkglib.BuildOpt

	badr := &buildArgsDockerRunner{
		buildArgs: map[string]string{},
	}

	opts = append(opts, pkglib.WithBuildDocker(badr))
	opts = append(opts, pkglib.WithDryRun())
	tmpDir, err := os.MkdirTemp("", "get-deps")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	opts = append(opts, pkglib.WithBuildCacheDir(tmpDir))
	opts = append(opts, pkglib.WithBuildSbomScanner("")) // but why?
	opts = append(opts, pkglib.WithBuildBuilderImage(defaultBuilderImage))
	opts = append(opts, pkglib.WithBuildBuilderRestart(false))
	opts = append(opts, pkglib.WithProgress("auto"))
	opts = append(opts, pkglib.WithBuildForce())

	for _, pkg := range pkgs {
		plats := []imagespec.Platform{{OS: TARGETOS, Architecture: TARGETARCH}}

		var (
			pkgPlats = make([]imagespec.Platform, len(plats))
		)
		copy(pkgPlats, plats)
		// unless overridden, platforms are specific to a package, so this needs to be inside the for loop

		// if there are no platforms to build for, do nothing.
		// note that this is *not* an error; we simply skip it
		if len(pkgPlats) == 0 {
			// fmt.Printf("Skipping %s with no architectures to build\n", p.Tag())
			continue
		}

		opts = append(opts, pkglib.WithBuildPlatforms(pkgPlats...))

		err := pkg.ProcessBuildArgs()
		if err != nil {
			panic(err)
		}

		err = pkg.Build(opts...)
		if err != nil {
			panic(err)
		}
	}

	return badr.buildArgs
}

// getPkgTag returns the linuxkit content tag for a package directory.
// pkgDir is a path like "pkg/zfs"; buildYml is the build yml filename
// (e.g. "build.yml" or "build-2.3.yml").
// The env-var convention EVE_PKG_BUILD_YML_<PKGNAME> (uppercase,
// hyphens→underscores) overrides buildYml when set.
func getPkgTag(pkgDir, buildYml string) (string, error) {
	// Allow Makefile to override the build yml via env var.
	pkgName := filepath.Base(pkgDir)
	envKey := "EVE_PKG_BUILD_YML_" + strings.ToUpper(strings.ReplaceAll(pkgName, "-", "_"))
	if override := os.Getenv(envKey); override != "" {
		buildYml = override
	}

	pkglibConfig := pkglib.PkglibConfig{
		BuildYML:   buildYml,
		HashCommit: defaultPkgCommit,
		Dev:        false,
		// Tag intentionally omitted: use the tag template from build.yml
		// (e.g. "{{.Hash}}-2.3" for ZFS). Setting Tag here would override it.
	}
	pkgs, err := pkglib.NewFromConfig(pkglibConfig, pkgDir)
	if err != nil {
		return "", fmt.Errorf("pkglib.NewFromConfig for %s: %v", pkgDir, err)
	}
	if len(pkgs) == 0 {
		return "", fmt.Errorf("no packages found in %s", pkgDir)
	}
	return pkgs[0].Tag(), nil
}
