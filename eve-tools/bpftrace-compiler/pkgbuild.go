// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// heavily inspired by github.com/linuxkit/linuxkit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/moby"
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/pkglib"
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/spec"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	mobybuild "github.com/linuxkit/linuxkit/src/cmd/linuxkit/moby/build"
	log "github.com/sirupsen/logrus"
)

const (
	defaultBuilderImage = "moby/buildkit:v0.12.3"
)

type userspaceContainer interface {
	String() string
}

type onbootContainer string
type serviceContainer string

func (o onbootContainer) String() string {
	return string(o)
}

func (s serviceContainer) String() string {
	return string(s)
}

func createImage(arch string, lc lkConf, uc userspaceContainer, outputDir string) {
	var err error

	ib := newImageBuilder(arch, lc, outputDir)
	ib.userspace = uc
	err = ib.buildPkgs([]string{"root"})
	if err != nil {
		log.Fatalf("building pkgs 'root' failed: %v", err)
	}
	err = ib.buildImg()
	if err != nil {
		log.Fatalf("building image failed: %v", err)
	}

	ib.cleanup()
}

type imageBuilder struct {
	cacheDir  string
	logWriter io.Writer
	arch      string
	lkConf    lkConf
	outputDir string
	userspace userspaceContainer
	hash      string
}

func defaultLinuxkitCache() string {
	lktDir := ".linuxkit"
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not determine home directory: %v", err)
	}
	return filepath.Join(homedir, lktDir, "cache")
}

func newImageBuilder(arch string, lkConf lkConf, outputDir string) *imageBuilder {
	ib := &imageBuilder{
		cacheDir:  defaultLinuxkitCache(),
		logWriter: io.Discard,
		arch:      arch,
		lkConf:    lkConf,
		outputDir: outputDir,
	}

	return ib
}

func (ib *imageBuilder) cleanup() {
}

func (ib *imageBuilder) buildPkgs(args []string) error {
	ib.hash = hashDir(args, ib.lkConf.kernel)
	pkglibConfig := pkglib.PkglibConfig{
		BuildYML:   "build.yml",
		HashCommit: defaultPkgCommit,
		Hash:       ib.hash,
		Dev:        false,
		Tag:        defaultPkgTag,
	}
	var opts []pkglib.BuildOpt

	pkgs, err := pkglib.NewFromConfig(pkglibConfig, args...)
	if err != nil {
		return errors.Wrapf(err, "NewFromConfig")
	}

	opts = append(opts, pkglib.WithBuildCacheDir(ib.cacheDir))
	opts = append(opts, pkglib.WithBuildTargetDockerCache())
	opts = append(opts, pkglib.WithBuildManifest())
	opts = append(opts, pkglib.WithBuildOutputWriter(ib.logWriter))

	opts = append(opts, pkglib.WithBuildArgs([]string{
		fmt.Sprintf("EVE_KERNEL=%s", ib.lkConf.kernel),
	}))

	// if requested specific platforms, build those. If not, then we will
	// retrieve the defaults in the loop over each package.
	plats := []imagespec.Platform{
		imagespec.Platform{OS: "linux", Architecture: ib.arch},
	}

	opts = append(opts, pkglib.WithBuildBuilderImage(defaultBuilderImage))
	opts = append(opts, pkglib.WithBuildBuilderRestart(false))
	opts = append(opts, pkglib.WithProgress("auto"))
	opts = append(opts, pkglib.WithBuildSbomScanner("")) // but why?

	for _, p := range pkgs {
		// things we need our own copies of
		var (
			pkgOpts  = make([]pkglib.BuildOpt, len(opts))
			pkgPlats = make([]imagespec.Platform, len(plats))
		)
		copy(pkgOpts, opts)
		copy(pkgPlats, plats)
		// unless overridden, platforms are specific to a package, so this needs to be inside the for loop

		// if there are no platforms to build for, do nothing.
		// note that this is *not* an error; we simply skip it
		if len(pkgPlats) == 0 {
			fmt.Printf("Skipping %s with no architectures to build\n", p.Tag())
			continue
		}

		pkgOpts = append(pkgOpts, pkglib.WithBuildPlatforms(pkgPlats...))

		if err := p.Build(pkgOpts...); err != nil {
			if strings.HasPrefix(err.Error(), "no valid descriptor returned for image for arch ") {
				continue
			}
			return fmt.Errorf("error building %q: %w", p.Tag(), err)
		}
	}
	return nil
}

func (ib *imageBuilder) buildImg() error {
	var err error

	m, err := ib.createMobyConfig()
	if err != nil {
		return err
	}

	name := filepath.Join(ib.outputDir, "linuxkit")
	var tf *os.File
	if tf, err = os.CreateTemp("/var/tmp", "bpftrace-tarfile"); err != nil {
		log.Fatalf("error creating tempfile: %v", err)
	}
	defer os.Remove(tf.Name())

	tp := "kernel+squashfs"
	if mobybuild.Streamable(tp) {
		log.Fatal("output cannot be streamed")
	}
	mobyBuildOpts := mobybuild.BuildOpts{
		Pull:             false,
		BuilderType:      tp,
		DecompressKernel: false,
		CacheDir:         ib.cacheDir,
		DockerCache:      true,
		Arch:             ib.arch,
	}
	err = mobybuild.Build(m, tf, mobyBuildOpts)
	if err != nil {
		return fmt.Errorf("mobybuild.Build: %v", err)
	}
	image := tf.Name()
	if err := tf.Close(); err != nil {
		return fmt.Errorf("error closing tempfile: %v", err)
	}

	log.Infof("Create outputs:")
	err = mobybuild.Formats(name, image, []string{tp}, -1, ib.arch, ib.cacheDir)
	if err != nil {
		return fmt.Errorf("error writing outputs: %v", err)
	}
	return nil
}

func (ib *imageBuilder) createMobyConfig() (moby.Moby, error) {
	var onboot string
	var service string
	var m moby.Moby
	var pkgFinder spec.PackageResolver

	config := []byte(`{
  "kernel": {
    "image": "EVE_KERNEL",
  },
  "init": [
    "@pkg:./root"
  ],
  "services": [
    {
    "name": "SERVICE_TEMPLATE",
    "image": "SERVICE_IMAGE"
    },
  ],
  "onboot": [
    {
    "name": "ONBOOT_TEMPLATE",
    "image": "ONBOOT_IMAGE"
    },
  ]
}`)

	switch ib.userspace.(type) {
	case onbootContainer:
		onboot = ib.userspace.String()
	case serviceContainer:
		service = ib.userspace.String()
	case nil:
		break
	default:
		log.Fatalf("unknown type %T", ib.userspace)
	}

	if service != "" && onboot != "" {
		return moby.Moby{}, fmt.Errorf("cannot have onboot and service container at the same time")
	}
	serviceImage := ib.lkConf.services[service]
	onbootImage := ib.lkConf.onboot[onboot]
	pkgFinder = createPackageResolver(map[string]string{
		"EVE_KERNEL":    ib.lkConf.kernel,
		"SERVICE_IMAGE": serviceImage,
		"ONBOOT_IMAGE":  onbootImage,
		"@pkg:./root":   "linuxkit/root:" + ib.hash,
	})
	c, err := moby.NewConfig(config, pkgFinder)
	if err != nil {
		return moby.Moby{}, fmt.Errorf("invalid config: %v", err)
	}
	m, err = moby.AppendConfig(m, c)
	if err != nil {
		return moby.Moby{}, fmt.Errorf("cannot append config files: %v", err)
	}

	for i := range m.Services {
		if m.Services[i].Name == "SERVICE_TEMPLATE" {
			if service == "" {
				m.Services = append(m.Services[:i], m.Services[i+1:]...)
			} else {
				m.Services[i].Name = service
			}

		}
	}
	for i := range m.Onboot {
		if m.Onboot[i].Name == "ONBOOT_TEMPLATE" {
			if onboot == "" {
				m.Onboot = append(m.Onboot[:i], m.Onboot[i+1:]...)
			} else {
				m.Onboot[i].Name = onboot
			}

		}
	}

	return m, nil
}
