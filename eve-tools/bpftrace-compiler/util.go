// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

type lkConf struct {
	kernel   string
	onboot   map[string]string // name -> image
	services map[string]string // name -> image
}

func (l lkConf) String() string {
	return fmt.Sprintf("kernel: %s onboot: %+q services: %+q", l.kernel, l.onboot, l.services)
}

type lkConfYaml struct {
	Kernel struct {
		Image string `yaml:"image"`
	} `yaml:"kernel"`
	Onboot []struct {
		Name  string `yaml:"name"`
		Image string `yaml:"image"`
	} `yaml:"onboot"`
	Services []struct {
		Name  string `yaml:"name"`
		Image string `yaml:"image"`
	} `yaml:"services"`
}

func linuxkitYml2KernelConf(ymlBytes []byte) lkConf {
	var y lkConfYaml
	err := yaml.Unmarshal(ymlBytes, &y)
	if err != nil {
		log.Fatalf("unmarshalling from yaml failed: %v", err)
	}

	l := lkConf{
		kernel:   "",
		onboot:   map[string]string{},
		services: map[string]string{},
	}
	l.kernel = y.Kernel.Image

	l.onboot = make(map[string]string)
	for _, container := range y.Onboot {
		l.onboot[container.Name] = container.Image
	}
	for _, container := range y.Services {
		l.services[container.Name] = container.Image
	}

	return l
}

func cleanArch(arch string) string {
	if arch == "x86_64" {
		arch = "amd64"
	}
	if arch == "aarch64" {
		arch = "arm64"
	}

	return arch
}

func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)

	return err
}

func hashDir(dirs []string, extraHashes ...string) string {
	hasher := md5.New()

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("could not walk %s: %v", path, err)
			}

			hasher.Write([]byte(path))

			if d.IsDir() {
				return nil
			}

			fh, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("could not open %s: %v", path, err)
			}
			defer fh.Close()

			_, err = io.Copy(hasher, fh)
			if err != nil {
				return fmt.Errorf("could not copy %s: %v", path, err)
			}

			return nil
		})

		if err != nil {
			log.Printf("could not hash %s: %v -- using current unix time stamp instead", dir, err)
			return fmt.Sprintf("%d", time.Now().Unix())
		}
	}

	for _, hash := range extraHashes {
		hasher.Write([]byte(hash))
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func waitForKeyFromStdin(timeout time.Duration) bool {
	reader := bufio.NewReader(os.Stdin)

	readChan := make(chan struct{})
	go func() {
		buf := []byte{' '}
		_, err := reader.Read(buf)
		if err == nil {
			readChan <- struct{}{}
		}
	}()

	select {
	case <-readChan:
		return true
	case <-time.After(timeout):
		return false
	}
}

func newQemuRunner(arch string, imageDir string, bpfFile, outputFile string) *qemuRunner {
	var qr *qemuRunner
	switch arch {
	case "arm64":
		qr = newQemuArm64Runner(imageDir, bpfFile, outputFile)
	case "amd64":
		qr = newQemuAmd64Runner(imageDir, bpfFile, outputFile)
	default:
		log.Fatalf("unknown architecture %s", arch)
	}
	return qr
}
