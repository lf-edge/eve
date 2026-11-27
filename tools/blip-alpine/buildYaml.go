// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type BuildYAML struct {
	Image string `yaml:"image"`
	Org   string `yaml:"org"`
}

func parseBuildYaml(path string) *BuildYAML {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var by BuildYAML

	yaml.Unmarshal(bs, &by)

	return &by
}
