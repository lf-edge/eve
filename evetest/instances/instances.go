// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package instances implements a small on-disk registry of running evetest
// instances (containers), so that the evetest CLI can find an instance without
// the user having to know its automatically assigned API port.
//
// Every evetest container registers itself on start-up by writing
// <home>/instances/<api-port>.json and removes the file on a clean exit. The
// directory lives under the evetest home directory, which is bind-mounted at
// the same path into the container. A container that crashed leaves a stale
// file behind; readers detect that by checking whether the instance still
// answers on its port.
package instances

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
)

// Instance describes one running evetest instance.
type Instance struct {
	// Name of the test or test suite the instance was started for.
	Name string `json:"name"`
	// Port is the gRPC API port, published on the host under the same number.
	Port int `json:"port"`
	// Container is the Docker container name; empty if not run by the Makefile.
	Container string `json:"container,omitempty"`
	// ArtifactDir is the (in-container) artifact directory of this execution.
	ArtifactDir string    `json:"artifactDir,omitempty"`
	StartedAt   time.Time `json:"startedAt"`
}

// Home returns the evetest data directory: EVETEST_HOME if set (the Makefile
// passes it into the container), otherwise $HOME/.evetest.
func Home() string {
	if home := os.Getenv(constants.EnvPrefix + constants.HomeDirEnv); home != "" {
		return home
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".evetest")
	}
	return filepath.Join(userHome, ".evetest")
}

// Dir returns the directory holding the instance registry.
func Dir() string {
	return filepath.Join(Home(), "instances")
}

func path(port int) string {
	return filepath.Join(Dir(), strconv.Itoa(port)+".json")
}

// Register records the instance in the registry and returns a function which
// removes the record again.
func Register(inst Instance) (unregister func(), err error) {
	if inst.StartedAt.IsZero() {
		inst.StartedAt = time.Now()
	}
	data, err := json.Marshal(inst)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(Dir(), 0o755); err != nil {
		return nil, err
	}
	// Write atomically so that a concurrent reader never sees a partial file.
	tmp, err := os.CreateTemp(Dir(), ".tmp-")
	if err != nil {
		return nil, err
	}
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path(inst.Port))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return func() { Remove(inst.Port) }, nil
}

// Remove deletes the registry record of the instance listening on the port.
func Remove(port int) {
	_ = os.Remove(path(port))
}

// List returns all registered instances, oldest first. Records may be stale;
// the caller is responsible for checking that an instance is alive.
func List() ([]Instance, error) {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var list []Instance
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(Dir(), e.Name()))
		if err != nil {
			continue
		}
		var inst Instance
		if json.Unmarshal(data, &inst) != nil || inst.Port == 0 {
			continue
		}
		list = append(list, inst)
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].StartedAt.Equal(list[j].StartedAt) {
			return list[i].StartedAt.Before(list[j].StartedAt)
		}
		return list[i].Port < list[j].Port
	})
	return list, nil
}

// Match selects one instance out of the list by a user-supplied selector:
// a 1-based index, an API port, an exact name or container name, or else a
// unique name prefix or substring.
func Match(list []Instance, selector string) (Instance, error) {
	if selector == "" {
		return Instance{}, errors.New("empty instance selector")
	}
	if n, err := strconv.Atoi(selector); err == nil {
		for _, inst := range list {
			if inst.Port == n {
				return inst, nil
			}
		}
		if n >= 1 && n <= len(list) {
			return list[n-1], nil
		}
	}
	var exact, prefix, substr []Instance
	for _, inst := range list {
		switch {
		case inst.Name == selector || (inst.Container != "" && inst.Container == selector):
			exact = append(exact, inst)
		case strings.HasPrefix(inst.Name, selector):
			prefix = append(prefix, inst)
		case strings.Contains(inst.Name, selector):
			substr = append(substr, inst)
		}
	}
	for _, group := range [][]Instance{exact, prefix, substr} {
		switch len(group) {
		case 0:
			continue
		case 1:
			return group[0], nil
		default:
			return Instance{}, fmt.Errorf("instance selector %q is ambiguous: matches %s",
				selector, describe(group))
		}
	}
	return Instance{}, fmt.Errorf("no running evetest instance matches %q", selector)
}

func describe(list []Instance) string {
	var parts []string
	for _, inst := range list {
		parts = append(parts, fmt.Sprintf("%s (port %d)", inst.Name, inst.Port))
	}
	return strings.Join(parts, ", ")
}
