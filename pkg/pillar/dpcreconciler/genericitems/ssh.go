// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"fmt"
	"os"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	runDir           = "/run"
	authKeysFilename = runDir + "/authorized_keys"
)

// SSHAuthKeys : a singleton item representing file "authorized_keys" used by SSH.
type SSHAuthKeys struct {
	Keys string
}

// Name returns the full path of the authorized_keys file.
func (s SSHAuthKeys) Name() string {
	return authKeysFilename
}

// Label is not defined.
func (s SSHAuthKeys) Label() string {
	return ""
}

// Type of the item.
func (s SSHAuthKeys) Type() string {
	return SSHAuthKeysTypename
}

// Equal compares keys.
func (s SSHAuthKeys) Equal(other depgraph.Item) bool {
	s2, isSSHAuthKeys := other.(SSHAuthKeys)
	if !isSSHAuthKeys {
		return false
	}
	return s.Keys == s2.Keys
}

// External returns false.
func (s SSHAuthKeys) External() bool {
	return false
}

// String describes the authorized_keys file content.
func (s SSHAuthKeys) String() string {
	return fmt.Sprintf("%s with keys: %s", authKeysFilename, s.Keys)
}

// Dependencies returns nothing.
func (s SSHAuthKeys) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// SSHAuthKeysConfigurator implements Configurator interface (libs/reconciler) for authorized_keys.
type SSHAuthKeysConfigurator struct {
	Log *base.LogObject
}

// Create writes authorized_keys file.
func (c *SSHAuthKeysConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	return c.writeSSHAuthKeys(item)
}

// Modify writes updated authorized_keys file.
func (c *SSHAuthKeysConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return c.writeSSHAuthKeys(newItem)
}

// Delete writes authorized_keys with empty content.
func (c *SSHAuthKeysConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	return c.writeSSHAuthKeys(nil)
}

func (c *SSHAuthKeysConfigurator) writeSSHAuthKeys(item depgraph.Item) error {
	var keys string
	if item != nil {
		sshAuthKeys, isSSHAuthKeys := item.(SSHAuthKeys)
		if !isSSHAuthKeys {
			err := fmt.Errorf("invalid item type: %T (expected SSHAuthKeys)", item)
			c.Log.Error(err)
			return err
		}
		keys = sshAuthKeys.Keys
	}
	c.Log.Functionf("writeSSHAuthKeys: %s", keys)
	tmpfile, err := os.CreateTemp(runDir, "ak")
	if err != nil {
		err = fmt.Errorf("os.CreateTemp(%s) failed: %w", runDir, err)
		c.Log.Error(err)
		return err
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	err = tmpfile.Chmod(0600)
	if err != nil {
		err = fmt.Errorf("failed to chmod(0600) file %s: %w", tmpfile.Name(), err)
		c.Log.Error(err)
		return err
	}
	if keys != "" {
		if _, err = tmpfile.WriteString(keys); err != nil {
			err = fmt.Errorf("failed to write into %s: %w", tmpfile.Name(), err)
			c.Log.Error(err)
			return err
		}
	}
	if err = tmpfile.Sync(); err != nil {
		err = fmt.Errorf("failed to sync %s: %w", tmpfile.Name(), err)
		c.Log.Error(err)
		return err
	}
	if err = tmpfile.Close(); err != nil {
		err = fmt.Errorf("failed to close %s: %w", tmpfile.Name(), err)
		c.Log.Error(err)
		return err
	}
	if err = os.Rename(tmpfile.Name(), authKeysFilename); err != nil {
		err = fmt.Errorf("failed to rename %s to %s: %w",
			tmpfile.Name(), authKeysFilename, err)
		c.Log.Error(err)
		return err
	}
	c.Log.Functionf("writeSSHAuthKeys done")
	return nil
}

// NeedsRecreate returns false - Modify is able to handle any change.
func (c *SSHAuthKeysConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}
