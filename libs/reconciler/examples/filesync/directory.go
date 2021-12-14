// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lf-edge/eve/libs/depgraph"
)

// directory represents a file-system directory.
type directory struct {
	dirname     string
	parent      *directory
	permissions os.FileMode
}

// Name returns the full directory path.
func (d directory) Name() string {
	var name string
	if d.parent != nil {
		name = d.parent.Name() + "/"
	}
	name += d.dirname
	return name
}

// Label is used only for graph visualization and it does not have to be a unique
// item identifier.
func (d directory) Label() string {
	return d.dirname
}

func (d directory) Type() string {
	return "directory"
}

func (d directory) Equal(item2 depgraph.Item) bool {
	d2 := item2.(directory)
	return d.permissions == d2.permissions
}

// External returns true for the root of our "filesystem"
// (which is created with MkdirTemp outside of the Reconciler).
func (d directory) External() bool {
	return d.parent == nil
}

func (d directory) String() string {
	return fmt.Sprintf("path: %s\npermissions: %o",
		d.Name(), d.permissions)
}

// Dependencies returns the parent directory as the only dependency.
func (d directory) Dependencies() []depgraph.Dependency {
	if d.parent == nil {
		return []depgraph.Dependency{}
	}
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: directory{}.Type(),
				ItemName: d.parent.Name(),
			},
			Description: "For directory to be created, the parent directory must already exist",
		},
	}
}

// dirConfigurator is the Configurator for directories.
type dirConfigurator struct{}

// Create creates a new directory.
func (dc dirConfigurator) Create(_ context.Context, item depgraph.Item) error {
	d := item.(directory)
	return os.Mkdir(d.Name(), d.permissions)
}

// Modify can change the access rights of a directory.
func (dc dirConfigurator) Modify(_ context.Context, oldItem, newItem depgraph.Item) (err error) {
	oldD := oldItem.(directory)
	newD := newItem.(directory)
	if oldD.permissions != newD.permissions {
		if err := os.Chmod(newD.Name(), newD.permissions); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the directory.
func (dc dirConfigurator) Delete(_ context.Context, item depgraph.Item) error {
	d := item.(directory)
	return os.Remove(d.Name())
}

func (dc dirConfigurator) NeedsRecreate(_, _ depgraph.Item) (recreate bool) {
	return false
}
