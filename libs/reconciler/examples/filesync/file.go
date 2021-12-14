// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/lf-edge/eve/libs/depgraph"
)

var lastFileID int

func newFileID() int {
	lastFileID++
	return lastFileID
}

// file represents a named, regular file.
type file struct {
	id          int
	filename    string
	content     string
	permissions os.FileMode
	parentDir   *directory
}

// Name returns the file identifier.
// This is neither filename nor filepath, both of which can change and we want to use
// the efficient os.Rename(). If filepath would be used as the item ID, then change
// of the path would result in graph calling Delete + Create (i.e. re-creating the file
// on the new location as a completely new item). But we want the graph to call Modify,
// which inside uses the efficient os.Rename().
func (f file) Name() string {
	return strconv.Itoa(f.id)
}

// Label is used only for graph visualization and it does not have to be a unique
// item identifier.
func (f file) Label() string {
	return f.filename
}

func (f file) Type() string {
	return "file"
}

// Equal returns false even when only the parent directory reference changes.
// This is because we want to call Modify to move the file in that case.
func (f file) Equal(item2 depgraph.Item) bool {
	f2 := item2.(file)
	return f.path() == f2.path() &&
		f.permissions == f2.permissions &&
		f.content == f2.content
}

func (f file) External() bool {
	return false
}

func (f file) path() string {
	return f.parentDir.Name() + "/" + f.filename
}

func (f file) String() string {
	return fmt.Sprintf("path: %s\ncontent: %s\npermissions: %o",
		f.path(), f.content, f.permissions)
}

// Dependencies returns the parent directory as the file's only dependency.
func (f file) Dependencies() []depgraph.Dependency {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: directory{}.Type(),
				ItemName: f.parentDir.Name(),
			},
			Description: "For file to be created, the parent directory must already exist",
		},
	}
}

// fileConfigurator is the Configurator for files.
type fileConfigurator struct{}

// Create writes a new file.
func (fc fileConfigurator) Create(_ context.Context, item depgraph.Item) error {
	f := item.(file)
	return ioutil.WriteFile(f.path(), []byte(f.content), f.permissions)
}

// Modify can rename the file and change the access rights.
// Change in the file content is handled through re-creation (for demo purposes).
func (fc fileConfigurator) Modify(_ context.Context, oldItem, newItem depgraph.Item) (err error) {
	oldF := oldItem.(file)
	newF := newItem.(file)
	if oldF.path() != newF.path() {
		if err := os.Rename(oldF.path(), newF.path()); err != nil {
			return err
		}
	}
	if oldF.permissions != newF.permissions {
		if err := os.Chmod(newF.path(), newF.permissions); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the file.
func (fc fileConfigurator) Delete(_ context.Context, item depgraph.Item) error {
	f := item.(file)
	return os.Remove(f.path())
}

// NeedsRecreate returns true when the file content changes.
// This is used just to demonstrate how Reconciler can re-create an item.
func (fc fileConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldF := oldItem.(file)
	newF := newItem.(file)
	return oldF.content != newF.content
}
