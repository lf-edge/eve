// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package containerd

import (
	"fmt"
	uuid "github.com/satori/go.uuid"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"
)

const (
	oldTempBasePath = "/tmp/persist/pods/prepared"
	newTempBasePath = "/tmp/persist/vault/volumes"
)

var (
	containerID, _  = uuid.NewV4()
	containerDir    = fmt.Sprintf("%s#0.container", containerID.String())
	snapshotID      = containerDir
	oldTempRootPath = path.Join(oldTempBasePath, containerDir)
	newTempRootPath = path.Join(newTempBasePath, containerDir)
)

func TestSaveSnapshotID(t *testing.T) {
	err := os.MkdirAll(newTempRootPath, 0777)
	if err != nil {
		t.Errorf("TestSaveSnapshotID: Failed to create %s: %s", newTempRootPath, err.Error())
	} else {
		defer os.RemoveAll(newTempRootPath)
	}

	type args struct {
		oldRootpath string
		newRootpath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "TestSaveSnapshotID1",
			args: args{
				oldRootpath: oldTempRootPath,
				newRootpath: newTempRootPath,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveSnapshotID(tt.args.oldRootpath, tt.args.newRootpath); err != nil || tt.wantErr != nil {
				if (tt.wantErr == nil) || ((err != nil) && (tt.wantErr.Error() != err.Error())) {
					t.Errorf("SaveSnapshotID() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				snapshotIDFile := path.Join(tt.args.newRootpath, snapshotIDFile)
				expectedSnapshotID := snapshotID
				snapshotID, err := ioutil.ReadFile(snapshotIDFile)
				if err != nil {
					t.Errorf("TestSaveSnapshotID: exception while reading %s file %s %v",
						snapshotIDFile, snapshotIDFile, err)
				}
				if string(snapshotID) != expectedSnapshotID {
					t.Errorf("TestSaveSnapshotID: mismatched %s file content, actual '%s' expected '%s'",
						snapshotIDFile, string(snapshotID), expectedSnapshotID)
				}
			}
		})
	}
}

func TestGetSnapshotID(t *testing.T) {
	err := os.MkdirAll(newTempRootPath, 0777)
	if err != nil {
		t.Errorf("TestPrepareMount: Failed to create %s: %s", oldTempRootPath, err.Error())
	} else {
		defer os.RemoveAll(newTempRootPath)
	}

	filename := filepath.Join(newTempRootPath, snapshotIDFile)
	if err := ioutil.WriteFile(filename, []byte(snapshotID), 0644); err != nil {
		t.Errorf("TestGetSnapshotID: exception while saving %s: %s", filename, err.Error())
	}
	type args struct {
		rootpath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "TestGetSnapshotID1",
			args: args{
				rootpath: newTempRootPath,
			},
			want: snapshotID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSnapshotID(tt.args.rootpath); got != tt.want {
				t.Errorf("GetSnapshotID() = %v, want %v", got, tt.want)
			}
		})
	}
}
