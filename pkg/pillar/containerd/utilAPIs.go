// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/containerd/containerd"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	//file under container's root path which stores the respective snapshotID
	snapshotIDFile = "snapshotid.txt"
)

// PrepareMount creates special files for running container inside a VM
func PrepareMount(containerID uuid.UUID, containerPath string, envVars map[string]string, noOfDisks int) error {
	logrus.Infof("PrepareMount(%s, %s, %v, %d)", containerID, containerPath,
		envVars, noOfDisks)
	imageInfo, err := getSavedImageInfo(containerPath)
	if err != nil {
		logrus.Errorf("PrepareMount(%s, %s) getImageInfo failed: %s",
			containerID, containerPath, err)
		return err
	}
	// inject a few files of our own into the bundle
	mountpoints, execpath, workdir, env, err := getContainerConfigs(imageInfo, envVars)
	if err != nil {
		logrus.Errorf("PrepareMount(%s, %s) getContainerConfigs failed: %s",
			containerID, containerPath, err)
		return fmt.Errorf("PrepareMount: unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerPath, mountpoints, execpath, workdir, env, noOfDisks)
	if err != nil {
		logrus.Errorf("PrepareMount(%s, %s) createMountPointExecEnvFiles failed: %s",
			containerID, containerPath, err)
	}
	return err
}

// SaveSnapshotID stores snapshotID under newRootpath to handle upgrade scenario
func SaveSnapshotID(oldRootpath, newRootpath string) error {
	snapshotID := filepath.Base(oldRootpath)
	filename := filepath.Join(newRootpath, snapshotIDFile)
	if err := ioutil.WriteFile(filename, []byte(snapshotID), 0644); err != nil {
		err = fmt.Errorf("SaveSnapshotID: Save snapshotID %s failed: %s", snapshotID, err)
		logrus.Error(err.Error())
		return err
	}
	logrus.Infof("SaveSnapshotID: Saved snapshotID %s in %s",
		snapshotID, filename)
	return nil
}

// GetSnapshotID handles the upgrade scenario when the snapshotID needs to be
// extracted from a file created by upgradeconverter
// Assumes that rootpath is a complete pathname
func GetSnapshotID(rootpath string) string {
	filename := filepath.Join(rootpath, snapshotIDFile)
	if _, err := os.Stat(filename); err == nil {
		cont, err := ioutil.ReadFile(filename)
		if err == nil {
			snapshotID := string(cont)
			logrus.Infof("GetSnapshotID read %s from %s",
				snapshotID, filename)
			return snapshotID
		}
		logrus.Errorf("GetSnapshotID read %s failed: %s", filename, err)
	}
	snapshotID := filepath.Base(rootpath)
	logrus.Infof("GetSnapshotID basename %s from %s", snapshotID, rootpath)
	return snapshotID
}

//UnpackClientImage unpacks given client image into containerd.
func (client *Client) UnpackClientImage(clientImage containerd.Image) error {
	logrus.Infof("UnpackClientImage: for image :%s", clientImage.Name())
	ctrdCtx, done := client.CtrNewUserServicesCtx()
	defer done()
	unpacked, err := clientImage.IsUnpacked(ctrdCtx, defaultSnapshotter)
	if err != nil {
		return fmt.Errorf("UnpackClientImage: unable to get image metadata: %v config: %v", clientImage.Name(), err)
	}
	if !unpacked {
		if err := clientImage.Unpack(ctrdCtx, defaultSnapshotter); err != nil {
			return fmt.Errorf("UnpackClientImage: unable to unpack image: %v: %v", clientImage.Name(), err)
		}
	}
	return nil
}

//isFile check if the given path is pointing to a file.
func isFile(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		logrus.Errorf("isFile(%s): %s", path, err.Error())
		return false
	}
	return !fileInfo.IsDir()
}
