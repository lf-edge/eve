// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	//file under container's root path which stores the respective snapshotID
	snapshotIDFile = "snapshotid.txt"
)

// PrepareMount creates special files for running container inside a VM
func PrepareMount(containerID uuid.UUID, containerPath string, envVars map[string]string, noOfDisks int) error {
	log.Infof("PrepareMount(%s, %s, %v, %d)", containerID, containerPath,
		envVars, noOfDisks)
	imageInfo, err := getSavedImageInfo(containerPath)
	if err != nil {
		log.Errorf("PrepareMount(%s, %s) getImageInfo failed: %s",
			containerID, containerPath, err)
		return err
	}
	// inject a few files of our own into the bundle
	mountpoints, execpath, workdir, env, err := getContainerConfigs(imageInfo, envVars)
	if err != nil {
		log.Errorf("PrepareMount(%s, %s) getContainerConfigs failed: %s",
			containerID, containerPath, err)
		return fmt.Errorf("PrepareMount: unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerPath, mountpoints, execpath, workdir, env, noOfDisks)
	if err != nil {
		log.Errorf("PrepareMount(%s, %s) createMountPointExecEnvFiles failed: %s",
			containerID, containerPath, err)
	}
	return err
}

// GetContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func GetContainerPath(containerDir string) string {
	return path.Join(containersRoot, containerDir)
}

// SaveSnapshotID stores snapshotID under newRootpath to handle upgrade scenario
func SaveSnapshotID(oldRootpath, newRootpath string) error {
	snapshotID := filepath.Base(oldRootpath)
	filename := filepath.Join(newRootpath, snapshotIDFile)
	if err := ioutil.WriteFile(filename, []byte(snapshotID), 0644); err != nil {
		err = fmt.Errorf("SaveSnapshotID: Save snapshotID %s failed: %s", snapshotID, err)
		log.Error(err.Error())
		return err
	}
	log.Infof("SaveSnapshotID: Saved snapshotID %s in %s",
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
			log.Infof("GetSnapshotID read %s from %s",
				snapshotID, filename)
			return snapshotID
		}
		log.Errorf("GetSnapshotID read %s failed: %s", filename, err)
	}
	snapshotID := filepath.Base(rootpath)
	log.Infof("GetSnapshotID basename %s from %s", snapshotID, rootpath)
	return snapshotID
}

// GetClientImageObjectFromMetadata returns a client image object from the metadata image
func GetClientImageObjectFromMetadata(metadataImageObject images.Image) containerd.Image {
	return containerd.NewImage(CtrdClient, metadataImageObject)
}

//UnpackClientImage unpacks given client image into containerd.
func UnpackClientImage(clientImage containerd.Image) error {
	log.Infof("UnpackClientImage: for image :%s", clientImage.Name())
	unpacked, err := clientImage.IsUnpacked(ctrdCtx, defaultSnapshotter)
	if err != nil {
		return fmt.Errorf("UnpackClientImage: unable to get image metadata: %v config: %v", clientImage.Name(), err)
	}
	if !unpacked {
		if err := clientImage.Unpack(ctrdCtx, defaultSnapshotter); err != nil {
			return fmt.Errorf("UnpackClientImage: unable to unpack image: %v config: %v", clientImage.Name(), err)
		}
	}
	return nil
}

//GetClientImageSpec returns image spec object for a containerd client image.
func GetClientImageSpec(clientImage containerd.Image) (v1.Image, error) {
	log.Infof("GetClientImageSpec: for image :%s", clientImage.Name())
	var ociimage v1.Image
	ic, err := clientImage.Config(ctrdCtx)
	if err != nil {
		return ociimage, fmt.Errorf("GetClientImageSpec: ubable to fetch image: %v config. %v", clientImage.Name(), err.Error())
	}
	switch ic.MediaType {
	case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		p, err := content.ReadBlob(ctrdCtx, clientImage.ContentStore(), ic)
		if err != nil {
			return ociimage, fmt.Errorf("GetClientImageSpec: ubable to read cotentStore of image: %v config. %v", clientImage.Name(), err.Error())
		}

		if err := json.Unmarshal(p, &ociimage); err != nil {
			return ociimage, fmt.Errorf("GetClientImageSpec: ubable to marshal cotentStore of image: %v config. %v", clientImage.Name(), err.Error())

		}
	default:
		return ociimage, fmt.Errorf("GetClientImageSpec: unknown image config media type %s", ic.MediaType)
	}
	return ociimage, nil
}
