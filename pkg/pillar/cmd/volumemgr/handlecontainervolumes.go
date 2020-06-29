package volumemgr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/containerd"

	log "github.com/sirupsen/logrus"
)

const (
	// relative path to rootfs for an individual container
	containerRootfsPath = "rootfs/"
	// container config file name
	imageConfigFilename = "image-config.json"
	// contains conatiner's image name.
	imageNameFilename = "image-name"
)

// prepareContainerVolume prepares a writable snapshot from an OCI layers bundle
// We always do it from scratch all the way, ignoring any existing state
// that may have accumulated (like existing snapshots being available, etc.)
// This effectively voids any kind of caching, but on the flip side frees us
// from cache invalidation. Additionally we deposit an OCI config json file and image name
// next to the rootfs so that the effective structure becomes:
//    rootPath/rootfs, rootPath/image-config.json, rootPath/image-name
// We also expect rootPath to end in a basename that becomes containerd's snapshotID
func prepareContainerVolume(rootPath string, ociFilename string) error {

	//Step 1: On device restart, the existing bundle is not deleted, we need to delete the
	// existing bundle of the container and recreate it. This is safe to run even
	// when bundle doesn't exist
	if removeContainerVolume(rootPath, true) != nil {
		log.Infof("prepareContainerVolume: tried to clean up any existing state, hopefully it worked")
	}

	//Step 2: Load the OCI tar file as image into containerd.
	var err error
	tarReader, err := os.Open(ociFilename)
	if err != nil {
		err = fmt.Errorf("prepareContainerVolume: could not open tar file for reading at %s: %+s",
			ociFilename, err.Error())
		log.Errorf(err.Error())
		return err
	}

	imageMetadataList, err := containerd.CtrLoadImage(tarReader)
	if err != nil {
		log.Errorf("prepareContainerVolume: could not load image tar at %s into containerd: %+s",
			ociFilename, err.Error())
		return err
	}
	if len(imageMetadataList) > 1 {
		log.Errorf("prepareContainerVolume: loaded %d images, expected just 1. Considering only the first image",
			len(imageMetadataList))
	}

	//Step 3: unpack image (if not done already)
	clientImageObj := containerd.GetClientImageObjectFromMetadata(imageMetadataList[0])
	if err := containerd.UnpackClientImage(clientImageObj); err != nil {
		err = fmt.Errorf("prepareContainerVolume: could not unpack image %s: %+s",
			clientImageObj.Name(), err.Error())
		log.Errorf(err.Error())
		return err
	}

	//Step 4: create snapshot of the image so that it can be mounted as container's rootfs.
	snapshotID := containerd.GetSnapshotID(rootPath)
	mounts, err := containerd.CtrPrepareSnapshot(snapshotID, clientImageObj)
	if err != nil {
		err = fmt.Errorf("prepareContainerVolume: Could not create snapshot %s. %v", snapshotID, err)
		log.Errorf(err.Error())
		return err
	} else {
		if len(mounts) > 1 {
			return fmt.Errorf("prepareContainerVolume: More than 1 mount-point for snapshot %v %v",
				rootPath, mounts)
		} else {
			log.Infof("prepareContainerVolume: prepared a snapshot for %v with the following mounts: %v",
				snapshotID, mounts)
		}
	}

	//Step 5: write OCI image config/spec json under the container's rootPath.
	clientImageSpec, err := containerd.GetClientImageSpec(clientImageObj)
	if err != nil {
		err = fmt.Errorf("prepareContainerVolume: Could not get image config/spec %s. %v",
			clientImageObj.Name(), err)
		log.Errorf(err.Error())
		return err
	}
	mountpoints := clientImageSpec.Config.Volumes
	execpath := clientImageSpec.Config.Entrypoint
	cmd := clientImageSpec.Config.Cmd
	workdir := clientImageSpec.Config.WorkingDir
	unProcessedEnv := clientImageSpec.Config.Env
	log.Infof("prepareContainerVolume: mountPoints %+v execpath %+v cmd %+v workdir %+v env %+v",
		mountpoints, execpath, cmd, workdir, unProcessedEnv)

	clientImageSpecJSON, err := getJSON(clientImageSpec)
	if err != nil {
		err = fmt.Errorf("prepareContainerVolume: Could not build json of image: %v. %v",
			clientImageObj.Name(), err.Error())
		log.Errorf(err.Error())
		return err
	}
	if err := os.MkdirAll(rootPath, 0766); err != nil {
		return fmt.Errorf("prepareContainerVolume: Exception while creating rootPath dir. %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(rootPath, imageConfigFilename), []byte(clientImageSpecJSON), 0666); err != nil {
		return fmt.Errorf("prepareContainerVolume: Exception while writing image info to %v/%v. %v",
			rootPath, imageConfigFilename, err)
	}

	//Step 6: save image's name into a file. Since image name is not part of `clientImageSpecJSON`,
	// we need this while removing image later in the flow
	if err := ioutil.WriteFile(filepath.Join(rootPath, imageNameFilename), []byte(clientImageObj.Name()), 0666); err != nil {
		return fmt.Errorf("prepareContainerVolume: Exception while writing image name to %v/%v. %v",
			rootPath, imageNameFilename, err)
	}
	return nil
}

// removeContainerVolume removes existing snapshot and image.
// If silent is true, then operation failures are ignored and no error is returned
func removeContainerVolume(rootPath string, silent bool) error {

	//Step 1: Un-mount container's rootfs
	if err := syscall.Unmount(filepath.Join(rootPath, containerRootfsPath), 0); err != nil {
		err = fmt.Errorf("removeContainerVolume: exception while unmounting: %v/%v. %v",
			rootPath, containerRootfsPath, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	//Step 2: Clean container rootPath
	if err := os.RemoveAll(rootPath); err != nil {
		err = fmt.Errorf("removeContainerVolume: exception while deleting: %v. %v", rootPath, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	//Step 3: Remove snapshot created for the image
	snapshotID := containerd.GetSnapshotID(rootPath)
	if err := containerd.CtrRemoveSnapshot(snapshotID); err != nil {
		err = fmt.Errorf("removeContainerVolume: unable to remove snapshot: %v. %v", snapshotID, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	//Step 4: Remove image
	imageName, err := getImageNameFromRootPath(rootPath)
	if err != nil {
		err := fmt.Errorf("removeContainerVolume: exception while getting image name from %s: %s", rootPath, err.Error())
		log.Error(err.Error())
		if !silent {
			return err
		}
	}
	if err := containerd.CtrDeleteImage(imageName); err != nil {
		err := fmt.Errorf("removeContainerVolume: exception while deleting image %s: %s", imageName, err.Error())
		log.Error(err.Error())
		if !silent {
			return err
		}
	}
	return nil
}

//Util methods

// getJSON - returns input in JSON format
func getJSON(x interface{}) (string, error) {
	b, err := json.MarshalIndent(x, "", "    ")
	if err != nil {
		return "", fmt.Errorf("getJSON: Exception while marshalling container spec JSON. %v", err)
	}
	return fmt.Sprint(string(b)), nil
}

func getImageNameFromRootPath(rootPath string) (string, error) {
	filename := filepath.Join(rootPath, imageNameFilename)
	imageNameBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		err = fmt.Errorf("getImageNameFromRootPath: exception while reading %s from %s: %s",
			imageNameFilename, rootPath, err.Error())
		log.Error(err.Error())
		return "", err
	}
	imageName := string(imageNameBytes)
	log.Infof("getImageNameFromRootPath read %s from %s", imageName, filename)
	return imageName, err
}
