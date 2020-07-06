package volumemgr

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var (
	downloaderObjTypes = []string{types.AppImgObj, types.BaseOsObj, types.CertObj}
)

func initializeDirs() {

	// first the certs directory
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Debugf("initializeDirs: Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Remove any files which didn't make it to the verifier.
	// XXX space calculation doesn't take into account files in verifier
	// XXX get space report from verifier??
	clearInProgressDownloadDirs(downloaderObjTypes)

	// create the object download directories
	createDownloadDirs(downloaderObjTypes)
}

// Create the object download directories we own
func createDownloadDirs(objTypes []string) {

	workingDirTypes := []string{"pending"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range workingDirTypes {
			dirName := types.DownloadDirname + "/" + objType + "/" + dirType
			if _, err := os.Stat(dirName); err != nil {
				log.Debugf("Create %s", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// clear in-progress object download directories
func clearInProgressDownloadDirs(objTypes []string) {

	inProgressDirTypes := []string{"pending"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range inProgressDirTypes {
			dirName := types.DownloadDirname + "/" + objType +
				"/" + dirType
			if _, err := os.Stat(dirName); err == nil {
				if err := os.RemoveAll(dirName); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
	// Our destination volume directories
	volumeDirs := []string{
		types.VolumeEncryptedDirName,
		types.VolumeClearDirName,
	}
	for _, dirName := range volumeDirs {
		if _, err := os.Stat(dirName); err != nil {
			log.Infof("Create %s", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}
}
