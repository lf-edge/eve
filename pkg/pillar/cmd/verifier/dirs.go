package verifier

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var (
	verifierObjTypes = []string{types.AppImgObj, types.BaseOsObj}
)

func initializeDirs() {
	// Remove any files which didn't make it past the verifier.
	// useful for calculating total available space in
	// downloader context
	// XXX when does downloader calculate space?
	clearInProgressDownloadDirs(verifierObjTypes)
	// create the object download directories
	createDownloadDirs(verifierObjTypes)
}

// Create the object download directories we own
func createDownloadDirs(objTypes []string) {
	// now create the download dirs
	for _, objType := range objTypes {
		workingDirTypes := []string{getVerifierDir(objType), getVerifiedDir(objType)}
		for _, dirName := range workingDirTypes {
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

	// Now remove the in-progress dirs
	for _, objType := range objTypes {
		inProgressDirTypes := []string{getVerifierDir(objType)}
		for _, dirName := range inProgressDirTypes {
			if _, err := os.Stat(dirName); err == nil {
				if err := os.RemoveAll(dirName); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}
