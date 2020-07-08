package volumemgr

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func initializeDirs() {

	// first the certs directory
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Debugf("initializeDirs: Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
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
