package upgradeconverter

import (
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

const OLDVERSION  = "/persist/config/GlobalConfig/global.json"
const NEWVERSION  = "/persist/config/GlobalConfigV2/global.json"
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func fileTimeStamp(filename string) (time.Time, error) {
	file, err := os.Stat(filename)
	if err != nil {
		return time.Now(), err
	}
	return file.ModTime(), nil
}

func deleteFile(filename string) error {
	var err = os.Remove(filename)
	if err == nil {
		log.Debugf("Removed file %s", filename)
		return nil
	}
	return err
}
