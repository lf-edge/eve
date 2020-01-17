// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Routines which operate on types.GlobalConfig

package utils

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	globalConfigDir = types.PersistConfigDir + "/GlobalConfig"
	symlinkDir      = types.TmpDirname + "/GlobalConfig"
)

// EnsureGCFile is used by agents which wait for GlobalConfig to become initialized
// on startup in order to make sure we have a GlobalConfig file.
func EnsureGCFile() {
	pubGlobalConfig, err := pubsub.PublishPersistent("", types.ConfigItemValueMap{})
	if err != nil {
		log.Fatal(err)
	}
	ReadAndUpdateGCFile(pubGlobalConfig)
}

// ReadAndUpdateGCFile does the work of getting a sane or default
// GlobalConfig based on the current definition of GlobalConfig which
// might be different than the file stored on disk if we did an update
// of EVE.
func ReadAndUpdateGCFile(pub pubsub.Publication) {
	key := "global"
	_, err := pub.Get(key)
	if err != nil {
		log.Warn("No globalConfig in /persist; creating it with defaults")
		err := pub.Publish(key, types.DefaultConfigItemValueMap())
		if err != nil {
			log.Errorf("Publish for globalConfig failed %s\n",
				err)
		}
	}
	// Make sure we have a correct symlink from /var/tmp/zededa so
	// others can subscribe from there
	info, err := os.Lstat(symlinkDir)
	if err == nil {
		if (info.Mode() & os.ModeSymlink) != 0 {
			return
		}
		log.Warnf("Removing old %s", symlinkDir)
		if err := os.RemoveAll(symlinkDir); err != nil {
			log.Fatal(err)
		}
	}
	if err := os.Symlink(globalConfigDir, symlinkDir); err != nil {
		log.Fatal(err)
	}
}
