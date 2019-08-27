// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func SizeFromDir(dirname string) uint64 {
	var totalUsed uint64
	locations, err := ioutil.ReadDir(dirname)
	if err != nil {
		//log.Debugf("Dir %s is missing. Set the size to zero\n", dirname)
		return totalUsed
	}
	for _, location := range locations {
		filename := dirname + "/" + location.Name()
		log.Debugf("Looking in %s\n", filename)
		if location.IsDir() {
			size := SizeFromDir(filename)
			log.Debugf("Dir %s size %d\n", filename, size)
			totalUsed += size
		} else {
			log.Debugf("File %s Size %d\n", filename, location.Size())
			totalUsed += uint64(location.Size())
		}
	}
	return totalUsed
}
