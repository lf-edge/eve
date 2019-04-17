// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func SizeFromDir(dirname string) uint64 {
	var totalUsed uint64 = 0
	locations, err := ioutil.ReadDir(dirname)
	if err != nil {
		log.Fatal(err)
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
