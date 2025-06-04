// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func savePanicFiles(panicbuf []byte) {
	var reason string
	panicStr := string(panicbuf)
	strs := strings.Split(panicStr, "\n")
	if len(strs) > 1 {
		reason = strs[0]
		f1, err := os.OpenFile("/persist/reboot-reason", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error(err)
			return
		}
		defer f1.Close()
		if _, err := f1.WriteString(reason); err != nil {
			log.Error(err)
		}
	}

	f2, err := os.OpenFile("/persist/reboot-stack", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error(err)
		return
	}
	defer f2.Close()
	if _, err := f2.WriteString(panicStr); err != nil {
		log.Error(err)
	}

	// save to /persist/newlog/panicStacks directory for maximum of 100 files
	now := time.Now()
	timeStr := strconv.Itoa(int(now.Unix()))
	fileName := panicFileDir + "/pillar-panic-stack." + timeStr
	pfile, err := os.Create(fileName)
	if err != nil {
		log.Error(err)
		return
	}
	defer pfile.Close()

	_, err = pfile.WriteString(formatAndGetMeta("") + "\n")
	if err != nil {
		log.Error(err)
	}
	_, err = pfile.WriteString(panicStr)
	if err != nil {
		log.Error(err)
	}

	cleanPanicFileDir()
}

// clean up the old panic files if the directory has more than 100 files
func cleanPanicFileDir() {
	if _, err := os.Stat(panicFileDir); err != nil {
		return
	}

	files, err := os.ReadDir(panicFileDir)
	if err != nil {
		log.Error(err)
		return
	}

	if len(files) <= 100 {
		return
	}

	var minNum int
	var getFileName string
	for _, f := range files {
		p := strings.Split(f.Name(), ".")
		if len(p) != 2 {
			continue
		}
		fnumber, err := strconv.Atoi(p[1])
		if err != nil {
			continue
		}
		if minNum == 0 || fnumber < minNum {
			minNum = fnumber
			getFileName = f.Name()
		}
	}

	if getFileName != "" {
		err := os.Remove(panicFileDir + "/" + getFileName)
		if err != nil {
			log.Error(err)
			return
		}
	}
}
