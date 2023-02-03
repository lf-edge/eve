// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func runPubsub(pubStr string) {
	opts, err := checkOpts(pubStr, pubsubopts)
	if err != nil {
		fmt.Println("runPubsub:", err)
		return
	}

	if !rePattern.MatchString(pubStr) {
		fmt.Printf("pubStr has invalid string\n")
		return
	}

	startdir := []string{"/run/", "/persist/status/", "/persist/pubsub-large/"}
	for _, p := range opts {
		printTitle("\n === Pub/Sub: <"+p+"> ===\n\n", colorPURPLE, false)

		var pubsubdir, subdir string
		if strings.Contains(p, "/") {
			items := strings.Split(p, "/")
			pubsubdir = items[0]
			subdir = items[1]
		} else {
			pubsubdir = p
			subdir = ""
		}

		for _, sdir := range startdir {
			if sdir == "/persist/status/" {
				opts1, _ := checkOpts(pubStr, pubsubpersist)
				if len(opts1) == 0 {
					break
				}
			} else if sdir == "/persist/pubsub-large/" {
				opts1, _ := checkOpts(pubStr, pubsublarge)
				if len(opts1) == 0 {
					break
				}
			}

			printColor("\n pubsub in: "+sdir, colorBLUE)

			if subdir != "" {
				files, err := os.ReadDir(sdir + pubsubdir)
				if err != nil {
					continue
				}
				for _, sub := range files {
					if !sub.IsDir() {
						continue
					}
					lowerName := strings.ToLower(sub.Name())
					lowerStr := strings.ToLower(subdir)
					if !strings.Contains(lowerName, lowerStr) {
						continue
					}
					subdir = sub.Name()
					pubsubSvs(sdir, pubsubdir, subdir)
				}
			} else {
				pubsubSvs(sdir, pubsubdir, subdir)
			}
			closePipe(true)
		}
	}
}

func pubsubSvs(startDir, pubsubDir, subDir string) {
	newdir := startDir + pubsubDir
	if subDir != "" {
		newdir = newdir + "/" + subDir
	}

	jfiles, err := listRecursiveFiles(newdir, ".json")
	if err != nil {
		fmt.Printf("list file error: %v\n", err)
		return
	}
	printpath := ""
	byteCnt := 0
	for _, f := range jfiles {
		dir1 := strings.Split(f, newdir+"/")
		if len(dir1) < 2 {
			continue
		}
		paths := strings.Split(dir1[1], "/")
		path := ""
		for _, p := range paths[:len(paths)-1] {
			path = path + "/" + p
		}
		if printpath != newdir+path {
			printColor("  "+newdir+path, colorGREEN)
			printpath = newdir + path
		}
		fmt.Printf("   service: %s\n", paths[len(paths)-1])
		retData, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		prettyJSON, err := formatJSON(retData)
		if err != nil {
			fmt.Printf("JsonFormet error %v\n", err)
		}

		byteCnt += len(prettyJSON)
		if byteCnt > 5000 { // it can have large number of files
			closePipe(true)
			byteCnt = 0
		}
		fmt.Println(string(prettyJSON))
		if isTechSupport {
			closePipe(true)
		}
	}
}

func formatJSON(data []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", "    ")
	if err == nil {
		return out.Bytes(), err
	}
	return data, nil
}
