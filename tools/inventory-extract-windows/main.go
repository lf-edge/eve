// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/diskfs/go-diskfs/filesystem/fat32"
	"github.com/diskfs/go-diskfs/partition"
)

//sleepTime is used for sleep before closing the app
const sleepTime = time.Second * 5

var outputPath = flag.String("dir", "", "save file to provided directory (will generate temp if empty)")
var driveNumber = flag.Uint("drive", 0, "open drive with provided number")
var drivesList = flag.Bool("list", false, "list drives")
var helpFlag = flag.Bool("help", false, "help")
var overrideFlag = flag.Bool("override", false, "override existing files/directories")

func main() {
	flag.Parse()
	if *helpFlag {
		fmt.Println("This program do export of INVENTORY partition from EVE drive")
		fmt.Println("You can see list of available drives with -list flag")
		fmt.Println("Then you must set Index of drive to -drive flag")
		fmt.Println("With -dir flag you can provide directory to save files into. " +
			"The program will create directory in temp if you will not provide this flag.")
		fmt.Println("You can set -override flag if you want to override existing directories/files")
		os.Exit(0)
	}
	if *driveNumber == 0 {
		fmt.Println("Please provide -drive flag with Index of device from the list below:")
		*drivesList = true
	}
	if *drivesList {
		res, err := exec.Command("wmic", "diskdrive",
			"where", "MediaType='Removable Media'",
			"get", "index,caption").CombinedOutput()
		if err != nil {
			log.Println(err)
		} else {
			fmt.Println(string(res))
		}
		time.Sleep(sleepTime)
		os.Exit(0)
	}
	fd0, err := os.Open(`\\.\PhysicalDrive0`)
	if err != nil {
		log.Println("This program must be run by Administrator")
		log.Println("We will ask for permissions")
		time.Sleep(sleepTime)
		runMeElevated()
		os.Exit(0)
	}
	_ = fd0.Close()
	f, err := os.Open(fmt.Sprintf(`\\.\PhysicalDrive%d`, *driveNumber))
	if err != nil {
		log.Println(err)
		time.Sleep(sleepTime)
		os.Exit(1)
	}
	defer f.Close()

	table, err := partition.Read(f, 512, 512)

	if err != nil {
		log.Println(err)
		time.Sleep(sleepTime)
		os.Exit(1)
	}
	partitions := table.GetPartitions()
	found := false
	for _, el := range partitions {
		fsCurrent, err := fat32.Read(f, el.GetSize(), el.GetStart(), 512)
		if err != nil {
			continue
		}
		if fsCurrent.Label() == "INVENTORY" {
			var dir string
			if *outputPath != "" {
				dir, err = filepath.Abs(*outputPath)
				if err != nil {
					log.Println(err)
					continue
				}
				err = os.MkdirAll(dir, os.ModeDir)
				if err != nil {
					log.Println(err)
					continue
				}
			} else {
				dir, err = ioutil.TempDir("", "INVENTORY")
				if err != nil {
					log.Println(err)
					continue
				}
			}
			log.Printf("Will save to directory: %s", dir)
			err = iterateAndSave(fsCurrent, dir, "/")
			if err != nil {
				log.Println(err)
				continue
			}
			found = true
			break
		}
	}
	if found {
		log.Println("Processing done")
	} else {
		log.Println("No INVENTORY found")
	}
	time.Sleep(sleepTime)
}

func iterateAndSave(fsCurrent *fat32.FileSystem, dirToSave, dir string) error {
	d, err := fsCurrent.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, curFileInfo := range d {
		if curFileInfo.Name() == "." || curFileInfo.Name() == ".." {
			continue
		}
		log.Println(curFileInfo.Name())
		if curFileInfo.IsDir() {
			curDirPath := filepath.Join(dirToSave, curFileInfo.Name())
			if !*overrideFlag {
				err = os.Mkdir(curDirPath, os.ModeDir)
			} else {
				err = os.MkdirAll(curDirPath, os.ModeDir)
			}
			if err != nil {
				log.Println(err)
				continue
			}
			err = iterateAndSave(fsCurrent, filepath.Join(dirToSave, curFileInfo.Name()), fmt.Sprintf("%s/%s", dir, curFileInfo.Name()))
			if err != nil {
				log.Println(err)
			}
			err = os.Chtimes(curDirPath, curFileInfo.ModTime(), curFileInfo.ModTime())
			if err != nil {
				log.Println(err)
			}
			continue
		}
		dstFileName := filepath.Join(dirToSave, curFileInfo.Name())
		if !*overrideFlag {
			if _, err := os.Stat(dstFileName); err == nil {
				log.Printf("File %s already exists, skip it", dstFileName)
				continue
			}
		}
		dstFile, err := os.Create(dstFileName)
		if err != nil {
			log.Println(err)
			continue
		}
		curFile, err := fsCurrent.OpenFile(fmt.Sprintf("%s/%s", dir, curFileInfo.Name()), os.O_RDONLY)
		if err != nil {
			dstFile.Close()
			log.Println(err)
			continue
		}
		_, err = io.Copy(dstFile, curFile)
		curFile.Close()
		dstFile.Close()
		if err != nil {
			log.Println(err)
			continue
		}
		err = os.Chtimes(dstFileName, curFileInfo.ModTime(), curFileInfo.ModTime())
		if err != nil {
			log.Println(err)
		}
	}
	return nil
}
