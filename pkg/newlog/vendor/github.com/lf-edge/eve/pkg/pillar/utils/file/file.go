// Copyright (c) 2019,2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"golang.org/x/sys/unix"
)

const maxCounterReadSize = 16384 // Max size of counter file

// WriteRename write data to a fmpfile and then rename it to a desired name
func WriteRename(fileName string, b []byte) error {
	dirName := filepath.Dir(fileName)
	// Do atomic rename to avoid partially written files
	tmpfile, err := ioutil.TempFile(dirName, "tmp")
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(b)
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	// Make sure the file is flused from buffers onto the disk
	tmpfile.Sync()
	if err := tmpfile.Close(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := os.Rename(tmpfile.Name(), fileName); err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	return nil
}

// Writable checks if the directory is writable
func Writable(dir string) bool {
	return unix.Access(dir, unix.W_OK) == nil
}

// StatAndRead returns the content and Modtime
// We limit the size we read maxReadSize and truncate if longer
func StatAndRead(log *base.LogObject, filename string, maxReadSize int) (string, time.Time, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		// File doesn't exist
		return "", time.Time{}, err
	}
	if fi.Size() == 0 {
		return "", fi.ModTime(), nil
	}
	content, err := ReadWithMaxSize(log, filename, maxReadSize)
	if err != nil {
		err = fmt.Errorf("StatAndRead %s failed: %v", filename, err)
		if log != nil {
			log.Error(err)
		}
		return "", fi.ModTime(), err
	}
	return string(content), fi.ModTime(), err
}

// ReadWithMaxSize returns the content but limits the size to maxReadSize and
// truncates if longer
func ReadWithMaxSize(log *base.LogObject, filename string, maxReadSize int) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		err = fmt.Errorf("ReadWithMaxSize %s failed: %v", filename, err)
		if log != nil {
			log.Error(err)
		}
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	content := make([]byte, maxReadSize)
	n, err := r.Read(content)
	if err != nil {
		err = fmt.Errorf("ReadWithMaxSize %s failed: %v", filename, err)
		if log != nil {
			log.Error(err)
		}
		return nil, err
	}
	if n == maxReadSize {
		err = fmt.Errorf("ReadWithMaxSize %s truncated after %d bytes",
			filename, maxReadSize)
	} else {
		err = nil
	}
	return content[0:n], err
}

// ReadSavedCounter returns counter value from provided file
// If the file doesn't exist or doesn't contain an integer it returns false
func ReadSavedCounter(log *base.LogObject, fileName string) (uint32, bool) {
	if log != nil {
		log.Tracef("ReadSavedCounter(%s) - reading", fileName)
	}

	b, _, err := StatAndRead(log, fileName, maxCounterReadSize)
	if err == nil {
		c, err := strconv.Atoi(b)
		if err != nil {
			if log != nil {
				log.Errorf("ReadSavedCounter(%s): %s", fileName, err)
				return 0, false
			}
		}
		return uint32(c), true
	}
	if log != nil {
		log.Functionf("ReadSavedCounter(%s): %s", fileName, err)
	}
	return 0, false
}
