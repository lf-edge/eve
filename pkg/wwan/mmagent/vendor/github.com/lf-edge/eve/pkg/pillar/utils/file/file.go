// Copyright (c) 2019,2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const maxCounterReadSize = 16384 // Max size of counter file

// FileExists checks file existence.
func FileExists(log *base.LogObject, filename string) bool {
	_, err := os.Stat(filename)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	if log != nil {
		log.Errorf("File %s may or may not exist. Err: %s", filename, err)
	}
	return false
}

// DirExists checks directory existence.
func DirExists(log *base.LogObject, dirname string) bool {
	fi, err := os.Stat(dirname)
	if err == nil {
		return fi.IsDir()
	}
	if os.IsNotExist(err) {
		return false
	}
	if log != nil {
		log.Errorf("Directory %s may or may not exist. Err: %s",
			dirname, err)
	}
	return false
}

// DirSync flushes changes made to a directory.
func DirSync(dirName string) error {
	f, err := os.OpenFile(dirName, os.O_RDONLY, 0755)
	if err != nil {
		return err
	}

	err = f.Sync()
	if err != nil {
		f.Close()
		return err
	}

	// Not a deferred call, because DirSync is a critical
	// path. Better safe then sorry, and we better check all the
	// errors including one returned by close()
	err = f.Close()
	return err
}

func backupFile(fileName string) error {
	_, err := os.Stat(fileName)
	if err != nil {
		//lint:ignore nilerr File doesn't exist, nothing to backup.
		return nil
	}

	bakName := fmt.Sprintf("%s.bak", fileName)

	err = CopyFile(fileName, bakName)
	if err != nil {
		return err
	}

	err = DirSync(filepath.Dir(fileName))
	return err
}

// WriteRename write data to a fmpfile and then rename it to a desired name
func WriteRename(fileName string, b []byte) error {
	return writeRename(fileName, b, false)
}

// WriteRenameWithBackup : just like WriteRename but additionally it creates
// a backup of the original file at the same path but with the ".bak" extension
// added.
func WriteRenameWithBackup(fileName string, b []byte) error {
	return writeRename(fileName, b, true)
}

func writeRename(fileName string, b []byte, withBackup bool) error {
	dirName := filepath.Dir(fileName)
	// Do atomic rename to avoid partially written files
	tmpfile, err := os.CreateTemp(dirName, "tmp")
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
	// Make sure the file is flushed from buffers onto the disk
	if err := tmpfile.Sync(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s) failed to sync temp file: %s",
			fileName, err)
		return errors.New(errStr)
	}

	if err := tmpfile.Close(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}

	if withBackup {
		err = backupFile(fileName)
		if err != nil {
			// Not a fatal error, continuing
			logrus.Errorf("Unable to backup file %s: %v", fileName, err)
		}
	}

	if err := os.Rename(tmpfile.Name(), fileName); err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}

	return DirSync(filepath.Dir(fileName))
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
	content := make([]byte, maxReadSize+1)
	n, err := r.Read(content)
	if err != nil {
		err = fmt.Errorf("ReadWithMaxSize %s failed: %v", filename, err)
		if log != nil {
			log.Error(err)
		}
		return nil, err
	}
	if n > maxReadSize {
		err = fmt.Errorf("ReadWithMaxSize %s truncated after %d bytes",
			filename, maxReadSize)
		n = maxReadSize
	} else {
		err = nil
	}
	return content[:n], err
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
