// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"bufio"
	"container/ring"
	"context"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// PSIHeader is the header of the PSI log file
	PSIHeader = "date time someAvg10 someAvg60 someAvg300 someTotal fullAvg10 fullAvg60 fullAvg300 fullTotal"
	// PSITimeIntervalSec is the time interval in seconds to collect PSI data
	PSITimeIntervalSec = 1
	// StatLinesPerHour is the maximum number of lines in the log file
	StatLinesPerHour = 60 * 60 / PSITimeIntervalSec
	// StatLineMaxSize is the maximum size of a log line in bytes.
	// The format of a log line is
	// "date time someAvg10 someAvg60 someAvg300 someTotal fullAvg10 fullAvg60 fullAvg300 fullTotal"
	// date is of format "2006-01-02" (10 bytes)
	// time is of format "15:04:05" (8 bytes)
	// someAvg10, someAvg60, someAvg300, fullAvg10, fullAvg60, fullAvg300 are of format "%.02f"
	//  and the values are in a range of 0.00 to 100.00 (6 bytes maximum each)
	// totals are int64 and can be represented as a 20 bytes maximum string each
	// Plus 1 byte for the space between each field (9 spaces) and 1 byte for the newline character
	// Total size is 10 + 8 + 6*6 + 20*2 + 9 + 1 = 104 bytes
	// Nevertheless, most of the time the values are not at the maximum size, so we can consider
	// an average size of 75 bytes. This estimation is good enough for the purpose of the
	// calculation of the threshold file size.
	StatLineMaxSize uint64 = 104
	// StatLineMinSize is the minimum size of a log line in bytes. It's the case when the values of
	// the "total" fields are at their minimum size (1 byte) and the values of the "avg" fields are
	// at their minimum size (0.00-9.99). The format of a log line is
	// It is 10 + 8 + 4*6 + 1*2 + 9 + 1 = 54 bytes
	StatLineMinSize uint64 = 54
	// StatLineAvgSize is the average size of a log line in bytes. It's just for estimation purposes.
	StatLineAvgSize uint64 = 75
)

var (
	// PressureMemoryFile is the memory pressure file. It is a variable, not a constant, to allow
	// changing it in tests to mock the file.
	pressureMemoryFile     = "/proc/pressure/memory"
	pressureMemoryFileLock sync.RWMutex
)

// PressureMemoryFile returns the path to the memory pressure file in /proc
func PressureMemoryFile() string {
	pressureMemoryFileLock.RLock()
	path := pressureMemoryFile
	pressureMemoryFileLock.RUnlock()

	return path
}

// UpdatePressureMemoryFile sets the path to the memory pressure file (mostly used for tests)
func UpdatePressureMemoryFile(newpath string) {
	pressureMemoryFileLock.Lock()
	pressureMemoryFile = newpath
	pressureMemoryFileLock.Unlock()
}

// MemAllocationSite is the return value of GetMemProfile
type MemAllocationSite struct {
	InUseBytes   int64
	InUseObjects int64
	AllocBytes   int64
	AllocObjects int64
	PrintedStack string
}

// PressureStallInfo is the information about the pressure stall available in the PSI files.
// See https://www.kernel.org/doc/html/latest/accounting/psi.html for more information.
type PressureStallInfo struct {
	SomeAvg10  float64
	SomeAvg60  float64
	SomeAvg300 float64
	SomeTotal  int64
	FullAvg10  float64
	FullAvg60  float64
	FullAvg300 float64
	FullTotal  int64
}

// GetMemAllocationSites returns the non-zero allocation sites in the form of
// an array of strings; each string is for one allocation call site.
// If reportZeroInUse is set it also reports with zero InUse.
func GetMemAllocationSites(reportZeroInUse bool) (int, []MemAllocationSite) {
	var sites []MemAllocationSite

	// Determine how many sites we have
	nprof := 100
	prof := make([]runtime.MemProfileRecord, 100)
	var n = 0
	for {
		var ok bool
		n, ok = runtime.MemProfile(prof, reportZeroInUse)
		if ok {
			break
		}
		fmt.Printf("MemProfile failed for %d\n", nprof)
		nprof += 100
		prof = append(prof, make([]runtime.MemProfileRecord, 100)...)
	}
	for i := 0; i < n; i++ {
		site := MemAllocationSite{
			InUseBytes:   prof[i].InUseBytes(),
			InUseObjects: prof[i].InUseObjects(),
			AllocBytes:   prof[i].AllocBytes,
			AllocObjects: prof[i].AllocObjects,
		}
		frames := runtime.CallersFrames(prof[i].Stack())

		var lines string
		for {
			frame, more := frames.Next()
			// Don't print the entries inside the runtime
			// XXX
			if false && strings.Contains(frame.File, "runtime/") {
				if !more {
					break
				}
				continue
			}
			line := fmt.Sprintf("%s[%d] %s\n",
				frame.File, frame.Line, frame.Function)
			lines += line
			if !more {
				break
			}
		}
		site.PrintedStack = lines
		sites = append(sites, site)
	}
	return n, sites
}

// PsiMutex is the mutex to protect the access to the PSI files.
// We need it to avoid a race condition with the PSI data emulator in tests.
var PsiMutex sync.Mutex

func isPSISupported() bool {
	_, err := os.Stat(PressureMemoryFile())
	if err != nil {
		fmt.Println("PSI is not supported. Be sure to enable CONFIG_PSI=y in your kernel configuration.")
		return false
	}
	return true
}

func collectMemoryPSI() (*PressureStallInfo, error) {
	PsiMutex.Lock()
	defer PsiMutex.Unlock()
	if !isPSISupported() {
		return nil, fmt.Errorf("PSI is not supported")
	}
	procFile, err := os.Open(PressureMemoryFile())
	if err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	defer procFile.Close()

	scanner := bufio.NewScanner(procFile)
	var someAvg10, someAvg60, someAvg300 float64
	var someTotal int64
	var fullAvg10, fullAvg60, fullAvg300 float64
	var fullTotal int64

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "some") {
			_, err = fmt.Sscanf(line, "some avg10=%f avg60=%f avg300=%f total=%d", &someAvg10, &someAvg60, &someAvg300, &someTotal)
		} else if strings.HasPrefix(line, "full") {
			_, err = fmt.Sscanf(line, "full avg10=%f avg60=%f avg300=%f total=%d", &fullAvg10, &fullAvg60, &fullAvg300, &fullTotal)
		}
		if err != nil {
			return nil, fmt.Errorf("scan: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %v", err)
	}

	return &PressureStallInfo{
		SomeAvg10:  someAvg10,
		SomeAvg60:  someAvg60,
		SomeAvg300: someAvg300,
		SomeTotal:  someTotal,
		FullAvg10:  fullAvg10,
		FullAvg60:  fullAvg60,
		FullAvg300: fullAvg300,
		FullTotal:  fullTotal,
	}, nil
}

// MemoryPSICollector collects PSI data and writes it to a statistics file.
// log is the logger object.
// collectorCtx is the context of the collector.
// The statistics file is truncated when it reaches a threshold size and keeps only the last
// linesToKeep lines. The collector runs until the context is canceled.
func MemoryPSICollector(collectorCtx context.Context, log *base.LogObject) error {
	ticker := time.NewTicker(PSITimeIntervalSec * time.Second)
	defer ticker.Stop()

	// Open the statistics file. Truncate it if it exists.
	statFile, err := os.OpenFile(types.MemoryMonitorPSIStatsFile, os.O_CREATE|os.O_RDWR|os.O_SYNC, 0644)
	if err != nil {
		log.Errorf("error opening file: %v", err)
		return fmt.Errorf("error opening file: %v", err)
	}
	defer statFile.Close()

	// Truncate the file
	if err := statFile.Truncate(0); err != nil {
		log.Errorf("error truncating file: %v", err)
		return fmt.Errorf("error truncating file: %v", err)
	}

	// The threshold size is the maximum size of the log file. When the log file reaches this size,
	// it will be truncated. We keep no more than 24 hours of data in the maximum size. It's 8.57MB.
	thresholdSize := StatLineAvgSize * StatLinesPerHour * 24
	// The number of lines to keep in the statistics file. When the file reaches the threshold size,
	// it will be truncated to this number of lines. We keep 23 hours of data, truncating the oldest
	// hour.
	var linesToKeep uint = StatLinesPerHour * 23

	header := PSIHeader + "\n"
	if _, err := statFile.WriteString(header); err != nil {
		log.Errorf("error writing to file: %v", err)
		return fmt.Errorf("error writing to file: %v", err)
	}

	for {
		select {
		case <-ticker.C:
			avgSize, err := ManageStatFileSize(log, statFile, thresholdSize, linesToKeep)
			if err != nil {
				log.Errorf("error managing stat file size: %v", err)
				return err
			}

			// If the returned average size is greater than 0, it means that the file has reached the
			// threshold size, but even if it's truncated to the number of lines to keep, the size is
			// still greater than the threshold size. It may happen if the original estimation of the
			// threshold size was too low. Most probably, it was too low because the estimation of the
			// average size of a line was too small. Now we have a better estimation of the average
			// size of the lines read from the file. We can adjust the threshold size according to this
			// average size, so the truncation is not called every time.
			if avgSize > 0 {
				thresholdSize = avgSize * StatLinesPerHour * 24
			}

			timestamp := time.Now().Format("2006-01-02 15:04:05")
			psiData, err := collectMemoryPSI()
			if err != nil {
				log.Errorf("error collecting PSI data: %v", err)
				return fmt.Errorf("error collecting PSI data: %v", err)
			}

			data := fmt.Sprintf("%s %.02f %.02f %.02f %d %.02f %.02f %0.02f %d\n", timestamp, psiData.SomeAvg10, psiData.SomeAvg60, psiData.SomeAvg300, psiData.SomeTotal, psiData.FullAvg10, psiData.FullAvg60, psiData.FullAvg300, psiData.FullTotal)
			if _, err := statFile.WriteString(data); err != nil {
				log.Errorf("error writing to file: %v", err)
				return fmt.Errorf("error writing to file: %v", err)
			}
		case <-collectorCtx.Done():
			log.Noticef("MemoryPSICollector stopped")
			return nil
		}
	}
}

// ManageStatFileSize manages the size of the stat file by truncating it when it reaches the
// threshold size and keeping only the last linesToKeep lines of statistics (excluding the header).
// log is the logger object.
// statFile is the file to manage.
// thresholdSize is the maximum size of the file.
// linesToKeep is the number of lines of statistics (excluding the header) to keep in the file.
// It returns an error if the file size is still greater than the threshold size after truncating.
// We make it public to be able to test it.
func ManageStatFileSize(log *base.LogObject, statFile *os.File, thresholdSize uint64, linesToKeep uint) (uint64, error) {
	// Check if the args are valid
	// The size of the result file should (we can only approximate) be less than the threshold size
	// Evaluate the minimum possible size of the file
	if uint64(linesToKeep)*StatLineMinSize+uint64(len(PSIHeader)+1) > thresholdSize {
		log.Errorf("linesToKeep is too high for the threshold size\n")
		return 0, fmt.Errorf("linesToKeep is too high for the threshold size")
	}

	// Check the file size
	fileInfo, err := statFile.Stat()
	if err != nil {
		log.Errorf("error getting file info: %v", err)
		return 0, fmt.Errorf("error getting file info: %v", err)
	}

	// If the file size is less than the threshold, do nothing
	// We check here size, not the number of lines to avoid counting the number
	// of lines in the file every time. Size is a good enough approximation.
	if uint64(fileInfo.Size()) < thresholdSize {
		return 0, nil
	}

	// If we reach this point, the file size is greater than the threshold size. We need to truncate
	// the file and keep only the last linesToKeep lines of statistics (excluding the header).

	statRing := ring.New(int(linesToKeep))

	// Set the file pointer to the beginning of the file
	if _, err := statFile.Seek(0, 0); err != nil {
		log.Errorf("error seeking file: %v", err)
		return 0, fmt.Errorf("error seeking file: %v", err)
	}

	// Read the file contents
	scanner := bufio.NewScanner(statFile)
	var linesRead uint64
	for scanner.Scan() {
		statRing.Value = scanner.Text()
		statRing = statRing.Next()
		linesRead++
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("error scanning file: %v", err)
		return 0, fmt.Errorf("error scanning file: %v", err)
	}

	// If the number of lines read is less than the number of lines to keep, it means that the file
	// has reached the threshold size, but has not reached the number of lines to keep. It may happen
	// if the original estimation of the threshold size was too low. Most probably, it was too low
	// because the estimation of the average size of the lines was too small. We return the real
	// average size of the lines read from the file, so the threshold size can be adjusted.
	if linesRead < uint64(linesToKeep) {
		return uint64(fileInfo.Size()) / linesRead, nil
	}

	// If we reach this point, the file has reached the threshold size and has more lines than we
	// want to keep. We need to truncate the file and keep only the last linesToKeep lines of
	// statistics (excluding the header).

	// Truncate the file and write the contents of the ring buffer
	if err := statFile.Truncate(0); err != nil {
		log.Errorf("error truncating file: %v", err)
		return 0, fmt.Errorf("error truncating file: %v", err)
	}
	if _, err := statFile.Seek(0, 0); err != nil {
		log.Errorf("error seeking file: %v", err)
		return 0, fmt.Errorf("error seeking file: %v", err)
	}

	// The file is truncated. So, the header is lost. Write it again.
	if _, err := statFile.WriteString(PSIHeader + "\n"); err != nil {
		log.Errorf("error writing to file: %v", err)
		return 0, fmt.Errorf("error writing to file: %v", err)
	}

	// Write the contents of the ring buffer
	statRing.Do(func(line interface{}) {
		if line != nil {
			if _, err := statFile.WriteString(line.(string) + "\n"); err != nil {
				log.Errorf("error writing to file: %v", err)
			}
		}
	})

	// Check the file size again
	newFileInfo, err := statFile.Stat()
	if err != nil {
		log.Errorf("error getting file info: %v", err)
		return 0, fmt.Errorf("error getting file info: %v", err)
	}
	if uint64(newFileInfo.Size()) > thresholdSize {
		// If the file size is still greater than the threshold size, it means that the threshold size
		// is estimated too low. We return the real average size of the lines read from the file, so
		// the threshold size can be adjusted.
		return uint64(fileInfo.Size()) / linesRead, nil
	}

	return 0, nil
}
