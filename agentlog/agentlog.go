// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package agentlog

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/zboot"
	"os"
	"os/signal"
	"runtime"
	dbg "runtime/debug"
	"syscall"
	"time"
)

func initImpl(agentName string, logdir string, redirect bool,
	text bool) (*os.File, error) {

	logfile := fmt.Sprintf("%s/%s.log", logdir, agentName)
	logf, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND,
		0666)
	if err != nil {
		return nil, err
	}
	if redirect {
		log.SetOutput(logf)
		if text {
			// Report nano timestamps
			formatter := log.TextFormatter{
				TimestampFormat: time.RFC3339Nano,
			}
			log.SetFormatter(&formatter)
		} else {
			// Report nano timestamps
			formatter := log.JSONFormatter{
				TimestampFormat: time.RFC3339Nano,
			}
			log.SetFormatter(&formatter)
		}
		log.RegisterExitHandler(printStack)

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGUSR1)
		signal.Notify(sigs, syscall.SIGUSR2)
		go handleSignals(sigs)
	}
	return logf, nil
}

// Wait on channel then handle the signals
func handleSignals(sigs chan os.Signal) {
	for {
		select {
		case sig := <-sigs:
			log.Infof("handleSignals: received %v\n", sig)
			switch sig {
			case syscall.SIGUSR1:
				log.Warnf("SIGUSR1 triggered stack traces:\n%v\n",
					getStacks(true))
			case syscall.SIGUSR2:
				log.Warnf("SIGUSR2 triggered memory info:\n")
				logMemUsage()
				logGCStats()
			}
		}
	}
}

// Print out our stack
func printStack() {
	log.Error("fatal stack trace:\n%v\n", getStacks(false))
}

func getStacks(all bool) string {
	var (
		buf       []byte
		stackSize int
	)
	bufferLen := 16384
	for stackSize == len(buf) {
		buf = make([]byte, bufferLen)
		stackSize = runtime.Stack(buf, all)
		bufferLen *= 2
	}
	buf = buf[:stackSize]
	return string(buf)
}

func logGCStats() {
	var m dbg.GCStats

	dbg.ReadGCStats(&m)
	log.Infof("GCStats %+v\n", m)
}

func logMemUsage() {
	var m runtime.MemStats

	runtime.ReadMemStats(&m)

	log.Infof("Alloc %v Mb", roundToMb(m.Alloc))
	log.Infof("TotalAlloc %v Mb", roundToMb(m.TotalAlloc))
	log.Infof("Sys %v Mb", roundToMb(m.Sys))
	log.Infof("NumGC %v", m.NumGC)
	log.Infof("MemStats %+v", m)
}

func roundToMb(b uint64) uint64 {

	kb := (b + 1023) / 1024
	mb := (kb + 1023) / 1024
	return mb
}

func Init(agentName string) (*os.File, error) {
	logdir := GetCurrentLogdir()
	return initImpl(agentName, logdir, true, false)
}

func InitWithDirText(agentName string, logdir string) (*os.File, error) {
	return initImpl(agentName, logdir, true, true)
}

// Setup and return a logf, but don't redirect our log.*
func InitChild(agentName string) (*os.File, error) {
	logdir := GetCurrentLogdir()
	return initImpl(agentName, logdir, false, false)
}

const baseLogdir = "/persist"

// Return a logdir for agents and logmanager to use by default
func GetCurrentLogdir() string {
	var partName string
	if !zboot.IsAvailable() {
		partName = "IMGA"
	} else {
		partName = zboot.GetCurrentPartition()
	}
	logdir := fmt.Sprintf("%s/%s/log", baseLogdir, partName)
	return logdir
}

// If the other partition is not inprogress we return the empty string
func GetOtherLogdir() string {
	if !zboot.IsAvailable() {
		return ""
	}
	if !zboot.IsOtherPartitionStateInProgress() {
		return ""
	}
	partName := zboot.GetOtherPartition()
	logdir := fmt.Sprintf("%s/%s/log", baseLogdir, partName)
	return logdir
}

// Touch a file per agentName to signal the event loop is still running
// Could be use by watchdog
func StillRunning(agentName string) {

	log.Debugf("StillRunning(%s)\n", agentName)
	filename := fmt.Sprintf("/var/run/%s.touch", agentName)
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		if err != nil {
			log.Infof("StillRunning: %s\n", err)
			return
		}
		file.Close()
	}
	_, err = os.Stat(filename)
	if err != nil {
		log.Errorf("StilRunning: %s\n", err)
		return
	}
	now := time.Now()
	err = os.Chtimes(filename, now, now)
	if err != nil {
		log.Errorf("StillRunning: %s\n", err)
		return
	}
}
