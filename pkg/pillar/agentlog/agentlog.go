// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	dbg "runtime/debug"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
)

const (
	persistDir = "/persist"
	reasonFile = "reboot-reason"
	stackFile  = "reboot-stack"
)

var savedAgentName string = "unknown" // Keep for signal and exit handlers

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
		log.SetReportCaller(true)
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
	stacks := getStacks(false)
	log.Errorf("fatal stack trace:\n%v\n", stacks)
	RebootReason(fmt.Sprintf("fatal: agent %s exit", savedAgentName))
	RebootStack(stacks)
}

// RebootReason writes a reason string in /persist/IMGx/reboot-reason, including agentName and date
func RebootReason(reason string) {
	filename := fmt.Sprintf("%s/%s", getCurrentIMGdir(), reasonFile)
	log.Warnf("RebootReason to %s: %s\n", filename, reason)
	dateStr := time.Now().Format(time.RFC3339Nano)
	err := printToFile(filename, fmt.Sprintf("Reboot from agent %s at %s: %s\n",
		savedAgentName, dateStr, reason))
	if err != nil {
		log.Errorf("printToFile failed %s\n", err)
	}
	syscall.Sync()
}

// RebootStack writes stack in /persist/IMGx/reboot-stack
func RebootStack(stacks string) {
	filename := fmt.Sprintf("%s/%s", getCurrentIMGdir(), stackFile)
	log.Warnf("RebootStack to %s", filename)
	err := printToFile(filename, fmt.Sprintf("%v\n", stacks))
	if err != nil {
		log.Errorf("printToFile failed %s\n", err)
	}
	syscall.Sync()
}

func GetCurrentRebootReason() (string, time.Time, string) {
	reasonFilename := fmt.Sprintf("%s/%s", getCurrentIMGdir(), reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", getCurrentIMGdir(), stackFile)
	reason, ts := statAndRead(reasonFilename)
	stack, _ := statAndRead(stackFilename)
	return reason, ts, stack
}

func GetOtherRebootReason() (string, time.Time, string) {
	dirname := getOtherIMGdir(false)
	if dirname == "" {
		return "", time.Time{}, ""
	}
	reasonFilename := fmt.Sprintf("%s/%s", dirname, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", dirname, stackFile)
	reason, ts := statAndRead(reasonFilename)
	stack, _ := statAndRead(stackFilename)
	return reason, ts, stack
}

// Used for failures/hangs when zboot curpart hangs
func GetCommonRebootReason() (string, time.Time, string) {
	reasonFilename := fmt.Sprintf("%s/%s", persistDir, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", persistDir, stackFile)
	reason, ts := statAndRead(reasonFilename)
	stack, _ := statAndRead(stackFilename)
	return reason, ts, stack
}

// Returns content and Modtime
func statAndRead(filename string) (string, time.Time) {
	fi, err := os.Stat(filename)
	if err != nil {
		// File doesn't exist
		return "", time.Time{}
	}
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Errorf("statAndRead failed %s", err)
		return "", fi.ModTime()
	}
	return string(content), fi.ModTime()
}

// Append if file exists.
func printToFile(filename string, str string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE,
		os.ModeAppend)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(str)
	if err != nil {
		return err
	}
	return nil
}

func DiscardCurrentRebootReason() {
	reasonFilename := fmt.Sprintf("%s/%s", getCurrentIMGdir(), reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", getCurrentIMGdir(), stackFile)
	if err := os.Remove(reasonFilename); err != nil {
		log.Errorf("DiscardCurrentRebootReason failed %s\n", err)
	}
	if err := os.Remove(stackFilename); err != nil {
		log.Errorf("DiscardCurrentRebootReason failed %s\n", err)
	}
}

func DiscardOtherRebootReason() {
	dirname := getOtherIMGdir(false)
	if dirname == "" {
		return
	}
	reasonFilename := fmt.Sprintf("%s/%s", dirname, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", dirname, stackFile)
	if err := os.Remove(reasonFilename); err != nil {
		log.Errorf("DiscardOtherRebootReason failed %s\n", err)
	}
	if err := os.Remove(stackFilename); err != nil {
		log.Errorf("DiscardOtherRebootReason failed %s\n", err)
	}
}

func DiscardCommonRebootReason() {
	reasonFilename := fmt.Sprintf("%s/%s", persistDir, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", persistDir, stackFile)
	if err := os.Remove(reasonFilename); err != nil {
		log.Errorf("DiscardCommonRebootReason failed %s\n", err)
	}
	if err := os.Remove(stackFilename); err != nil {
		log.Errorf("DiscardCommonRebootReason failed %s\n", err)
	}
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

	kb := (b + 512) / 1024
	mb := (kb + 512) / 1024
	return mb
}

func Init(agentName string, curpart string) (*os.File, error) {
	if curpart != "" {
		zboot.SetCurpart(curpart)
	}
	logdir := GetCurrentLogdir()
	savedAgentName = agentName
	return initImpl(agentName, logdir, true, false)
}

func InitWithDirText(agentName string, logdir string, curpart string) (*os.File, error) {
	if curpart != "" {
		zboot.SetCurpart(curpart)
	}
	savedAgentName = agentName
	return initImpl(agentName, logdir, true, true)
}

// Setup and return a logf, but don't redirect our log.*
func InitChild(agentName string) (*os.File, error) {
	logdir := GetCurrentLogdir()
	return initImpl(agentName, logdir, false, false)
}

var currentIMGdir = ""

func getCurrentIMGdir() string {

	if currentIMGdir != "" {
		return currentIMGdir
	}
	partName := zboot.GetCurrentPartition()
	currentIMGdir = fmt.Sprintf("%s/%s", persistDir, partName)
	return currentIMGdir
}

var otherIMGdir = ""

func getOtherIMGdir(inprogressCheck bool) string {

	if otherIMGdir != "" {
		return otherIMGdir
	}
	if inprogressCheck && !zboot.IsOtherPartitionStateInProgress() {
		return ""
	}
	partName := zboot.GetOtherPartition()
	otherIMGdir = fmt.Sprintf("%s/%s", persistDir, partName)
	return otherIMGdir
}

// Return a logdir for agents and logmanager to use by default
func GetCurrentLogdir() string {
	return fmt.Sprintf("%s/log", getCurrentIMGdir())
}

// If the other partition is not inprogress we return the empty string
func GetOtherLogdir() string {
	dirname := getOtherIMGdir(true)
	if dirname == "" {
		return ""
	}
	return fmt.Sprintf("%s/log", dirname)
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
