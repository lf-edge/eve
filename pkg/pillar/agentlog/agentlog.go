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
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
)

const (
	reasonFile  = "reboot-reason"
	stackFile   = "reboot-stack"
	rebootImage = "reboot-image"
)

var savedAgentName = "unknown" // Keep for signal and exit handlers
var savedRebootReason = "unknown"
var savedPid = 0

// Parameter description
// 1. agentName: Name with which disk log file will be created.
// 2. logdir: Directory in which disk log file will be placed.
func initImpl(agentName string, logdir string) error {
	log.SetOutput(os.Stdout)
	hook := new(FatalHook)
	log.AddHook(hook)
	hook2 := new(SourceHook)
	log.AddHook(hook2)
	// Report nano timestamps
	formatter := log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	log.SetFormatter(&formatter)
	log.SetReportCaller(true)
	log.RegisterExitHandler(printStack)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	signal.Notify(sigs, syscall.SIGUSR2)
	go handleSignals(sigs)
	return nil
}

// FatalHook is used make sure we save the fatal and panic strings to a file
type FatalHook struct {
}

// Fire saves the reason for the log.Fatal or log.Panic
func (hook *FatalHook) Fire(entry *log.Entry) error {
	reason := fmt.Sprintf("fatal: agent %s[%d]: %s", savedAgentName, savedPid, entry.Message)
	savedRebootReason = reason
	RebootReason(reason, false)
	return nil
}

// Levels installs the FatalHook for Fatal and Panic levels
func (hook *FatalHook) Levels() []log.Level {
	return []log.Level{
		log.FatalLevel,
		log.PanicLevel,
	}
}

// SourceHook is used to add source=agentName
type SourceHook struct {
}

// Fire adds source=agentName
func (hook *SourceHook) Fire(entry *log.Entry) error {
	entry.Data["source"] = savedAgentName
	entry.Data["pid"] = savedPid
	return nil
}

// Levels installs the SourceHook for all levels
func (hook *SourceHook) Levels() []log.Level {
	return log.AllLevels
}

// Wait on channel then handle the signals
func handleSignals(sigs chan os.Signal) {
	for {
		select {
		case sig := <-sigs:
			log.Infof("handleSignals: received %v\n", sig)
			switch sig {
			case syscall.SIGUSR1:
				stacks := getStacks(true)
				stackArray := strings.Split(stacks, "\n\n")
				log.Warnf("SIGUSR1 triggered with %d stacks", len(stackArray))
				for _, stack := range stackArray {
					log.Warnf("%v", stack)
				}
				log.Warnf("SIGUSR1: end of stacks")
				// Could result in a watchdog reboot hence
				// we save it as a reboot-stack
				RebootStack(stacks)
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
	stackArray := strings.Split(stacks, "\n\n")
	log.Errorf("Fatal stack trace due to %s with %d stack traces", savedRebootReason, len(stackArray))
	for _, stack := range stackArray {
		log.Errorf("%v", stack)
	}
	log.Errorf("Fatal: end of stacks")
	RebootReason(fmt.Sprintf("fatal: agent %s[%d] exit", savedAgentName, savedPid),
		false)
	RebootStack(stacks)
}

// RebootReason writes a reason string in /persist/reboot-reason, including agentName and date
// It also appends to /persist/log/reboot-reason.log
// NOTE: can not use log here since we are called from a log hook!
func RebootReason(reason string, normal bool) {
	// NOTE: can not use log here since we are called from a log hook!
	fmt.Printf("RebootReason(%s)", reason)
	filename := fmt.Sprintf("%s/%s", types.PersistDir, reasonFile)
	dateStr := time.Now().Format(time.RFC3339Nano)
	if !normal {
		reason = fmt.Sprintf("Reboot from agent %s[%d] in partition %s EVE version %s at %s: %s\n",
			savedAgentName, savedPid, zboot.GetCurrentPartition(), EveVersion(), dateStr, reason)
	}
	err := printToFile(filename, reason)
	if err != nil {
		// Note: can not use log here since we are called from a log hook!
		fmt.Printf("printToFile failed %s\n", err)
	}
	filename = "/persist/log/" + reasonFile + ".log"
	err = printToFile(filename, reason)
	if err != nil {
		// Note: can not use log here since we are called from a log hook!
		fmt.Printf("printToFile failed %s\n", err)
	}
	filename = "/persist/" + rebootImage
	curPart := zboot.GetCurrentPartition()
	err = printToFile(filename, curPart)
	if err != nil {
		// Note: can not use log here since we are called from a log hook!
		fmt.Printf("printToFile failed %s\n", err)
	}
	syscall.Sync()
}

// RebootStack writes stack in /persist/reboot-stack
// and appends to /persist/log/reboot-stack.log
func RebootStack(stacks string) {
	filename := fmt.Sprintf("%s/%s", types.PersistDir, stackFile)
	log.Warnf("RebootStack to %s", filename)
	err := printToFile(filename, fmt.Sprintf("%v\n", stacks))
	if err != nil {
		log.Errorf("printToFile failed %s\n", err)
	}
	filename = "/persist/log/" + stackFile + ".log"
	err = printToFile(filename, fmt.Sprintf("%v\n", stacks))
	if err != nil {
		log.Errorf("printToFile failed %s\n", err)
	}
	syscall.Sync()
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
	reasonFilename := fmt.Sprintf("%s/%s", types.PersistDir, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", types.PersistDir, stackFile)
	reason, ts := statAndRead(reasonFilename)
	stack, _ := statAndRead(stackFilename)
	return reason, ts, stack
}

// GetRebootImage : Image from which the reboot happened
func GetRebootImage() string {
	rebootFilename := fmt.Sprintf("%s/%s", types.PersistDir, rebootImage)
	image, _ := statAndRead(rebootFilename)
	return image
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
	_, err := os.Stat(stackFilename)
	if err != nil {
		if err := os.Remove(stackFilename); err != nil {
			log.Errorf("DiscardOtherRebootReason failed %s\n", err)
		}
	}
}

func DiscardCommonRebootReason() {
	reasonFilename := fmt.Sprintf("%s/%s", types.PersistDir, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", types.PersistDir, stackFile)
	if err := os.Remove(reasonFilename); err != nil {
		log.Errorf("DiscardCommonRebootReason failed %s\n", err)
	}
	_, err := os.Stat(stackFilename)
	if err != nil {
		if err := os.Remove(stackFilename); err != nil {
			log.Errorf("DiscardCommonRebootReason failed %s\n", err)
		}
	}
}

// DiscardRebootImage : Discard the last reboot-image file
func DiscardRebootImage() {
	rebootFilename := fmt.Sprintf("%s/%s", types.PersistDir, rebootImage)
	if err := os.Remove(rebootFilename); err != nil {
		log.Errorf("DiscardRebootImage failed %s\n", err)
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

// LogMemoryUsage provides for user-triggered memory reports
func LogMemoryUsage() {
	log.Info("User-triggered memory report")
	logMemUsage()
	logGCStats()
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

func Init(agentName string, curpart string) error {
	if curpart != "" {
		zboot.SetCurpart(curpart)
	}
	logdir := GetCurrentLogdir()
	savedAgentName = agentName
	savedPid = os.Getpid()
	return initImpl(agentName, logdir)
}

var currentIMGdir = ""

func getCurrentIMGdir() string {

	if currentIMGdir != "" {
		return currentIMGdir
	}
	partName := zboot.GetCurrentPartition()
	currentIMGdir = fmt.Sprintf("%s/%s", types.PersistDir, partName)
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
	otherIMGdir = fmt.Sprintf("%s/%s", types.PersistDir, partName)
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

// Debug info to tell how often/late we call stillRunning; keyed by agentName
var lastStillMap = make(map[string]time.Time)

// Touch a file per agentName to signal the event loop is still running
// Could be use by watchdog
func StillRunning(agentName string, warnTime time.Duration, errTime time.Duration) {
	log.Debugf("StillRunning(%s)\n", agentName)

	if ls, found := lastStillMap[agentName]; !found {
		lastStillMap[agentName] = time.Now()
	} else {
		elapsed := time.Since(ls)
		if elapsed > errTime {
			log.Errorf("StillRunning(%s) XXX took a long time: %d",
				agentName, elapsed/time.Second)
		} else if elapsed > warnTime {
			log.Warnf("StillRunning(%s) took a long time: %d",
				agentName, elapsed/time.Second)
		}
		lastStillMap[agentName] = time.Now()
	}

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
