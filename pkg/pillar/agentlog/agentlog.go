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
	"sort"
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
	panicOutput = "panic-output"
)

var savedAgentName = "unknown" // Keep for signal and exit handlers
var savedRebootReason = "unknown"
var savedPid = 0

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
				logMemAllocationSites()
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
			savedAgentName, savedPid, EveCurrentPartition(), EveVersion(), dateStr, reason)
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
	curPart := EveCurrentPartition()
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

// GetPanicTrace : Get any traces that services might have left before the last reboot
func GetPanicTrace() (string, time.Time) {
	panicFileName := fmt.Sprintf("%s/%s", types.PersistDir, panicOutput)
	panicTrace, ts := statAndRead(panicFileName)
	return panicTrace, ts
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
	if err == nil {
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
	if err == nil {
		if err := os.Remove(stackFilename); err != nil {
			log.Errorf("DiscardCommonRebootReason failed %s\n", err)
		}
	}
}

// DiscardPanicTrace : Discard after reading any panic traces
func DiscardPanicTrace() {
	panicFilename := fmt.Sprintf("%s/%s", types.PersistDir, panicOutput)
	_, err := os.Stat(panicFilename)
	if err == nil {
		if err := os.Remove(panicFilename); err != nil {
			log.Errorf("DiscardPanicTrace failed %s\n", err)
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

// Print in sorted order based on top bytes
func logMemAllocationSites() {
	reportZeroInUse := false
	numSites, sites := GetMemAllocationSites(reportZeroInUse)
	log.Warnf("alloc %d sites len %d", numSites, len(sites))
	sort.Slice(sites,
		func(i, j int) bool {
			return sites[i].InUseBytes > sites[j].InUseBytes ||
				(sites[i].InUseBytes == sites[j].InUseBytes &&
					sites[i].AllocBytes > sites[j].AllocBytes)
		})
	for _, site := range sites {
		log.Warnf("alloc %d bytes %d objects total %d/%d at:\n%s",
			site.InUseBytes, site.InUseObjects, site.AllocBytes,
			site.AllocObjects, site.PrintedStack)
	}
}

// LogMemoryUsage provides for user-triggered memory reports
func LogMemoryUsage() {
	log.Info("User-triggered memory report")
	logMemUsage()
	logMemAllocationSites()
}

func logMemUsage() {
	var m runtime.MemStats

	runtime.ReadMemStats(&m)
	log.Infof("Alloc %d Mb, TotalAlloc %d Mb, Sys %d Mb, NumGC %d",
		roundToMb(m.Alloc), roundToMb(m.TotalAlloc), roundToMb(m.Sys), m.NumGC)
}

func roundToMb(b uint64) uint64 {

	kb := (b + 512) / 1024
	mb := (kb + 512) / 1024
	return mb
}

// Send application stdout/stderr to this panic file
func spoofStdFDs(panicFileName string) *os.File {
	filename := fmt.Sprintf("%s/%s", types.PersistDir, panicFileName)
	panicOut, _ := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_APPEND, 0755)
	fd2, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		log.Fatalf("Error duplicating Stdout: %s", err)
	}
	originalStdout, err := os.OpenFile(fmt.Sprintf("/dev/fd/%d", fd2),
		os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0755)
	if err != nil {
		log.Fatalf("Error opening duplicate stdout with fd: %v", fd2)
	}
	// replace stdout
	err = syscall.Dup2(int(panicOut.Fd()), 1)
	if err != nil {
		log.Fatalf("Error replacing stdout with panic file %s: %s",
			filename, err)
	}
	err = syscall.Dup2(int(panicOut.Fd()), 2)
	if err != nil {
		log.Fatalf("Error replacing stderr with panic file %s: %s",
			filename, err)
	}
	return originalStdout
}

func Init(agentName string) {
	savedAgentName = agentName
	savedPid = os.Getpid()
	originalStdout := spoofStdFDs(panicOutput)
	log.SetOutput(originalStdout)
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
