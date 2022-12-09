// Copyright (c) 2018,2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	dbg "runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	reasonFile     = "reboot-reason"
	stackFile      = "reboot-stack"
	rebootImage    = "reboot-image"
	bootReasonFile = "boot-reason"
	readSize16k    = 16 << 10  // From files in /persist
	readSize512k   = 512 << 10 // Kernel dmesg
)

var savedRebootReason = "unknown"

var onceLock = &sync.Mutex{}
var onceVal bool

// once returns true the first time and then false
func once() bool {
	onceLock.Lock()
	defer onceLock.Unlock()
	if onceVal {
		return false
	} else {
		onceVal = true
		return true
	}
}

// FatalHook is used make sure we save the fatal and panic strings to a file
type FatalHook struct {
	agentName string
	agentPid  int
}

// Fire saves the reason for the logrus.Fatal or logrus.Panic
func (hook *FatalHook) Fire(entry *logrus.Entry) error {
	reason := fmt.Sprintf("fatal: agent %s[%d]: %s", hook.agentName,
		hook.agentPid, entry.Message)
	savedRebootReason = reason
	RebootReason(reason, types.BootReasonFatal, hook.agentName,
		hook.agentPid, false)
	return nil
}

// Levels installs the FatalHook for Fatal and Panic levels
func (hook *FatalHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}

// SourceHook is used to add source and pid if not already set
type SourceHook struct {
	agentName string
	agentPid  int
}

// Fire adds source and pid if not already set
func (hook *SourceHook) Fire(entry *logrus.Entry) error {
	if _, ok := entry.Data["source"]; !ok {
		entry.Data["source"] = hook.agentName
	}
	if _, ok := entry.Data["pid"]; !ok {
		entry.Data["pid"] = hook.agentPid
	}
	return nil
}

// Levels installs the SourceHook for all levels
func (hook *SourceHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// SkipCallerHook is used to skip to the "base" package entry in the stack
type SkipCallerHook struct {
}

// Fire does the skipping
func (hook *SkipCallerHook) Fire(entry *logrus.Entry) error {
	const maximumCallerDepth = 25
	if entry.Caller != nil {
		pcs := make([]uintptr, maximumCallerDepth)
		depth := runtime.Callers(0, pcs)
		frames := runtime.CallersFrames(pcs[:depth])

		next := false
		for f, again := frames.Next(); again; f, again = frames.Next() {
			if f == *entry.Caller {
				pkg := getPackageName(f.Function)
				// XXX should we compare on the whole name?
				if strings.HasSuffix(pkg, "/base") {
					next = true
					continue
				}
				break
			}
			if next {
				entry.Caller = &f
				break
			}
		}
	}
	return nil
}

// getPackageName reduces a fully qualified function name to the package name
// From logrus
func getPackageName(f string) string {
	for {
		lastPeriod := strings.LastIndex(f, ".")
		lastSlash := strings.LastIndex(f, "/")
		if lastPeriod > lastSlash {
			f = f[:lastPeriod]
		} else {
			break
		}
	}

	return f
}

// Levels installs the SkipCallerHook for all levels
func (hook *SkipCallerHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Wait on channel then handle the signals
func handleSignals(log *base.LogObject, agentName string, agentPid int, sigs chan os.Signal) {
	agentDebugDir := fmt.Sprintf("%s/%s/", types.PersistDebugDir, agentName)
	sigUsr1FileName := agentDebugDir + "/sigusr1"
	sigUsr2FileName := agentDebugDir + "/sigusr2"

	for {
		select {
		case sig := <-sigs:
			log.Functionf("handleSignals: received %v\n", sig)
			switch sig {
			case syscall.SIGUSR1:
				stacks := getStacks(true)
				stackArray := strings.Split(stacks, "\n\n")

				sigUsr1File, err := os.OpenFile(sigUsr1FileName,
					os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
				if err == nil {
					for _, stack := range stackArray {
						// This goes to /persist/agentdebug/<agentname>/sigusr1 file
						sigUsr1File.WriteString(stack + "\n\n")
					}
					sigUsr1File.Close()
				} else {
					log.Errorf("handleSignals: Error opening file %s with: %s", sigUsr1FileName, err)
				}

				usr1LogObject := base.EnsureLogObject(log, base.SigUSR1StacksType,
					"", uuid.UUID{}, string(base.SigUSR1StacksType))
				if usr1LogObject != nil {
					log.Warnf("SIGUSR1 triggered with %d stacks", len(stackArray))
					for _, stack := range stackArray {
						usr1LogObject.Warnf("%v", stack)
					}
					log.Warnf("SIGUSR1: end of stacks")
				}
			case syscall.SIGUSR2:
				log.Warnf("SIGUSR2 triggered memory info:\n")
				sigUsr2File, err := os.OpenFile(sigUsr2FileName,
					os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
				if err != nil {
					log.Errorf("handleSignals: Error opening file %s with: %s", sigUsr2FileName, err)
				} else {
					// This goes to /persist/agentdebug/<agentname>/sigusr2 file
					sigUsr2File.WriteString("SIGUSR2 triggered memory info:\n")
				}

				logMemUsage(log, sigUsr2File)
				logMemAllocationSites(log, sigUsr2File)
				if sigUsr2File != nil {
					sigUsr2File.Close()
				}
			}
		}
	}
}

// DumpAllStacks writes to file but does not log
func DumpAllStacks(log *base.LogObject, agentName string) {
	agentDebugDir := fmt.Sprintf("%s/%s/", types.PersistDebugDir, agentName)
	sigUsr1FileName := agentDebugDir + "/sigusr1"

	stacks := getStacks(true)
	stackArray := strings.Split(stacks, "\n\n")

	sigUsr1File, err := os.OpenFile(sigUsr1FileName,
		os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
	if err == nil {
		for _, stack := range stackArray {
			// This goes to /persist/agentdebug/<agentname>/sigusr1 file
			sigUsr1File.WriteString(stack + "\n\n")
		}
		sigUsr1File.Close()
		log.Noticef("DumpAllStacks: Wrote file %s",
			sigUsr1FileName)
	} else {
		log.Errorf("DumpAllStacks: Error opening file %s with: %s",
			sigUsr1FileName, err)
	}
}

// PrintStacks - for newlogd log init
func PrintStacks(log *base.LogObject) {
	stacks := getStacks(false)
	stackArray := strings.Split(stacks, "\n\n")
	log.Errorf("Fatal stack trace due to %s with %d stack traces", savedRebootReason, len(stackArray))
	for _, stack := range stackArray {
		log.Errorf("%v", stack)
	}
}

// Print out our stack
func printStack(log *base.LogObject, agentName string, agentPid int) {
	stacks := getStacks(false)
	stackArray := strings.Split(stacks, "\n\n")
	fatalLogObject := base.EnsureLogObject(log, base.FatalStacksType,
		"", uuid.UUID{}, string(base.FatalStacksType))
	if fatalLogObject != nil {
		log.Errorf("Fatal stack trace due to %s with %d stack traces",
			savedRebootReason, len(stackArray))
		for _, stack := range stackArray {
			fatalLogObject.Warnf("%v", stack)
		}
		log.Errorf("Fatal: end of stacks")
	}
	RebootStack(log, stacks, agentName, agentPid)
}

// RebootReason writes a reason string in /persist/reboot-reason, including agentName and date
// It also appends to /persist/log/reboot-reason.log
// If the bootReasonFile is not present it will write the bootReason enum
// there as a string. That ensures that if we have a e.g., a log.Fatal followed
// by watchdog we retain the fatal.
// NOTE: can not use log here since we are called from a log hook!
func RebootReason(reason string, bootReason types.BootReason, agentName string,
	agentPid int, normal bool) {

	filename := fmt.Sprintf("%s/%s", types.PersistDir, reasonFile)
	dateStr := time.Now().Format(time.RFC3339Nano)
	if !normal {
		reason = fmt.Sprintf("Reboot from agent %s[%d] in partition %s at EVE version %s at %s: %s\n",
			agentName, agentPid, EveCurrentPartition(), EveVersion(), dateStr, reason)
	} else {
		reason = fmt.Sprintf("%s at EVE version %s at %s\n",
			reason, EveVersion(), dateStr)
	}
	// If we already wrote a bootReason file we append to
	// the rebootReason file otherwise we truncate and write.
	_, err := os.Stat("/persist/" + bootReasonFile)
	if err != nil {
		// Already failed; append subsequent info to rebootReason
		err = printToFile(filename, reason)
		if err != nil {
			// Note: can not use log here since we are called from a log hook!
			fmt.Printf("printToFile failed %s\n", err)
		}
	} else {
		// First call hence a new failure
		err = overWriteFile(filename, reason)
		if err != nil {
			// Note: can not use log here since we are called from a log hook!
			fmt.Printf("overWriteFile failed %s\n", err)
		}
	}
	// Append to the log file
	filename = "/persist/log/" + reasonFile + ".log"
	err = printToFile(filename, reason)
	if err != nil {
		// Note: can not use log here since we are called from a log hook!
		fmt.Printf("printToFile failed %s\n", err)
	}

	// Printing the reboot reason to the console
	filename = "/dev/console"

	operation := "Rebooting"
	if bootReason == types.BootReasonPoweroffCmd {
		operation = "Power off"
	}
	err = printToFile(filename, fmt.Sprintf("%s EVE. Reason: %s", operation, reason))

	if err != nil {
		// Note: can not use log here since we are called from a log hook!
		fmt.Printf("printToFile failed %s\n", err)
	}
	if !normal {
		agentDebugDir := fmt.Sprintf("%s/%s/", types.PersistDebugDir,
			agentName)

		agentFatalReasonFilename := agentDebugDir + "/fatal-reason"
		err = overWriteFile(agentFatalReasonFilename, reason)
		if err != nil {
			// Note: can not use log here since we are called from a log hook!
			fmt.Printf("overWriteFile failed %s\n", err)
		}
	}

	filename = "/persist/" + rebootImage
	curPart := EveCurrentPartition()
	err = overWriteFile(filename, curPart)
	if err != nil {
		// Note: can not use log here since we are called from a log hook!
		fmt.Printf("overWriteFile failed %s\n", err)
	}
	syscall.Sync()

	if bootReason != types.BootReasonNone {
		filename = "/persist/" + bootReasonFile
		brString := bootReason.String()
		b, _ := fileutils.ReadWithMaxSize(nil, filename, readSize16k)
		if len(b) != 0 {
			// Note: can not use log here since we are called from a log hook!
			fmt.Printf("not replacing BootReason %s with %s\n",
				string(b), brString)
		} else {
			err = overWriteFile(filename, brString)
			if err != nil {
				// Note: can not use log here since we are called from a log hook!
				fmt.Printf("overwriteFile failed %s\n", err)
			}
		}
	}
}

// RebootStack writes stack in /persist/reboot-stack
// and appends to /persist/log/reboot-stack.log
// XXX remove latter? Can grow unbounded.
func RebootStack(log *base.LogObject, stacks string, agentName string, agentPid int) {
	filename := fmt.Sprintf("%s/%s", types.PersistDir, stackFile)
	log.Warnf("RebootStack to %s", filename)
	err := overWriteFile(filename, fmt.Sprintf("%v\n", stacks))
	if err != nil {
		log.Errorf("overWriteFile failed %s\n", err)
	}
	filename = "/persist/log/" + stackFile + ".log"
	err = printToFile(filename, fmt.Sprintf("%v\n", stacks))
	if err != nil {
		log.Errorf("printToFile failed %s\n", err)
	}
	agentDebugDir := fmt.Sprintf("%s/%s/", types.PersistDebugDir, agentName)
	agentStackTraceFile := agentDebugDir + "/fatal-stack"
	err = overWriteFile(agentStackTraceFile, fmt.Sprintf("%v\n", stacks))
	if err != nil {
		log.Errorf("overWriteFile failed %s\n", err)
	}
	syscall.Sync()
}

// GetRebootReason returns the RebootReason string together with
// its timestamp plus the reboot stack. We limit the size we read
// to 16k for the RebootReason and to 512k for the stack, because
// in case of a kernel crash, the stack file contains the whole
// dmesg, which kernel buffer is limited to some reasonable value
// below 512k.
func GetRebootReason(log *base.LogObject) (string, time.Time, string) {
	reasonFilename := fmt.Sprintf("%s/%s", types.PersistDir, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", types.PersistDir, stackFile)
	reason, ts, _ := fileutils.StatAndRead(log, reasonFilename, readSize16k)
	stack, _, _ := fileutils.StatAndRead(log, stackFilename, readSize512k)
	return reason, ts, stack
}

// GetBootReason returns the BootReason enum, which is stored as a string in /persist, together with its timestamp
func GetBootReason(log *base.LogObject) (types.BootReason, time.Time) {
	reasonFilename := fmt.Sprintf("%s/%s", types.PersistDir, bootReasonFile)
	reason, ts, _ := fileutils.StatAndRead(log, reasonFilename, readSize16k)
	return types.BootReasonFromString(reason), ts
}

// GetRebootImage : Image from which the reboot happened
func GetRebootImage(log *base.LogObject) string {
	rebootFilename := fmt.Sprintf("%s/%s", types.PersistDir, rebootImage)
	image, _, _ := fileutils.StatAndRead(log, rebootFilename, readSize16k)
	return image
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

// Overwrite if file exists.
func overWriteFile(filename string, str string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
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

// DiscardRebootReason removes any reason and stack from /persist/
func DiscardRebootReason(log *base.LogObject) {
	reasonFilename := fmt.Sprintf("%s/%s", types.PersistDir, reasonFile)
	stackFilename := fmt.Sprintf("%s/%s", types.PersistDir, stackFile)
	if err := os.Remove(reasonFilename); err != nil {
		log.Errorf("DiscardRebootReason failed %s\n", err)
	}
	_, err := os.Stat(stackFilename)
	if err == nil {
		if err := os.Remove(stackFilename); err != nil {
			log.Errorf("DiscardRebootReason failed %s\n", err)
		}
	}
}

// DiscardBootReason removes the BootReason file
func DiscardBootReason(log *base.LogObject) {
	reasonFilename := fmt.Sprintf("%s/%s", types.PersistDir, bootReasonFile)
	if err := os.Remove(reasonFilename); err != nil {
		// Might not have existed
		log.Warnf("DiscardBootReason failed %s\n", err)
	}
}

// DiscardRebootImage : Discard the last reboot-image file
func DiscardRebootImage(log *base.LogObject) {
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

// GetMyStack is used to log stack traces at certain call sites
// Excludes ourselves
func GetMyStack() string {
	var output string
	const maximumCallerDepth = 25
	pcs := make([]uintptr, maximumCallerDepth)
	depth := runtime.Callers(0, pcs)
	frames := runtime.CallersFrames(pcs[:depth])

	output += "goroutine:\n"
	for f, again := frames.Next(); again; f, again = frames.Next() {
		// Exclude the top and bottom ones
		if strings.HasSuffix(f.Function, "runtime.Callers") ||
			strings.HasSuffix(f.Function, "runtime.main") {
			continue
		}
		// Exclude myself
		if strings.HasSuffix(f.Function, "agentlog.GetMyStack") {
			continue
		}
		output += fmt.Sprintf("%s()\n\t%s:%d\n", f.Function, f.File, f.Line)
	}
	return output
}

func logGCStats(log *base.LogObject) {
	var m dbg.GCStats

	dbg.ReadGCStats(&m)
	log.Functionf("GCStats %+v\n", m)
}

// Print in sorted order based on top bytes
func logMemAllocationSites(log *base.LogObject, file *os.File) {
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

		if file != nil {
			// This goes to /persist/agentdebug/<agentname>/sigusr2 file
			// And there in not much difference from the above log except the CRNL at the end.
			statString := fmt.Sprintf("alloc %d bytes %d objects total %d/%d at:\n%s\n",
				site.InUseBytes, site.InUseObjects, site.AllocBytes,
				site.AllocObjects, site.PrintedStack)
			file.WriteString(statString)
		}
	}
}

func logMemUsage(log *base.LogObject, file *os.File) {
	var m runtime.MemStats

	runtime.ReadMemStats(&m)
	log.Functionf("Alloc %d Mb, TotalAlloc %d Mb, Sys %d Mb, NumGC %d",
		roundToMb(m.Alloc), roundToMb(m.TotalAlloc), roundToMb(m.Sys), m.NumGC)

	if file != nil {
		// This goes to /persist/agentdebug/<agentname>/sigusr2 file
		// And there in not much difference from the above log except the CRNL at the end.
		statString := fmt.Sprintf("Alloc %d Mb, TotalAlloc %d Mb, Sys %d Mb, NumGC %d\n",
			roundToMb(m.Alloc), roundToMb(m.TotalAlloc), roundToMb(m.Sys), m.NumGC)
		file.WriteString(statString)
	}
}

func roundToMb(b uint64) uint64 {

	kb := (b + 512) / 1024
	mb := (kb + 512) / 1024
	return mb
}

func spoofStdFDs(log *base.LogObject, agentName string) *os.File {
	agentDebugDir := fmt.Sprintf("%s/%s/", types.PersistDebugDir, agentName)
	if _, err := os.Stat(agentDebugDir); os.IsNotExist(err) {
		// Create the agent specific debug directory
		if err := os.MkdirAll(agentDebugDir, 0755); err != nil {
			log.Fatalf("spoofStdFDs: Agent specific debug directory (%s) does not exist: %s",
				agentDebugDir, err)
		}
	}
	startTimeFile := agentDebugDir + "/starttime"
	base.TouchFile(log, startTimeFile)

	stdOutFile := agentDebugDir + "/stdout"
	stdOut, err := os.OpenFile(stdOutFile, os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0755)
	if err != nil {
		log.Fatalf("spoofStdFDs: Failed opening stdout file %s with err: %s", stdOutFile, err)
	}

	fd2, err := syscall.Dup(syscall.Stdout)
	if err != nil {
		log.Fatalf("spoofStdFDs: Error duplicating Stdout: %s", err)
	}
	originalStdout := os.NewFile(uintptr(fd2), "originalStdout")
	if originalStdout == nil {
		log.Fatalf("spoofStdFDs: Error opening duplicate stdout with fd: %v", fd2)
	}
	// replace stdout
	err = syscall.Dup3(int(stdOut.Fd()), 1, 0)
	if err != nil {
		log.Fatalf("spoofStdFDs: Error replacing stdout with panic file %s: %s",
			stdOutFile, err)
	}
	return originalStdout
}

// Init provides both a logger and a logObject
func Init(agentName string) (*logrus.Logger, *base.LogObject) {
	return initImpl(agentName, true)
}

// InitNoRedirect provides both a logger and a logObject; does not redirect stdout
func InitNoRedirect(agentName string) (*logrus.Logger, *base.LogObject) {
	return initImpl(agentName, false)
}

func initImpl(agentName string, redirect bool) (*logrus.Logger, *base.LogObject) {
	agentPid := os.Getpid()
	logger := logrus.New()
	// Report nano timestamps
	formatter := logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	logger.SetFormatter(&formatter)
	logger.SetReportCaller(true)
	log := base.NewSourceLogObject(logger, agentName, agentPid)

	fatalHook := new(FatalHook)
	fatalHook.agentName = agentName
	fatalHook.agentPid = agentPid
	logger.AddHook(fatalHook)

	sourceHook := new(SourceHook)
	sourceHook.agentName = agentName
	sourceHook.agentPid = agentPid
	logger.AddHook(sourceHook)

	skipHook := new(SkipCallerHook)
	logger.AddHook(skipHook)
	// For every separate process we set up output redirection
	// to /persist/agentdebug (while keeping logs on stdout) and
	// signal handlers
	if once() {
		if redirect {
			originalStdout := spoofStdFDs(log, agentName)
			logger.SetOutput(originalStdout)
			logrus.SetOutput(originalStdout)
		}

		// XXX Some code such as containerd and hypervisor still use
		// logrus directly. Set up the formatter and hooks for them
		// to point at zedbox as agentname
		logrus.SetFormatter(&formatter)
		logrus.SetReportCaller(true)
		logrus.AddHook(fatalHook)
		logrus.AddHook(sourceHook)
		logrus.AddHook(skipHook)

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGUSR1)
		signal.Notify(sigs, syscall.SIGUSR2)
		log.Functionf("Creating %s at %s", "handleSignals", GetMyStack())
		go handleSignals(log, agentName, agentPid, sigs)
		eh := func() { printStack(log, agentName, agentPid) }
		logrus.RegisterExitHandler(eh)
	}
	return logger, log
}

// CustomLogInit - allow pillar services and containers to use customized logging
func CustomLogInit(level logrus.Level) *logrus.Logger {
	logger := logrus.New()
	formatter := logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	logger.SetFormatter(&formatter)
	logger.SetLevel(level)
	return logger
}
