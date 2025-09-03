// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package agentlog_test checks the logging
package agentlog_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultAgent    = "zedbox"
	agentName       = "myAgent"
	subscriberAgent = "subscriberAgent"
	publisherAgent  = "publisherAgent"
)

// Really a constant
var nilUUID = uuid.UUID{}

const myLogType = "mylogtype"

type Item struct {
	AString string
	ID      string
}

// Key for pubsub
func (status Item) Key() string {
	return status.ID
}

// LogCreate :
func (status Item) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, myLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("a-string", status.AString).
		Noticef("Item create")
}

// LogModify :
func (status Item) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, myLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(Item)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of Item type")
	}
	if oldStatus.AString != status.AString {
		logObject.CloneAndAddField("a-string", status.AString).
			AddField("old-a-string", oldStatus.AString).
			Noticef("Item modify")
	} else {
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Item modify other change")
	}
}

// LogDelete :
func (status Item) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, myLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("a-string", status.AString).
		Noticef("Item delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status Item) LogKey() string {
	return myLogType + "-" + status.Key()
}

var (
	item = Item{
		AString: "aString",
		ID:      "myID",
	}
)

// TestPubsubLog verifies some agentlog+pubsub operations
// TBD add assertions on what is logged in terms of "source"
// This test only works if /persist and /run are writable
func TestPubsubLog(t *testing.T) {
	if !utils.Writable(types.PersistDir) || !utils.Writable("/run") {
		t.Logf("Required directories not writeable; SKIP")
		return
	}
	defaultLogger, defaultLog := agentlog.Init(defaultAgent)
	// how do we check this appears in log?
	defaultLogger.Infof("defaultLogger")
	defaultLog.Noticef("defaultLog")
	logrus.Infof("logrus")

	pubLogger, pubLog := agentlog.Init(publisherAgent)
	// pubLogger.SetLevel(logrus.TraceLevel)
	pubPs := pubsub.New(
		&socketdriver.SocketDriver{
			Logger: pubLogger,
			Log:    pubLog,
		},
		pubLogger, pubLog)
	pub, err := pubPs.NewPublication(pubsub.PublicationOptions{
		AgentName:  publisherAgent,
		TopicType:  item,
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("unable to publish: %v", err)
	}

	subLogger, subLog := agentlog.Init(subscriberAgent)
	// subLogger.SetLevel(logrus.TraceLevel)
	subPs := pubsub.New(
		&socketdriver.SocketDriver{
			Logger: subLogger,
			Log:    subLog,
		},
		subLogger, subLog)

	restarted := false
	synchronized := false
	created := false
	modified := false
	deleted := false
	subRestartHandler := func(ctxArg interface{}, restartCounter int) {
		t.Logf("subRestartHandler %d", restartCounter)
		if restartCounter == 0 {
			t.Fatalf("subRestartHandler called with zero")
		} else {
			restarted = true
		}
	}
	subSyncHandler := func(ctxArg interface{}, arg bool) {
		t.Logf("subSyncHandler")
		if !arg {
			t.Fatalf("subSyncHandler called with false")
		} else {
			synchronized = true
		}
	}
	subCreateHandler := func(ctxArg interface{}, key string, status interface{}) {
		t.Logf("subCreateHandler")
		created = true
	}
	subModifyHandler := func(ctxArg interface{}, key string, status interface{}, oldStatus interface{}) {
		t.Logf("subModifyHandler")
		modified = true
	}
	subDeleteHandler := func(ctxArg interface{}, key string, status interface{}) {
		t.Logf("subDeleteHandler")
		deleted = true
	}

	sub, err := subPs.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      publisherAgent,
		MyAgentName:    subscriberAgent,
		RestartHandler: subRestartHandler,
		SyncHandler:    subSyncHandler,
		CreateHandler:  subCreateHandler,
		ModifyHandler:  subModifyHandler,
		DeleteHandler:  subDeleteHandler,
		TopicImpl:      item,
		Persistent:     false,
		Ctx:            &item,
		Activate:       true,
	})
	if err != nil {
		t.Fatalf("unable to subscribe: %v", err)
	}

	dummyItem := Item{AString: "something to publish", ID: "mykey"}
	t.Logf("Initial Publish")
	pub.Publish(dummyItem.ID, dummyItem)
	i, err := pub.Get("mykey")
	assert.Nil(t, err)
	i2 := i.(Item)
	assert.Equal(t, "something to publish", i2.AString)
	assert.Equal(t, "mykey", i2.ID)

	change := <-sub.MsgChan()
	t.Logf("ProcessChange synchronized?")
	sub.ProcessChange(change)
	assert.False(t, synchronized)
	assert.False(t, restarted)

	change = <-sub.MsgChan()
	t.Logf("ProcessChange created?")
	sub.ProcessChange(change)
	assert.True(t, created)

	dummyItem.AString = "something else"
	t.Logf("Modify Publish")
	pub.Publish(dummyItem.ID, dummyItem)
	change = <-sub.MsgChan()
	t.Logf("ProcessChange modified?")
	sub.ProcessChange(change)
	assert.True(t, modified)

	t.Logf("Unpublish")
	pub.Unpublish(dummyItem.ID)
	change = <-sub.MsgChan()
	t.Logf("ProcessChange deleted?")
	sub.ProcessChange(change)
	assert.True(t, deleted)
}

// Memory PSI collector tests

func getSHA256Hash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func increaseTimeByASec(timestamp string) string {
	t, err := time.Parse("2006-01-02 15:04:05", timestamp)
	if err != nil {
		panic(err)
	}
	t = t.Add(time.Second)
	return t.Format("2006-01-02 15:04:05")
}

// Generate a random value in the range [low, high] with a skewed distribution
// The skewness parameter determines how much the distribution is skewed towards the low end
// A skewness of 1.0 means no skewness
func skewedRandomValue(low, high int64, skewness float64) int64 {
	// Generate a random float between 0 and 1
	randFloat := rand.Float64()

	// Apply the power transformation to skew the distribution
	value := math.Pow(randFloat, skewness)

	// Scale the value to the range [low, high]
	return low + int64(float64(high-low)*value)
}

// Take the current value and increase it by a random value
// Make it so way in most cases it returns 0 or small value, but sometimes it returns a big value
func increaseTotalRandomly(total int64) int64 {
	return total + skewedRandomValue(0, 1000000, 2)
}

func generateRandomAvgValue() float64 {
	// Avg is a float of format 0.00 in range [0.00, 100.00]
	return rand.Float64() * 100
}

func matchPsiStats(line string) bool {
	// The line should have the format "avg avg avg total avg avg avg total"
	// where avg is a float of format 0.00 in range [0.00, 100.00] and total is an int from 0 to max uint64
	re := regexp.MustCompile(`(\d{1,2}\.\d{2} ){3}\d{1,19} (\d{1,2}\.\d{2} ){3}\d{1,19}`)
	return re.MatchString(line)
}

// Mutex for PSI stats producer - let's avoid running multiple producers at the same time
var psiProducerMutex sync.Mutex

func emulateMemoryPressureStats() (cancel context.CancelFunc, err error) {
	// Take the mutex on the producer creation and release it when the producer is done
	psiProducerMutex.Lock()
	// Create a new file for memory pressure stats
	fakePSIFileHandler, err := os.CreateTemp("", "memory-pressure")
	if err != nil {
		psiProducerMutex.Unlock()
		return nil, err
	}

	fakePSIFileName := fakePSIFileHandler.Name()
	originalPressureMemoryFile := agentlog.PressureMemoryFile()
	agentlog.UpdatePressureMemoryFile(fakePSIFileName)

	// Start a ticker to write a new line to the file every 0.5 seconds
	ticker := time.NewTicker(500 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		PsiStats := agentlog.PressureStallInfo{
			SomeAvg10:  0.00,
			SomeAvg60:  0.00,
			SomeAvg300: 0.00,
			SomeTotal:  0,
			FullAvg10:  0.00,
			FullAvg60:  0.00,
			FullAvg300: 0.00,
			FullTotal:  0,
		}
		for {
			select {
			case <-ticker.C:
				agentlog.PsiMutex.Lock()
				PsiStats.SomeAvg10 = generateRandomAvgValue()
				PsiStats.SomeAvg60 = generateRandomAvgValue()
				PsiStats.SomeAvg300 = generateRandomAvgValue()
				PsiStats.SomeTotal = increaseTotalRandomly(PsiStats.SomeTotal)
				PsiStats.FullAvg10 = generateRandomAvgValue()
				PsiStats.FullAvg60 = generateRandomAvgValue()
				PsiStats.FullAvg300 = generateRandomAvgValue()
				PsiStats.FullTotal = increaseTotalRandomly(PsiStats.FullTotal)
				// Rewrite the content of the file
				content := fmt.Sprintf(
					"some avg10=%.02f avg60=%.02f avg300=%.02f total=%d\nfull avg10=%.02f avg60=%.02f avg300=%.02f total=%d\n",
					PsiStats.SomeAvg10, PsiStats.SomeAvg60, PsiStats.SomeAvg300, PsiStats.SomeTotal,
					PsiStats.FullAvg10, PsiStats.FullAvg60, PsiStats.FullAvg300, PsiStats.FullTotal)
				if err := os.WriteFile(fakePSIFileName, []byte(content), 0644); err != nil {
					panic(err)
				}
				agentlog.PsiMutex.Unlock()
			case <-ctx.Done():
				ticker.Stop()
				agentlog.PsiMutex.Lock()
				fakePSIFileHandler.Close()
				os.Remove(fakePSIFileName)
				agentlog.UpdatePressureMemoryFile(originalPressureMemoryFile)
				agentlog.PsiMutex.Unlock()
				// We destroy this producer, so release the mutex
				psiProducerMutex.Unlock()
				return
			}
		}
	}()

	return cancel, nil

}

const (
	staticPSIStatsContent = `some avg10=1.00 avg60=0.10 avg300=0.01 total=1000
full avg10=2.00 avg60=0.20 avg300=0.02 total=2000`
	staticStatLine = `1.00 0.10 0.01 1000 2.00 0.20 0.02 2000`
)

func createFakePSIStatsFile() (cleanupFunc context.CancelFunc, err error) {
	// Take the mutex on the producer creation and release it when the producer is done
	psiProducerMutex.Lock()
	// Create a new file for memory pressure stats
	fakePSIFileHandler, err := os.CreateTemp("", "memory-pressure")
	if err != nil {
		return nil, err
	}

	fakePSIFileName := fakePSIFileHandler.Name()
	originalPressureMemoryFile := agentlog.PressureMemoryFile()
	agentlog.UpdatePressureMemoryFile(fakePSIFileName)

	// Write some content to the file
	agentlog.PsiMutex.Lock()
	if err := os.WriteFile(fakePSIFileName, []byte(staticPSIStatsContent), 0644); err != nil {
		agentlog.PsiMutex.Unlock()
		return nil, err
	}
	agentlog.PsiMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		agentlog.PsiMutex.Lock()
		fakePSIFileHandler.Close()
		os.Remove(fakePSIFileName)
		agentlog.UpdatePressureMemoryFile(originalPressureMemoryFile)
		agentlog.PsiMutex.Unlock()
		// We destroy this producer, so release the mutex
		psiProducerMutex.Unlock()
	}()

	return cancel, nil
}

// Mutext for HTTP server start/stop
var psiServerMutex sync.Mutex

func startIntegratedPSICollectorAPI() (cancel context.CancelFunc, err error) {
	// Take mutex
	psiServerMutex.Lock()
	logger, logObj := agentlog.Init("TestingAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	go agentlog.ListenDebug(logObj, "stackdump", "memdump")
	started := false
	// Wait for ListenDebug to start http service (try to get 200 response)
	// Limit the number of retries to avoid infinite loop, try for 10 seconds
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://127.0.0.1:6543")
		if err == nil && resp.StatusCode == 200 {
			started = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !started {
		psiServerMutex.Unlock()
		return nil, fmt.Errorf("could not start the server in 10 seconds")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ctx.Done()
		if started {
			http.Post("http://127.0.0.1:6543/stop", "", nil)
			// Wait for the server to stop, check if it is still running
			for i := 0; i < 100; i++ {
				_, err := http.Get("http://127.0.0.1:6543")
				if err != nil && strings.Contains(err.Error(), "connection refused") {
					started = false
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if started {
				panic("could not stop the server in 10 seconds")
			}
			psiServerMutex.Unlock()
		}
	}()
	return cancel, nil
}

func preparePSIEnvironment(predictable bool) (cancel context.CancelFunc, err error) {
	err = os.MkdirAll(types.MemoryMonitorOutputDir, 0755)
	if err != nil {
		return nil, err
	}
	if !predictable {
		return emulateMemoryPressureStats()
	} else {
		return createFakePSIStatsFile()
	}
}

func TestPsiEveIntegratedStartStop(t *testing.T) {

	stopEmulation, err := preparePSIEnvironment(true)
	if err != nil {
		t.Fatalf("could not prepare the PSI environment: %v", err)
	}
	defer stopEmulation()
	stopAPI, err := startIntegratedPSICollectorAPI()
	if err != nil {
		t.Fatalf("could not start the integrated psi collector API: %v", err)
	}
	defer stopAPI()

	// Start the collector
	resp, err := http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/start", "", nil)
	if err != nil {
		log.Fatalf("Starting psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	// Read the response body to check that the collector has started
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector started")

	// Let it work for 2 seconds
	time.Sleep(2 * time.Second)

	// Check that the file is created
	_, err = os.Stat(types.MemoryMonitorPSIStatsFile)
	if err != nil {
		t.Fatalf("expected file %s to be created, but got %v", types.MemoryMonitorPSIStatsFile, err)
	}

	// Check that the content of the file is correct
	content, err := os.ReadFile(types.MemoryMonitorPSIStatsFile)
	if err != nil {
		t.Fatalf("could not read from %s: %v", types.MemoryMonitorPSIStatsFile, err)
	}

	// Check that the first line contains the header
	lines := strings.Split(string(content), "\n")
	assert.Contains(t, lines[0], agentlog.PSIHeader)

	// Clean the empty line if it exists
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Check that it contains 1 or 2 lines of PSI stats plus header (as we ran the collector for 2 seconds)
	assert.True(t, len(lines) == 2 || len(lines) == 3)

	// Check that the lines contain the expected content
	for i := 1; i < len(lines); i++ {
		assert.True(t, matchPsiStats(lines[i]))
		assert.Contains(t, lines[i], staticStatLine)
	}

	// Stop the collector
	resp, err = http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/stop", "", nil)
	if err != nil {
		log.Fatalf("Stopping psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector stopped")

	// Check that the file is still there
	_, err = os.Stat(types.MemoryMonitorPSIStatsFile)
	if err != nil {
		t.Fatalf("expected file %s to be available, but got %v", types.MemoryMonitorPSIStatsFile, err)
	}
}

func TestPsiEveIntegratedStartStopTwice(t *testing.T) {
	t.Skip("skip test because of flakiness")
	stopEmulation, err := preparePSIEnvironment(false)
	if err != nil {
		t.Fatalf("could not prepare the PSI environment: %v", err)
	}
	defer stopEmulation()
	stopAPI, err := startIntegratedPSICollectorAPI()
	if err != nil {
		t.Fatalf("could not start the integrated psi collector API: %v", err)
	}
	defer stopAPI()

	// Start the collector the first time
	resp, err := http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/start", "", nil)
	if err != nil {
		log.Fatalf("Starting psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector started")

	// Let it work for 3 seconds
	time.Sleep(3 * time.Second)

	// Save the hash of the file content
	content, err := os.ReadFile(types.MemoryMonitorPSIStatsFile)
	if err != nil {
		t.Fatalf("could not read from %s: %v", types.MemoryMonitorPSIStatsFile, err)
	}

	hashFirst := getSHA256Hash(content)

	// Stop the collector
	resp, err = http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/stop", "", nil)
	if err != nil {
		log.Fatalf("Stopping psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector stopped")

	time.Sleep(1 * time.Second)

	// Start the collector the second time
	resp, err = http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/start", "", nil)
	if err != nil {
		log.Fatalf("Starting psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector started")

	// Let it work for 1 second
	time.Sleep(1 * time.Second)

	// Stop the collector
	resp, err = http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/stop", "", nil)
	if err != nil {
		log.Fatalf("Stopping psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector stopped")

	// Check that the file is rewritten
	content, err = os.ReadFile(types.MemoryMonitorPSIStatsFile)
	if err != nil {
		t.Fatalf("could not read from %s: %v", types.MemoryMonitorPSIStatsFile, err)
	}

	hashSecond := getSHA256Hash(content)

	// Check that the content of the file has changed
	assert.NotEqual(t, hashFirst, hashSecond)

	lines := strings.Split(string(content), "\n")
	// Check that the file contains a proper header
	assert.Contains(t, lines[0], agentlog.PSIHeader)

	// Clean the empty line if it exists
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Check that it contains 0 or 1 line of PSI stats plus header (as we ran the collector for 1 second)
	assert.True(t, len(lines) == 1 || len(lines) == 2)
}

func TestPsiEveIntegratedStartTwice(t *testing.T) {
	t.Skip("skip test because of flakiness")
	stopEmulation, err := preparePSIEnvironment(false)
	if err != nil {
		t.Fatalf("could not prepare the PSI environment: %v", err)
	}
	defer stopEmulation()
	stopAPI, err := startIntegratedPSICollectorAPI()
	if err != nil {
		t.Fatalf("could not start the integrated psi collector API: %v", err)
	}
	defer stopAPI()

	// Start the collector the first time
	resp, err := http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/start", "", nil)
	if err != nil {
		log.Fatalf("Starting psi collector failed: %v - response is %v", err, resp)
	}
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector started")

	defer func() {
		// Stop the collector
		resp, err := http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/stop", "", nil)
		if err != nil {
			log.Fatalf("Stopping psi collector failed: %v", err)
		}
		assert.Equal(t, 200, resp.StatusCode)
	}()

	// Start the collector the second time
	resp, err = http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/start", "", nil)
	if err != nil {
		log.Fatalf("Starting psi collector failed: %v", err)
	}
	assert.Equal(t, 409, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector is already running")

}

func TestPsiEveIntegratedStopUnstarted(t *testing.T) {
	t.Skip("skip test because of flakiness")
	stopEmulation, err := preparePSIEnvironment(false)
	if err != nil {
		t.Fatalf("could not prepare the PSI environment: %v", err)
	}
	defer stopEmulation()
	stopAPI, err := startIntegratedPSICollectorAPI()
	if err != nil {
		t.Fatalf("could not start the integrated psi collector API: %v", err)
	}
	defer stopAPI()

	// Stop the collector without starting it
	resp, err := http.Post("http://127.0.0.1:6543/memory-monitor/psi-collector/stop", "", nil)
	if err != nil {
		log.Fatalf("Stopping psi collector failed: %v", err)
	}
	assert.Equal(t, 404, resp.StatusCode)
	assert.Contains(t, func() string { b, _ := io.ReadAll(resp.Body); return string(b) }(), "Memory PSI collector is not running")
}

const (
	MockStatMaxLine = "100.00 100.00 100.00 10000000000000000000 100.00 100.00 100.00 10000000000000000000"
)

func prepareOutputFile(lines int, predictable bool) *os.File {
	// Create a new file for memory pressure stats
	outputFile, err := os.CreateTemp("", "statfile")
	if err != nil {
		panic(err)
	}

	// Write header to the file
	if _, err := outputFile.WriteString(agentlog.PSIHeader + "\n"); err != nil {
		panic(err)
	}

	// Initialize the timestamp
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if predictable {
		// Just write the same line multiple times, but with different timestamps
		for i := 0; i < lines; i++ {
			content := fmt.Sprintf("%s %s\n", timestamp, MockStatMaxLine)
			if _, err := outputFile.WriteString(content); err != nil {
				panic(err)
			}
			timestamp = increaseTimeByASec(timestamp)
		}
	} else {
		// Initialize the timestamp and psi stats
		psiStats := agentlog.PressureStallInfo{
			SomeAvg10:  0.00,
			SomeAvg60:  0.00,
			SomeAvg300: 0.00,
			SomeTotal:  0,
			FullAvg10:  0.00,
			FullAvg60:  0.00,
			FullAvg300: 0.00,
			FullTotal:  0,
		}
		// For each line, update the timestamp and psi stats
		for i := 0; i < lines; i++ {
			psiStats.SomeAvg10 = generateRandomAvgValue()
			psiStats.SomeAvg60 = generateRandomAvgValue()
			psiStats.SomeAvg300 = generateRandomAvgValue()
			psiStats.SomeTotal = increaseTotalRandomly(psiStats.SomeTotal)
			psiStats.FullAvg10 = generateRandomAvgValue()
			psiStats.FullAvg60 = generateRandomAvgValue()
			psiStats.FullAvg300 = generateRandomAvgValue()
			psiStats.FullTotal = increaseTotalRandomly(psiStats.FullTotal)
			// Write the content to the file
			content := fmt.Sprintf("%s %.02f %.02f %.02f %d %.02f %.02f %.02f %d\n",
				timestamp, psiStats.SomeAvg10, psiStats.SomeAvg60, psiStats.SomeAvg300, psiStats.SomeTotal,
				psiStats.FullAvg10, psiStats.FullAvg60, psiStats.FullAvg300, psiStats.FullTotal)
			if _, err := outputFile.WriteString(content); err != nil {
				panic(err)
			}
			timestamp = increaseTimeByASec(timestamp)
		}
	}

	outputFile.Sync()

	return outputFile
}

func TestManageStatFileSizeTruncate(t *testing.T) {
	logger, logObj := agentlog.Init("TestAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	originalLines := 20
	outputFile := prepareOutputFile(originalLines, true)
	defer func() {
		outputFile.Close()
		os.Remove(outputFile.Name())
	}()

	fileInfo, err := outputFile.Stat()
	if err != nil {
		t.Fatalf("could not get file info: %v", err)
	}
	fileSize := fileInfo.Size()

	var linesToKeep uint = 10
	// Set the threshold size less than the file size
	thresholdSize := uint64(fileSize)

	// Check that the set threshold size is greater than minimal possible size for the given number
	// of lines to keep
	minimalSize := agentlog.StatLineMinSize * uint64(linesToKeep)
	if thresholdSize < agentlog.StatLineMinSize*uint64(linesToKeep) {
		t.Fatalf("expected threshold size to be greater than %d, but got %d", minimalSize, thresholdSize)
	}

	// Save the line that should be the first one after truncation

	// Read the content of the file
	outputFile.Seek(0, 0)
	content, err := io.ReadAll(outputFile)
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}

	// Split the content into lines
	lines := strings.Split(string(content), "\n")

	// Count the index of the first line that should be kept after truncation
	// Remember that the first line is always a header, so we operate with 1-based indexes
	expectedFirstLineIndex := originalLines - int(linesToKeep) + 1

	// Remember the content of the line
	expectedFirstLine := lines[expectedFirstLineIndex]

	// Truncate the file
	_, err = agentlog.ManageStatFileSize(logObj, outputFile, thresholdSize, linesToKeep)
	assert.Nil(t, err)

	// Check that the file content is truncated to the given amount of lines
	outputFile.Seek(0, 0)
	newContent, err := io.ReadAll(outputFile)
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}

	// Analyze the content of the file
	lines = strings.Split(string(newContent), "\n")
	// Remove the last line if it is empty
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Check that the file contains the header
	assert.Contains(t, lines[0], agentlog.PSIHeader)

	// Check that the file contains only one header
	headerCount := strings.Count(string(newContent), agentlog.PSIHeader)
	assert.Equal(t, 1, headerCount)

	// Check that the new first PSI stats line is the expected one (it's 20 - 10 = 10th line of the original file)
	assert.Equal(t, expectedFirstLine, lines[1])

	// Check that the file contains the expected number of lines (+1 because the first line is the header)
	assert.Equal(t, int(linesToKeep)+1, len(lines))

	// Check that the file contains the expected content
	// We can precalculate the expected content by just increasing the timestamp of the first line
	// So, first - read the timestamp from the first line
	// Then, increase it by a second and compare with the next line
	raws := strings.Split(expectedFirstLine, " ")
	timestamp := raws[0] + " " + raws[1]
	for i := 1; i <= int(linesToKeep); i++ {
		// Create the expected line
		expectedLine := fmt.Sprintf("%s %s", timestamp, MockStatMaxLine)
		// Check that the line is correct
		assert.Equal(t, expectedLine, lines[i])
		// Increase the timestamp
		timestamp = increaseTimeByASec(timestamp)
	}
}

func TestManageStatFileSizeTruncateNotTriggered(t *testing.T) {
	logger, logObj := agentlog.Init("TestAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	originalLines := 20
	outputFile := prepareOutputFile(originalLines, true)
	defer func() {
		outputFile.Close()
		os.Remove(outputFile.Name())
	}()

	fileInfo, err := outputFile.Stat()
	if err != nil {
		t.Fatalf("could not get file info: %v", err)
	}
	fileSize := fileInfo.Size()

	var linesToKeep uint = 20
	// Set the threshold size greater than the file size
	thresholdSize := uint64(fileSize) + 1

	// Save a hash of the file content
	outputFile.Seek(0, 0)
	content, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}

	originalHash := getSHA256Hash(content)

	// Call the function
	_, err = agentlog.ManageStatFileSize(logObj, outputFile, thresholdSize, linesToKeep)
	assert.Nil(t, err)

	// Check that the file content is not changed
	outputFile.Seek(0, 0)
	newContent, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}

	newHash := getSHA256Hash(newContent)
	assert.Equal(t, originalHash, newHash)
}

func TestManageStatFileSizeNotProperThreshold(t *testing.T) {
	logger, logObj := agentlog.Init("TestAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	originalLines := 20
	outputFile := prepareOutputFile(originalLines, false)
	defer func() {
		outputFile.Close()
		os.Remove(outputFile.Name())
	}()

	var linesToKeep uint = 10
	// Set the threshold size less that minimal possible size for the given number of lines to keep
	thresholdSize := agentlog.StatLineMinSize*uint64(linesToKeep) + uint64(len(agentlog.PSIHeader))

	// Call the function
	_, err := agentlog.ManageStatFileSize(logObj, outputFile, thresholdSize, linesToKeep)
	// We expect the function to return an error
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "linesToKeep is too high for the threshold size")

	// Now we will calculate the proper threshold size and call the function again
	properThresholdSize := agentlog.StatLineMinSize*uint64(linesToKeep) + uint64(len(agentlog.PSIHeader)) + 1
	_, err = agentlog.ManageStatFileSize(logObj, outputFile, properThresholdSize, linesToKeep)
	assert.Nil(t, err)
}

func TestManageStatFileSizeNotTruncatedLinesToKeepIsGreaterThanWeHave(t *testing.T) {
	logger, logObj := agentlog.Init("TestAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	originalLines := 20
	outputFile := prepareOutputFile(originalLines, false)
	defer func() {
		outputFile.Close()
		os.Remove(outputFile.Name())
	}()

	// Let's count the threshold so the truncation will be triggered
	// It should be:
	// * less than the current file size
	// * greater than the minimal possible size for the given number of lines to keep
	fileInfo, err := outputFile.Stat()
	if err != nil {
		t.Fatalf("could not get file info: %v", err)
	}
	maxThresholdValue := uint64(fileInfo.Size())

	var linesToKeep uint = 22
	minThresholdValue := agentlog.StatLineMinSize*uint64(linesToKeep) + uint64(len(agentlog.PSIHeader)) + 1

	if minThresholdValue > maxThresholdValue {
		t.Fatalf("expected minThresholdValue to be less than maxThresholdValue, but got %d and %d", minThresholdValue, maxThresholdValue)
	}

	thresholdSize := (minThresholdValue + maxThresholdValue) / 2

	// Save the hash of the file content, so we can compare it later and check if the file was not truncated
	outputFile.Seek(0, 0)
	content, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}
	orginalHash := getSHA256Hash(content)

	// Call the function
	realAverageSize, err := agentlog.ManageStatFileSize(logObj, outputFile, thresholdSize, linesToKeep)
	// We expect the function to finish without any error, but also return the average size of the lines
	assert.Nil(t, err)
	assert.NotEqual(t, realAverageSize, uint64(0))

	// We can calculate the expected average size of the lines, as we know the file size and the number of lines
	expectedAverageSize := uint64(fileInfo.Size()) / uint64(originalLines+1)
	assert.Equal(t, expectedAverageSize, realAverageSize)

	// Also we expect the file is not truncated
	outputFile.Seek(0, 0)
	newContent, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}
	newHash := getSHA256Hash(newContent)

	// Check that the file content is not changed
	assert.Equal(t, orginalHash, newHash)

}

// TestManageStatFileSizeTruncateButStillTooBig tests the case when
// the file is truncated to the given number of lines, but the file is still too big for the
// given threshold size. It happens when the real average size of the lines is greater than the
// expected one. In this case, the function should truncate the file to the given number of lines
// and return the real average size of the lines.
func TestManageStatFileSizeTruncateButStillTooBig(t *testing.T) {
	logger, logObj := agentlog.Init("TestAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	originalLines := 20
	outputFile := prepareOutputFile(originalLines, true)
	defer func() {
		outputFile.Close()
		os.Remove(outputFile.Name())
	}()

	// Save the original file info to calculate the expected average size of the lines
	fileInfo, err := outputFile.Stat()

	// Let the number of lines to keep be close enough to the original number of lines, so
	// that we do not truncate too much, so it is still possible to over the original threshold
	var linesToKeep uint = 15

	// The threshold size should be bigger than the expected size of the file after truncation
	thresholdSize := agentlog.StatLineAvgSize*uint64(linesToKeep+1) + uint64(len(agentlog.PSIHeader)) + 1

	// Check that the set threshold size is greater than minimal possible size for the given number
	minThresholdValue := agentlog.StatLineMinSize*uint64(linesToKeep) + uint64(len(agentlog.PSIHeader)) + 1

	if thresholdSize < minThresholdValue {
		t.Fatalf("expected threholdSize to be greater than %d, but got %d", minThresholdValue, thresholdSize)
	}

	// Okaaay, we are done with the arguments, let's do the job now

	// Save the hash of the file content, so we can compare it later and check if the file was truncated
	outputFile.Seek(0, 0)
	content, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}
	originalHash := getSHA256Hash(content)

	// Call the function
	realAverageSize, err := agentlog.ManageStatFileSize(logObj, outputFile, thresholdSize, linesToKeep)
	// We expect the function to finish without any error, but also return the average size of the lines
	assert.Nil(t, err)
	assert.NotEqual(t, realAverageSize, uint64(0))

	// We can calculate the expected average size of the lines, as we know the file size and the number of lines
	expectedAverageSize := uint64(fileInfo.Size()) / uint64(originalLines+1)
	assert.Equal(t, expectedAverageSize, realAverageSize)

	// Also we expect the file is truncated
	outputFile.Seek(0, 0)
	newContent, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}
	newHash := getSHA256Hash(newContent)

	// Check that the file is really changed
	assert.NotEqual(t, originalHash, newHash)

	// Check that the file contains the header
	assert.Contains(t, string(newContent), agentlog.PSIHeader)

	// Check that the file contains the expected number of lines
	lines := strings.Split(string(newContent), "\n")
	// Remove the last line if it is empty
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	// +1 because the first line is the header
	assert.Equal(t, int(linesToKeep+1), len(lines))
}

func TestManageStatFileSizeTargetSizesAvgThreshold(t *testing.T) {
	logger, logObj := agentlog.Init("TestAgentlog")
	// Silent the logger
	logger.SetOutput(io.Discard)
	originalLines := agentlog.StatLinesPerHour * 24
	outputFile := prepareOutputFile(originalLines, false)

	// Print the size of the file
	fileInfo, err := outputFile.Stat()
	if err != nil {
		t.Fatalf("could not get file info: %v", err)
	}
	fileSize := fileInfo.Size()
	t.Logf("Original file size: %v", fileSize)

	thresholdSize := agentlog.StatLineAvgSize * agentlog.StatLinesPerHour * 24
	linesToKeep := agentlog.StatLinesPerHour * 23

	// Calculate a hash of the file content
	outputFile.Seek(0, 0)
	content, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}
	originalHash := getSHA256Hash(content)

	timeStart := time.Now()
	avgSize, err := agentlog.ManageStatFileSize(logObj, outputFile, thresholdSize, uint(linesToKeep))
	timeEnd := time.Now()

	assert.Nil(t, err)
	// We also expect that the function will return the average size of the lines
	assert.NotEqual(t, avgSize, 0)

	duration := timeEnd.Sub(timeStart)
	assert.Truef(t, duration < 1*time.Second, "expected duration to be less than 1 second, but got %v", duration)
	t.Logf("Duration: %v", duration)
	t.Logf("AvgSize: %v", avgSize)

	fileInfo, err = outputFile.Stat()
	if err != nil {
		t.Fatalf("could not get file info: %v", err)
	}
	fileSize = fileInfo.Size()
	t.Logf("Resulting file size: %v", fileSize)

	// Check that the file content is correct
	outputFile.Seek(0, 0)
	newContent, err := io.ReadAll(outputFile)
	if err != nil {
		t.Fatalf("could not read from file: %v", err)
	}

	// Check that the file is changed
	newHash := getSHA256Hash(newContent)
	assert.NotEqual(t, originalHash, newHash)

	// Check that the file contains the expected number of lines
	lines := strings.Split(string(newContent), "\n")
	// Remove the last line if it is empty
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	// +1 because the last line is empty and we have a header
	assert.Equal(t, linesToKeep+1, len(lines))

	// Check that the file contains the header
	assert.Contains(t, lines[0], agentlog.PSIHeader)

}
