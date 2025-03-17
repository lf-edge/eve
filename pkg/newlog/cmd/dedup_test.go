package main

import (
	"bufio"
	"bytes"
	"container/ring"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"unicode"

	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
)

func TestDeduplicateLogs(t *testing.T) {
	// Create channels
	totalLogs := int(dedupWindowSize.Load() + 50)
	in := make(chan inputEntry, totalLogs)
	distinctLogs := 75
	out := make(chan inputEntry, distinctLogs)

	// Start deduplicateLogs in a goroutine.
	go deduplicateLogs(in, out)

	for i := range totalLogs {
		// Use 50 distinct messages
		entry := inputEntry{content: "msg" + strconv.Itoa(i%distinctLogs), severity: "error", appUUID: strconv.Itoa(i)}
		in <- entry
	}
	close(in)

	// Collect output logs.
	var results []inputEntry
	for entry := range out {
		results = append(results, entry)
	}

	if len(results) != distinctLogs {
		t.Fatalf("expected %d output logs, got %d", distinctLogs, len(results))
	}

	for i := range distinctLogs {
		expectedMessage := "msg" + strconv.Itoa(i)
		if results[i].content != expectedMessage {
			t.Errorf("at output index %d: expected %q, got %q", i, expectedMessage, results[i].content)
		}
	}
}

func TestDedupWithLocalFile(t *testing.T) {
	// Create a channel to send the log entry to deduplicateLogs
	in := make(chan inputEntry, 10)
	out := make(chan inputEntry, 10)

	// Start deduplicateLogs in a goroutine.
	go deduplicateLogs(in, out)

	go func() {
		// Read local log file
		file, err := os.Open("/home/paul/eve-info/eve-info-v33-2025-03-03-15-44-57/all_logs")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		// Read lines from the gzip file
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				t.Error(err)
				continue
			}

			var entry logs.LogEntry
			if err = json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				t.Error(err)
				continue
			}

			in <- inputEntry{
				severity:  entry.Severity,
				source:    entry.Source,
				content:   entry.Content,
				pid:       entry.Iid,
				filename:  entry.Filename,
				function:  entry.Function,
				timestamp: entry.Timestamp.String(),
				appUUID:   fmt.Sprint(entry.Msgid),
			}
		}
		close(in)
	}()

	file, err := os.OpenFile("/home/paul/eve-info/eve-info-v33-2025-03-03-15-44-57/deduped_logs", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	expectedMsgId := 1
	fmt.Println("msgid's of deduplicated logs:")
	for entry := range out {
		timeS, _ := getPtypeTimestamp(entry.timestamp)
		msgid, _ := strconv.Atoi(entry.appUUID)
		mapLog := logs.LogEntry{
			Severity:  entry.severity,
			Source:    entry.source,
			Content:   entry.content,
			Iid:       entry.pid,
			Filename:  entry.filename,
			Function:  entry.function,
			Timestamp: timeS,
			Msgid:     uint64(msgid),
		}
		for msgid > expectedMsgId {
			fmt.Println(expectedMsgId) // the msg with this id was deduplicated
			expectedMsgId++
		}
		expectedMsgId = msgid + 1

		mapJentry, _ := json.Marshal(&mapLog)
		logline := string(mapJentry) + "\n"
		_, err = file.WriteString(logline)
		if err != nil {
			t.Error(err)
		}
	}

	t.Logf("Total num deduped logs: %d", numDedupedLogs)
}

func TestMsgFieldExtraction(t *testing.T) {
	contentStr := "{\"file\":\"/pillar/zedcloud/zedcloudmetric.go:86\",\"func\":\"github.com/lf-edge/eve/pkg/pillar/zedcloud.(*AgentMetrics).RecordFailure\",\"level\":\"info\",\"msg\":\"EVENT: failed to access https://zedcloud.alpha.zededa.net/api/v2/edgedevice/id/91a44d75-0bfe-466b-acfe-0b91d2033c15/metrics\",\"pid\":2162,\"source\":\"zedagent\",\"time\":\"2025-03-03T15:36:18.530126869Z\"}"

	var content ContainsMsg
	json.Unmarshal([]byte(contentStr), &content)
	if content.Msg != "EVENT: failed to access https://zedcloud.alpha.zededa.net/api/v2/edgedevice/id/91a44d75-0bfe-466b-acfe-0b91d2033c15/metrics" {
		t.Errorf("expected %q, got %q", "EVENT: failed to access https://zedcloud.alpha.zededa.net/api/v2/edgedevice/id/91a44d75-0bfe-466b-acfe-0b91d2033c15/metrics", content.Msg)
	}
}

func TestHowMapsArePassedToFunctions(t *testing.T) {
	// Create a map and pass it to a function.
	m := make(map[string]int)
	m["test"] = 1
	addOneToMap(m)
	if m["test"] != 2 {
		t.Errorf("expected %d, got %d", 2, m["test"])
	}
	key := "test2"
	addKeyToMap(m, key)
	if m[key] != 1 {
		t.Errorf("expected %d, got %d", 1, m[key])
	}
}

func addOneToMap(m map[string]int) {
	m["test"]++
}

func addKeyToMap(m map[string]int, key string) {
	m[key] = 1
}

func TestDoMoveCompressFile(t *testing.T) {
	logFileInfo := fileChanInfo{
		tmpfile:   "/home/paul/eve-info/eve-info-v22-2025-01-29-13-51-04/right_time.log",
		isApp:     false,
		notUpload: false, // treat as if it was uploaded to see how the filtering measures work
	}

	logger, log = agentlog.Init(agentName)
	ps := *pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log}, logger, log)

	doMoveCompressFile(&ps, logFileInfo)
}

func TestLogFiltering(t *testing.T) {
	// open input file
	// iFile, err := os.Open("/home/paul/eve-info/eve-info-v22-2025-01-29-13-51-04/right_time.log")
	iFile, err := os.Open("/home/paul/eve-info/eve-info-v33-2025-03-03-15-44-57/all_logs")
	if err != nil {
		t.Fatal(err)
	}
	defer iFile.Close()

	// oFile, err := os.OpenFile("/home/paul/eve-info/eve-info-v22-2025-01-29-13-51-04/out.log", os.O_CREATE|os.O_WRONLY, 0644)
	oFile, err := os.OpenFile("/home/paul/eve-info/eve-info-v33-2025-03-03-15-44-57/out.log", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer oFile.Close()

	// FILTERING PARAMS:
	filenameFilter["/pillar/evetpm/tpm.go:346"] = nil
	logsToCount.Store([]string{
		"/pillar/types/zedroutertypes.go:1079",
	})

	// first we go through the file and count the number of occurrences of the selected log entries
	var logCounter map[string]int
	var seen map[string]uint64
	var queue *ring.Ring
	logCounter = make(map[string]int)
	for _, logSrcLine := range logsToCount.Load().([]string) {
		logCounter[logSrcLine] = 0
	}
	preScanner := bufio.NewScanner(iFile)
	for preScanner.Scan() {
		// we ingnore the errors here, they might be coming from non-json lines like the metadata line
		_ = countLogOccurances(preScanner.Bytes(), logCounter)
	}
	if err := preScanner.Err(); err != nil {
		t.Errorf("Error scanning file for log occurrence count: %v", err)
	}
	if _, err := iFile.Seek(0, 0); err != nil {
		t.Errorf("Failed to reset file pointer: %v", err)
		return // TODO: this might be wrong, what should we do here?
	}

	// for deduplicator
	// 'seen' counts occurrences of each file in the current window.
	seen = make(map[string]uint64)
	// 'queue' holds the file fields of the last bufferSize logs.
	queue = ring.New(int(dedupWindowSize.Load()))

	// now we go through the file again and deduplicate the logs
	scanner := bufio.NewScanner(iFile)
	for scanner.Scan() {
		newLine := scanner.Bytes()
		//trim non-graphic symbols
		newLine = bytes.TrimFunc(newLine, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if len(newLine) == 0 {
			continue
		}
		if !json.Valid(newLine) {
			t.Errorf("doMoveCompressFile: found broken line: %s", string(newLine))
			continue
		}

		var logEntry logs.LogEntry
		if err := json.Unmarshal(newLine, &logEntry); err != nil {
			continue // we don't care about the error here
		}
		var useEntry bool
		if useEntry = filterOut(&logEntry); !useEntry {
			continue
		}
		if useEntry = addLogCount(&logEntry, logCounter); !useEntry {
			continue
		}
		if useEntry, queue = dedupLogEntry(&logEntry, seen, queue); !useEntry {
			continue
		}
		newLine, err = json.Marshal(&logEntry)
		if err != nil {
			t.Errorf("doMoveCompressFile: failed to marshal logEntry: %v", err)
			continue
		}

		_, err := oFile.Write(append(newLine, '\n'))
		if err != nil {
			t.Fatal("doMoveCompressFile: cannot write file", err)
		}
	}

	if scanner.Err() != nil {
		t.Fatal("doMoveCompressFile: reading file failed", scanner.Err())
	}

	t.Logf("Total num deduped logs: %d", numDedupedLogs)
}
