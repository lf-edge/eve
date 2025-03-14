package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lf-edge/eve-api/go/logs"
)

func TestDeduplicateLogs(t *testing.T) {
	// Create channels
	totalLogs := bufferSize + 50
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
