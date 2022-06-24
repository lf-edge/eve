// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/api/go/logs"
)

type logfiletime struct {
	filepath string
	filesec  int64
}

// LogContent - log content struct
type LogContent struct {
	File    string `json:"file,omitempty"`
	Func    string `json:"func,omitempty"`
	IfName  string `ifname:"func,omitempty"`
	Level   string `json:"level,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Objtype string `json:"obj_type,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Source  string `json:"source,omitempty"`
	Time    string `json:"time,omitempty"`
}

func runLogSearch(cmds cmdOpt) {
	pattern := cmds.Logopt
	timeline := cmds.Timerange
	extralog := cmds.Extraline
	var copylogfiles bool
	log.Tracef("log pattern %s, time %s, json %v, extraline %d, type %s",
		pattern, timeline, cmds.IsJSON, extralog, querytype)

	if !strings.Contains(timeline, "-") {
		fmt.Printf("log time needs to have dash between start and end\n")
		return
	}

	if !rePattern.MatchString(pattern) {
		fmt.Printf("log search contains invalid string\n")
		return
	}

	now := time.Now().Unix()
	// t1 >= t2 int64
	t1, t2 := getTimeSec(timeline, now)
	if t1 == 0 || t2 == 0 {
		return
	}
	if pattern == cpLogFileString {
		if t1-t2 > 1800 {
			fmt.Printf("copy-logfiles can only be in the range of 30 minutes\n")
			return
		}
		copylogfiles = true
	} else if t1-t2 > 18000 {
		fmt.Printf("log search can only be in the range of 5 hours\n")
		return
	}

	gfiles := walkLogDirs(t1, t2, now)
	if copylogfiles {
		runCopyLogfiles(gfiles, t1)
		return
	}

	prog1 := "zcat"
	prog2 := "grep"
	arg2 := []string{"-E", pattern}
	if extralog > 0 {
		arg2 = []string{"-A", strconv.Itoa(extralog), "-B", strconv.Itoa(extralog), "-E", pattern}
	}
	var printIdx int
	for _, gf := range gfiles {
		arg1 := []string{gf.filepath}
		olines, err := runPipeCmds(prog1, arg1, prog2, arg2)
		if err == nil && len(olines) > 0 {
			bout := fmt.Sprintf("\n %s, -- %v --\n", gf.filepath, time.Unix(gf.filesec, 0).Format(time.RFC3339))
			printColor(bout, colorRED)

			colorMatch(olines, pattern, &printIdx, cmds.IsJSON)
		}
	}

	if now-t1 < 10 { // search for collect directory for uncompressed files
		if querytype != "app" {
			searchLiveLogs(pattern, now, "dev", &printIdx, cmds.IsJSON)
		}
		if querytype != "dev" {
			searchLiveLogs(pattern, now, "app", &printIdx, cmds.IsJSON)
		}
	}
	fmt.Println()
}

func walkLogDirs(t1, t2, now int64) []logfiletime {
	var getfiles []logfiletime

	files, err := ioutil.ReadDir("/persist/newlog")
	if err != nil {
		fmt.Printf("read /persist/newlog error %v\n", err)
		return getfiles
	}

	gzfiles := make(map[string][]string)
	for _, dir := range files {
		if !dir.IsDir() {
			continue
		}
		if strings.Contains(dir.Name(), "collect") || strings.Contains(dir.Name(), "panic") {
			continue
		}
		if strings.Contains(dir.Name(), "devUpload") && querytype == "app" {
			continue
		}
		if strings.Contains(dir.Name(), "appUpload") && querytype == "dev" {
			continue
		}
		files1, err := ioutil.ReadDir("/persist/newlog/" + dir.Name())
		if err != nil {
			continue
		}
		var groupfiles []string
		for _, f := range files1 {
			if f.ModTime().Unix() > t1 || f.ModTime().Unix() < t2 {
				continue
			}
			groupfiles = append(groupfiles, f.Name())
		}
		gzfiles["/persist/newlog/"+dir.Name()] = groupfiles
	}

	for k, g := range gzfiles {
		for _, l := range g {
			if !strings.Contains(l, "dev") && !strings.Contains(l, "app") {
				continue
			}
			if querytype == "app" && !strings.Contains(l, "app") {
				continue
			}
			if querytype == "dev" && !strings.Contains(l, "dev") {
				continue
			}
			ftime := getFileTime(l)
			if ftime == 0 {
				continue
			}
			if ftime >= t2 && ftime <= t1 {
				file1 := strings.TrimPrefix(l, "./")
				gfile := logfiletime{
					filepath: k + "/" + file1,
					filesec:  ftime,
				}
				getfiles = append(getfiles, gfile)
			}
		}
	}

	sort.Slice(getfiles, func(i1, i2 int) bool {
		return getfiles[i1].filesec < getfiles[i2].filesec
	})

	return getfiles
}

func searchLiveLogs(pattern string, now int64, typeStr string, idx *int, logjson bool) {
	files, err := ioutil.ReadDir("/persist/newlog/collect")
	if err != nil {
		fmt.Printf("read /persist/newlog/collect error %v\n", err)
		return
	}

	for _, l := range files {
		if !strings.HasPrefix(l.Name(), typeStr) {
			continue
		}
		file := "/persist/newlog/collect/" + l.Name()
		searchCurrentLogs(pattern, file, typeStr, now, idx, logjson)
	}
}

func searchCurrentLogs(pattern, path, typeStr string, now int64, idx *int, logjson bool) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("read %s file error: %v\n", path, err)
	}
	lines := bytes.SplitAfter(contents, []byte("\n"))
	var selectlines string
	for _, l := range lines {
		if !bytes.Contains(l, []byte(pattern)) {
			continue
		}
		selectlines = selectlines + string(l)
	}
	bout := fmt.Sprintf("\n current "+typeStr+" log, -- %v --\n", time.Unix(now, 0).Format(time.RFC3339))
	printColor(bout, colorRED)

	colorMatch(selectlines, pattern, idx, logjson)
}

func colorMatch(olines, pattern string, idx *int, logjson bool) {
	closePipe(true)
	lines := strings.Split(olines, "\n")
	if strings.Contains(pattern, "|") {
		pat := strings.Split(pattern, "|")
		pattern = strings.TrimSuffix(pat[0], " ")
	}
	for i, l := range lines[:len(lines)-1] {
		if logjson {
			prettyJSON, err := formatJSON([]byte(l))
			if err == nil {
				colorPattern := getColorStr(pattern, colorYELLOW)
				buff := strings.ReplaceAll(string(prettyJSON), pattern, colorPattern)
				fmt.Printf(" (%d) %s\n", i+1, buff)
			}
		} else {
			var entry logs.LogEntry
			var content LogContent
			var bufStr string
			_ = json.Unmarshal([]byte(l), &entry)
			err := json.Unmarshal([]byte(entry.Content), &content)
			*idx++
			if err != nil {
				var tlog string
				if entry.Timestamp != nil {
					tlog = time.Unix(entry.Timestamp.Seconds, 0).Format(time.RFC3339)
				}
				bufStr = fmt.Sprintf(" -(%d) %s, %s, %s, %v(%d)", *idx, strings.TrimSuffix(entry.Content, "\n"), entry.Severity, entry.Source,
					tlog, entry.Msgid)
			} else {
				bufStr = fmt.Sprintf(" -(%d) %s, %s, %s, %s, %s, %s, %s(%d)",
					*idx, content.Msg, entry.Severity, entry.Filename, entry.Function, content.Objtype,
					content.Source, content.Time, entry.Msgid)
			}
			colorPattern := getColorStr(pattern, colorYELLOW)
			buff := strings.ReplaceAll(bufStr, pattern, colorPattern)
			fmt.Printf("%s\n", buff)
		}
		if i%20 == 0 {
			closePipe(true)
		}
	}
}

// getTimeSec -
// log/<search> -time time1-time2 to be passed in, and needs to extract
// the time1 and time2, which can be a number in hour unit, and it can be
// a rfc3339 time format, and check the higher value can not exceed the current time.
// return two unix time numbers to search for the log files in that range.
func getTimeSec(timeline string, now int64) (int64, int64) {
	var ti1, ti2 int64
	if strings.Contains(timeline, "Z-") {
		times := strings.Split(timeline, "Z-")

		t1, _ := time.Parse(time.RFC3339, times[0]+"Z")
		t2, _ := time.Parse(time.RFC3339, times[1])
		ti1 = t1.Unix()
		ti2 = t2.Unix()
		if ti1 > now {
			ti1 = now
		}
		if ti2 > now {
			ti2 = now
		}
	} else {
		times := strings.Split(timeline, "-")
		if len(times) != 2 {
			fmt.Printf("time1-time2 format invalid\n")
			return 0, 0
		}
		f1, err1 := strconv.ParseFloat(times[0], 16)
		f2, err2 := strconv.ParseFloat(times[1], 16)
		if err1 != nil || err2 != nil {
			fmt.Printf("float error %v, %v\n", err1, err2)
			return 0, 0
		}

		ti1 = now - int64(f1*3600)
		ti2 = now - int64(f2*3600)
	}
	if ti1 >= ti2 {
		return ti1, ti2
	} else {
		return ti2, ti1
	}
}
