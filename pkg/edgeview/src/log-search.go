// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	newlogDir  = "/persist/newlog"
	collectDir = newlogDir + "/collect"
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
		copylogfiles = true
	}

	if copylogfiles {
		timeRange := &logSearchRange{
			starttime: t1,
			endtime:   t2,
		}
		// tar the logfiles result with the time range
		getTarFile("tar//persist/newlog", timeRange)
		return
	}

	gfiles := walkLogDirs(t1, t2)
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
			time.Sleep(200 * time.Millisecond)
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

func walkLogDirs(toTimestamp, fromTimestamp int64) []logfiletime {
	var getfiles []logfiletime

	subdirs, err := os.ReadDir(newlogDir)
	if err != nil {
		fmt.Printf("read %s error %v\n", newlogDir, err)
		return getfiles
	}

	excludeDirs := []string{"collect", "panic", "devUpload"}
	if querytype == "dev" {
		excludeDirs = append(excludeDirs, "appUpload")
	}
	excludeFiles := []string{}
	if querytype == "app" {
		excludeFiles = append(excludeFiles, "dev")
	}
	if querytype == "dev" {
		excludeFiles = append(excludeFiles, "app")
	}

	for _, dir := range subdirs {
		if filterDir(dir, excludeDirs) {
			continue
		}

		files, err := os.ReadDir(path.Join(newlogDir, dir.Name()))
		if err != nil {
			fmt.Printf("read %s error %v\n", path.Join(newlogDir, dir.Name()), err)
			continue
		}
		for _, f := range files {
			if filterFile(f, excludeFiles) {
				continue
			}

			timestamp, err := types.GetTimestampFromGzipName(f.Name())
			if err != nil {
				continue
			}
			ftime := timestamp.Unix() // convert to seconds

			if ftime >= fromTimestamp && ftime <= toTimestamp {
				file1 := strings.TrimPrefix(f.Name(), "./")
				gfile := logfiletime{
					filepath: path.Join(newlogDir, dir.Name(), file1),
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

func filterDir(dir os.DirEntry, filter []string) bool {
	if !dir.IsDir() {
		return true
	}
	for _, name := range filter {
		if strings.Contains(dir.Name(), name) {
			return true
		}
	}
	return false
}

func filterFile(file os.DirEntry, filter []string) bool {
	if file.IsDir() {
		return true
	}
	for _, name := range filter {
		if strings.Contains(file.Name(), name) {
			return true
		}
	}
	return false
}

func searchLiveLogs(pattern string, now int64, typeStr string, idx *int, logjson bool) {
	var filesToGrep []string
	switch typeStr {
	case "dev":
		filesToGrep = append(filesToGrep, path.Join(collectDir, "current.device.log"))
	case "app":
		files, err := os.ReadDir(collectDir)
		if err != nil {
			fmt.Printf("searchLiveLogs: read %s: error %v\n", collectDir, err)
			return
		}

		for _, l := range files {
			if strings.HasPrefix(l.Name(), "app") {
				filesToGrep = append(filesToGrep, path.Join(collectDir, l.Name()))
			}
		}
	default:
		fmt.Printf("searchLiveLogs: invalid typeStr %v\n", typeStr)
	}

	for _, file := range filesToGrep {
		searchCurrentLogs(pattern, file, typeStr, now, idx, logjson)
	}
}

func searchCurrentLogs(pattern, path, typeStr string, now int64, idx *int, logjson bool) {
	contents, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("searchCurrentLogs: read %s file error: %v\n", path, err)
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

// uncompress the gzip log files and pack them into a single
// json text file for device and each app logs
func unpackLogfiles(path string, files []dirEntry) {
	sfnames := make(map[string][]string)
	for _, f := range files {
		fName := filepath.Base(f.info.Name())
		if strings.Contains(fName, "dev.log.") {
			sfnames["dev"] = append(sfnames["dev"], strings.TrimPrefix(f.path, path))
		} else if strings.Contains(fName, "app.") {
			pname := strings.Split(fName, ".log.")
			if len(pname) != 2 {
				continue
			}
			sfnames[pname[0]] = append(sfnames[pname[0]], strings.TrimPrefix(f.path, path))
		}
	}

	if len(sfnames) == 0 {
		fmt.Printf("len is zero for sfnames\n")
		return
	}

	for p := range sfnames {
		textFileName := path + "/" + p + ".log.txt"
		sort.Strings(sfnames[p])
		fs, err := os.Create(textFileName)
		if err != nil {
			fmt.Printf("can't create file %v\n", err)
			return
		}

		for _, s := range sfnames[p] {
			f, err := os.Open(path + "/" + s)
			if err != nil {
				fmt.Printf("can't open file %v\n", err)
				continue
			}

			gs, err := gzip.NewReader(f)
			if err != nil {
				continue
			}

			buf := make([]byte, 4096)
			for {
				var done bool
				n, err := gs.Read(buf)
				if err != nil {
					if err != io.EOF {
						fmt.Printf("can't read gzip file %v\n", err)
						continue
					}
					done = true
				}

				_, err = fs.Write(buf[:n])
				if err != nil {
					fmt.Printf("can't write text file %v\n", err)
					if done {
						break
					}
				}
				if done {
					break
				}
			}
			gs.Close()
			f.Close()
		}

		fs.Close()
		fmt.Printf("\n uncompressed into %s\n", textFileName)
	}

	// remove the gzip files and directories.
	for _, f := range files {
		relPath, err := filepath.Rel(path, f.path)
		if err != nil {
			fmt.Printf("check gzip file path error %v\n", err)
		}
		err = os.Remove(filepath.Join(path, relPath))
		if err != nil {
			fmt.Printf("delete gzip file error %v\n", err)
		}
	}

	dirPath := path
	_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != dirPath {
			err := os.RemoveAll(path)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
