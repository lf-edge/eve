// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.
// Parse either RFC3339 or ISO8601 from front of string and format as RFC3389.
// Also parse the old format "2018/09/13 23:01:20.214433"
// XXX add parsing log level strings?

package logmanager

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// Extract any date from the line and reformat it as RFC3339
// If no date found we use the lastTime; we return the time to use for
// the next line. This ensures that multi-line output gets tagged with
// a timestamp per line.
func parseDateTime(line string, lastTime time.Time, lastLevel int) (string, time.Time, int) {
	// Check if first item has a timestamp
	words := strings.SplitN(line, " ", 2)
	if len(words) == 2 {
		t, ok := parseTime(words[0])
		if ok {
			out := fmt.Sprintf("%s %s\n",
				t.Format(time.RFC3339Nano), words[1])
			return out, t, lastLevel
		}
	}
	// Try old format; date<space>time
	words = strings.SplitN(line, " ", 3)
	if len(words) == 3 {
		t, ok := parseOldTime(words[0], words[1])
		if ok {
			out := fmt.Sprintf("%s %s\n",
				t.Format(time.RFC3339Nano), words[2])
			return out, t, lastLevel
		}
	}
	// Prepend most recent timestamp;
	out := fmt.Sprintf("%s %s\n", lastTime.Format(time.RFC3339Nano),
		line)
	return out, lastTime, lastLevel
}

func parseTime(ts string) (time.Time, bool) {
	var t time.Time
	// Check that it is a potential timestamp
	if strings.Index(ts, "T") != 10 {
		return t, false
	}
	err := t.UnmarshalText([]byte(ts))
	if err == nil {
		return t, true
	}
	// Covert from ISO8601 dropping the timezone (we assume UTC)
	// Handle comma for partial seconds, and + before timezone
	// If we need to handle timezones need to split 0000 into
	// 00:00
	ts = strings.Replace(ts, ",", ".", 1)
	// XXX does the end have +nnnn or -nnnn?
	ts2 := strings.Split(ts, "+")
	if len(ts2) == 2 {
		ts = ts2[0] + "Z"
	} else {
		li := strings.LastIndex(ts, "-")
		if li != 0 {
			ts = ts[:li] + "Z"
		}
	}
	if debug {
		log.Printf("Trying %s\n", ts)
	}
	err = t.UnmarshalText([]byte(ts))
	if err != nil {
		if debug {
			log.Println(err)
		}
		return t, false
	}
	return t, true
}

// Look for 2018/09/13 23:01:20.214433
func parseOldTime(date, timeStr string) (time.Time, bool) {
	var t time.Time
	re := regexp.MustCompile(`^\d{4}/\d{2}/\d{2}`)
	matched := re.MatchString(date)
	if !matched {
		return t, false
	}
	re = regexp.MustCompile("/")
	newDateFormat := re.ReplaceAllLiteralString(date, "-")

	newDateAndTime := newDateFormat + "T" + timeStr
	layout := "2006-01-02T15:04:05"

	///convert newDateAndTime type string to type time.time
	dt, err := time.Parse(layout, newDateAndTime)
	if err != nil {
		if debug {
			log.Println(err)
		}
		return t, false
	} else {
		return dt, true
	}
}
