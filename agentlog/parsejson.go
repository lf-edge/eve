// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package agentlog

import (
	"encoding/json"
	"log"
)

const debug = true // XXX remove?

// Extend this structure with optional specific tags from
// log.WithFields
type Loginfo struct {
	Level string `json:"level"`
	Time  string `json:"time"` // RFC3339 with Nanoseconds
	Msg   string `json:"msg"`
}

// Returns loginfo, ok
func ParseLoginfo(line string) (Loginfo, bool) {
	var output Loginfo
	if err := json.Unmarshal([]byte(line), &output); err != nil {
		if debug {
			log.Printf("json Unmarshal in parseLoginfo: %s\n", err)
		}
		return output, false
	}
	return output, true
}

// XXX dev
func PrintLoginfo(li Loginfo) {
	b, err := json.MarshalIndent(li, "", "    ")
	if err != nil {
		log.Fatal(err, "json Marshal in printLoginfo")
	}
	log.Printf("%s\n", b)
}
