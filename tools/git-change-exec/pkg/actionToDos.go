// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"fmt"
	"github.com/mailru/easyjson"
	"io"
	"log"
)

// ActionToDos holds action items grouped by action ID.
//
//easyjson:json
type ActionToDos struct {
	Actions map[string][]ActionToDo
}

// ActionToDo represents a single action item with a path and optional diff.
//
//easyjson:json
type ActionToDo struct {
	Path string
	Ld   *LineDiff
}

func (atd *ActionToDos) dumpActionToDos(w io.Writer) {
	bs, err := easyjson.Marshal(atd)
	if err != nil {
		log.Fatalf("json marshalling failed: %v", err)
	}

	fmt.Fprintf(w, "%s\n", string(bs))
}

func (atd *ActionToDos) addActionToDo(a Action, path string, ld *LineDiff) {
	if atd.Actions[ID(a)] == nil {
		atd.Actions[ID(a)] = make([]ActionToDo, 0)
	}
	atd.Actions[ID(a)] = append(atd.Actions[ID(a)], ActionToDo{
		Path: path,
		Ld:   ld,
	})
}
