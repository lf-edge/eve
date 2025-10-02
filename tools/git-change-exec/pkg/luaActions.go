// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	lua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

// LuaAction wraps a Lua script as an action.
type LuaAction struct {
	id         string
	script     string
	matchState *lua.LState
}

// LuaLoad creates a LuaAction from a name and script source.
func LuaLoad(name string, script string) *LuaAction {
	la := LuaAction{
		script: script,
	}

	la.id = name

	return &la
}

// ID returns the action identifier.
func (la *LuaAction) ID() string {
	return la.id
}

func (la *LuaAction) do(actionToDos []ActionToDo) error {
	state := lua.NewState(lua.Options{SkipOpenLibs: true, IncludeGoStackTrace: true})
	la.luaLoadBaseFunctions(state)
	la.luaLoadExtendedFunctions(state)

	defer state.Close()

	if err := state.DoString(la.script); err != nil {
		panic(err)
	}

	err := state.CallByParam(lua.P{
		Fn:      state.GetGlobal("exec"),
		NRet:    1,
		Protect: true,
	}, luar.New(state, actionToDos))
	if err != nil {
		return fmt.Errorf("running exec failed: %w", err)
	}
	ret := state.Get(-1) // returned value
	defer state.Pop(1)   // remove received value
	switch val := ret.(type) {
	case lua.LBool:
		if !val {
			return fmt.Errorf("action failed")
		}
	case lua.LNumber:
		if val != 0 {
			return fmt.Errorf("action failed, return %v", val)
		}
	}

	return nil
}

type luaFile struct {
	path string
}

func (lf luaFile) Path() string {
	return lf.path
}

func (lf luaFile) Lines() []string {
	bs, err := os.ReadFile(lf.path)
	if err != nil {
		log.Fatalf("could not read file %s: %v", lf.path, err)
	}

	lines := strings.Split(string(bs), "\n")

	return lines
}

func (la *LuaAction) match(path string, ld LineDiff) bool {
	var retBool bool

	if la.matchState == nil {
		la.matchState = lua.NewState(lua.Options{SkipOpenLibs: true, IncludeGoStackTrace: true})
		la.luaLoadBaseFunctions(la.matchState)

		if err := la.matchState.DoString(la.script); err != nil {
			panic(err)
		}
	}

	state := la.matchState

	lf := luaFile{
		path: path,
	}

	state.SetTop(0)
	if err := state.CallByParam(lua.P{
		Fn:      state.GetGlobal("match"),
		NRet:    1,
		Protect: true,
	}, luar.New(state, lf), luar.New(state, ld)); err != nil {
		log.Fatalf("could not call 'match': %v", err)
	}
	ret := state.Get(-1) // returned value
	switch val := ret.(type) {
	case lua.LBool:
		retBool = bool(val)
	case lua.LNumber:
		retBool = val == 0
	}

	return bool(retBool)
}

func (la *LuaAction) luaLoadExtendedFunctions(state *lua.LState) {
	lua.OpenOs(state)
	lua.OpenIo(state)
	lua.OpenPackage(state)
	lua.OpenChannel(state)
	lua.OpenCoroutine(state)
}

func (la *LuaAction) luaLoadBaseFunctions(state *lua.LState) {
	lua.OpenBase(state)
	lua.OpenString(state)
	lua.OpenMath(state)
}

// Do executes the Lua action's exec function with the given action items.
func (la *LuaAction) Do(actionToDos []ActionToDo) error {
	return la.do(actionToDos)
}

// Close releases the Lua state.
func (la *LuaAction) Close() {
	if la.matchState != nil {
		la.matchState.Close()
	}
}

// MatchDiff calls the Lua match function for a path and line diff.
func (la *LuaAction) MatchDiff(path string, ld LineDiff) bool {
	return la.match(path, ld)
}

// ListLuaActions recursively finds all .gce.lua files under the given path.
func ListLuaActions(path string) []string {
	actionLuaFiles := make([]string, 0)
	filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if d == nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".gce.lua") {
			return nil
		}
		actionLuaFiles = append(actionLuaFiles, path)
		return nil
	})
	return actionLuaFiles
}
