// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// breakUsage is printed for `break` with no or a bad action.
// A var, not a const: it embeds state.WaitItemDir, which tests shadow.
var breakUsage = `Usage: k3s-sctl break <set|clear|list> [name|--all]

Breakpoints hold the daemon at a named point so the node can be
inspected there. They are files under ` + state.WaitItemDir + `, which is on
/persist, so a breakpoint can be staged and then survive the reboot
that reaches the point of interest.

  k3s-sctl break set longhorn     hold just before Longhorn applies
  k3s-sctl break clear longhorn   release it
  k3s-sctl break clear --all      release every breakpoint
  k3s-sctl break list             show staged breakpoints

Names are the deploy-graph component names (longhorn, kubevirt, cdi,
descheduler, multus, ...) plus three fixed points:

  k3s-install   before the k3s version check and install
  containerd    before containerd starts
  wait          once per health tick — freezes steady-state
                housekeeping so the node can be worked on by hand

Staging and clearing are plain file operations and do not need the
daemon, which is the point: a daemon wedged before its control socket
is up is exactly when a breakpoint is worth staging. To see whether the
daemon has actually reached one and stopped there, use "k3s-sctl status"
and look for breakpoint=<name>.`

// runBreak handles the `break` subcommand entirely client-side.
// Returns the process exit code.
func runBreak(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, breakUsage)
		return 1
	}

	switch args[0] {
	case "set":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "k3s-sctl break set: expected exactly one name")
			return 1
		}
		return breakSet(args[1])
	case "clear":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "k3s-sctl break clear: expected a name or --all")
			return 1
		}
		if args[1] == "--all" {
			return breakClearAll()
		}
		return breakClear(args[1])
	case "list":
		return breakList()
	default:
		fmt.Fprintln(os.Stderr, breakUsage)
		return 1
	}
}

// validBreakName rejects names that would escape WaitItemDir or
// produce a file the daemon can never match.
func validBreakName(name string) error {
	if name == "" {
		return fmt.Errorf("empty breakpoint name")
	}
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return fmt.Errorf("invalid breakpoint name %q", name)
	}
	return nil
}

func breakSet(name string) int {
	if err := validBreakName(name); err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(state.WaitItemDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: create %s: %v\n", state.WaitItemDir, err)
		return 1
	}
	path := state.ItemPath(name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: set breakpoint %s: %v\n", path, err)
		return 1
	}
	_ = f.Close()
	fmt.Printf("breakpoint %q set (%s)\n", name, path)
	fmt.Println("the daemon holds there until it is cleared; " +
		"check \"k3s-sctl status\" for breakpoint=<name>")
	return 0
}

func breakClear(name string) int {
	if err := validBreakName(name); err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: %v\n", err)
		return 1
	}
	path := state.ItemPath(name)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		fmt.Printf("breakpoint %q was not set\n", name)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: clear breakpoint %s: %v\n", path, err)
		return 1
	}
	fmt.Printf("breakpoint %q cleared\n", name)
	return 0
}

func breakClearAll() int {
	names, err := stagedBreakpoints()
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: %v\n", err)
		return 1
	}
	if len(names) == 0 {
		fmt.Println("no breakpoints set")
		return 0
	}
	rc := 0
	for _, n := range names {
		if err := os.Remove(state.ItemPath(n)); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "k3s-sctl: clear %q: %v\n", n, err)
			rc = 1
			continue
		}
		fmt.Printf("breakpoint %q cleared\n", n)
	}
	return rc
}

func breakList() int {
	names, err := stagedBreakpoints()
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: %v\n", err)
		return 1
	}
	if len(names) == 0 {
		fmt.Println("no breakpoints set")
		return 0
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return 0
}

// stagedBreakpoints lists breakpoint names present on disk. A missing
// directory means none are staged, not an error.
func stagedBreakpoints() ([]string, error) {
	entries, err := os.ReadDir(state.WaitItemDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", state.WaitItemDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n, ok := strings.CutPrefix(filepath.Base(e.Name()), "wait_"); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}
