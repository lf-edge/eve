// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

func isNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func checkIdentifiersInFile(path string) (bool, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return false, err
	}

	hasViolation := false

	// Walk the AST
	ast.Inspect(node, func(n ast.Node) bool {
		// inspect only the identifiers, ignoring string literals and comments
		if v, ok := n.(*ast.Ident); ok && isNonASCII(v.Name) {
			pos := fset.Position(v.Pos())
			fmt.Printf("❌ %s:%d:%d: non-ASCII identifier %q\n", pos.Filename, pos.Line, pos.Column, v.Name)
			hasViolation = true
		}
		return true
	})

	return hasViolation, nil
}

func main() {
	startPath := "."
	if len(os.Args) > 1 {
		startPath = os.Args[1]
	}

	foundViolation := false

	err := filepath.Walk(startPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// look only at go files, skip those in vendor or .go
		if filepath.Ext(path) == ".go" && !info.IsDir() && !strings.Contains(path, "vendor") && !strings.Contains(path, ".go/") {
			v, err := checkIdentifiersInFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Error parsing %s: %v\n", path, err)
				return err
			}
			if v {
				foundViolation = true
			}
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning files: %v\n", err)
		os.Exit(2)
	}

	if foundViolation {
		os.Exit(1)
	}

	fmt.Println("✅ All identifiers are ASCII-only.")
}
