// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// helperPkg declares its parameters the way tests/konvert does: the test calls
// a package-local helper, which collects the shared set in a local variable,
// appends what the caller passed, and spreads the result into
// evetest.DefineTestParameters.
const helperPkg = `
package fixture_test

const (
	initialVersionKey = "INITIAL_EVE_VERSION"
	refuseReasonKey   = "REFUSE_REASON"
)

func TestFollowsHelper(test *testing.T) {
	defineParameters(refusedDefinitions()...)
}

func defineParameters(extra ...evetest.TestParameterDefinition) {
	shared := []evetest.TestParameterDefinition{
		evetest.TPMParameter(),
		{
			Key:          initialVersionKey,
			DefaultValue: "10.1.0",
			Description: evetest.TestParameterDescription{
				Summary: "Released EVE version the device boots first",
				Default: "10.1.0",
			},
		},
	}
	evetest.DefineTestParameters(append(shared, extra...)...)
}

func refusedDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		{
			Key: refuseReasonKey,
			Description: evetest.TestParameterDescription{
				Summary:       "Why the conversion must be refused",
				Default:       "zfs",
				AllowedValues: "zfs|too-full",
			},
		},
	}
}
`

func TestExtractParamsFollowsHelpers(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture_test.go", helperPkg, 0)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	ctx := buildPkgContext([]*ast.File{file})
	paramFuncs := map[string]paramInfo{
		"TPMParameter": {key: "TPM", defValue: "true", hasDefault: true, typeHint: "bool"},
	}

	var fd *ast.FuncDecl
	for _, decl := range file.Decls {
		if decl, ok := decl.(*ast.FuncDecl); ok && decl.Name.Name == "TestFollowsHelper" {
			fd = decl
		}
	}
	if fd == nil {
		t.Fatal("fixture has no TestFollowsHelper")
	}

	want := []paramInfo{
		{key: "TPM", defValue: "true", hasDefault: true, typeHint: "bool"},
		{key: "INITIAL_EVE_VERSION", defValue: "10.1.0", hasDefault: true, typeHint: "string"},
		{key: "REFUSE_REASON", defValue: "zfs", hasDefault: true, allowedValues: "zfs|too-full"},
	}
	got := extractParams(fd, ctx, paramFuncs)
	if len(got) != len(want) {
		t.Fatalf("got %d parameters %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parameter %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
