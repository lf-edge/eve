// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// list-tests scans the evetest test suite under ./tests and prints all
// available test functions grouped into two sections:
//
//   - Test suites: functions that call evetest.RunTestSuite, annotated with
//     suite-level parameters and with each test case's variants expanded
//     showing the parameter values that distinguish them.
//   - Individual tests: all other Test* functions, annotated with their
//     declared parameters (evetest.DefineTestParameters), including the
//     default value and allowed values where specified.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
)

// paramInfo describes one parameter accepted by a test or suite.
type paramInfo struct {
	key           string
	defValue      string // from Description.Default
	hasDefault    bool   // true when Description.Default was explicitly set (even if "")
	allowedValues string // from Description.AllowedValues (e.g. "kvm|xen|kubevirt")
	typeHint      string // inferred from DefaultValue literal: "bool", "string", "int", …
}

// kvParam is a resolved key=value pair used for variant parameter display.
type kvParam struct {
	key   string
	value string // human-readable value (String() representation when available)
}

// variantInfo describes one variant within a test case.
type variantInfo struct {
	name   string
	params []kvParam
}

// testCaseInfo describes one test case within a suite.
type testCaseInfo struct {
	testName string
	variants []variantInfo // empty when no Variants field is declared
}

// suiteInfo describes a test suite function.
type suiteInfo struct {
	name   string
	params []paramInfo
	cases  []testCaseInfo
}

// testInfo describes an individual (non-suite) test function.
type testInfo struct {
	name   string
	params []paramInfo
}

// pkgContext holds package-level declarations used to resolve references
// inside function bodies.
type pkgContext struct {
	constValues  map[string]string // string const name → string value (for key resolution)
	constStrings map[string]string // const name → String() return value (for variant display)
	allConsts    map[string]string // all simple const name → literal value (for variant display)
	varParams    map[string]paramInfo
}

func main() {
	testsDir := "./tests"
	if len(os.Args) > 1 {
		testsDir = os.Args[1]
	}

	// Parse the evetest framework package (parent of testsDir) to discover
	// all functions that return TestParameterDefinition.
	evetestDir := filepath.Dir(testsDir)
	paramFuncs, evetestConstValues := buildParamFuncs(evetestDir)

	// Group _test.go files by directory (= Go package).
	dirFiles := map[string][]string{}
	err := filepath.WalkDir(testsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, "_test.go") {
			dir := filepath.Dir(path)
			dirFiles[dir] = append(dirFiles[dir], path)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var suites []suiteInfo
	var allTests []testInfo

	for _, files := range dirFiles {
		fset := token.NewFileSet()
		var parsedFiles []*ast.File
		for _, path := range files {
			f, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: parsing %s: %v\n", path, parseErr)
				continue
			}
			parsedFiles = append(parsedFiles, f)
		}

		ctx := buildPkgContext(parsedFiles)
		// Inject evetest package string constants with "evetest." prefix so that
		// SelectorExpr references like evetest.DiskSizeMiBParameterKey are resolved.
		for k, v := range evetestConstValues {
			ctx.constValues["evetest."+k] = v
		}

		for _, f := range parsedFiles {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil || !strings.HasPrefix(fd.Name.Name, "Test") {
					continue
				}
				name := fd.Name.Name
				params := extractParams(fd, ctx, paramFuncs)
				cases := extractSuiteCases(fd, ctx)
				if cases != nil {
					suites = append(suites, suiteInfo{
						name:   name,
						params: params,
						cases:  cases,
					})
				} else {
					allTests = append(allTests, testInfo{name: name, params: params})
				}
			}
		}
	}

	sort.Slice(suites, func(i, j int) bool { return suites[i].name < suites[j].name })
	sort.Slice(allTests, func(i, j int) bool { return allTests[i].name < allTests[j].name })

	// Compute column width for individual tests with parameters.
	maxTestLen := 0
	for _, t := range allTests {
		if len(t.params) > 0 && len(t.name) > maxTestLen {
			maxTestLen = len(t.name)
		}
	}

	fmt.Println("Test suites:")
	fmt.Println()
	for _, s := range suites {
		if len(s.params) > 0 {
			fmt.Printf("  %s  [%s]\n", s.name, formatParams(s.params))
		} else {
			fmt.Printf("  %s\n", s.name)
		}
		for _, c := range s.cases {
			fmt.Printf("    - %s\n", c.testName)
			if len(c.variants) > 0 {
				// Compute column width across all variant names in this case.
				maxVarLen := 0
				for _, v := range c.variants {
					if len(v.params) > 0 && len(v.name) > maxVarLen {
						maxVarLen = len(v.name)
					}
				}
				for _, v := range c.variants {
					if len(v.params) > 0 {
						fmt.Printf("        %-*s  [%s]\n",
							maxVarLen, v.name, formatKVParams(v.params))
					} else {
						fmt.Printf("        %s\n", v.name)
					}
				}
			}
		}
		fmt.Println()
	}

	fmt.Println("Individual tests:")
	fmt.Println()
	for _, t := range allTests {
		if len(t.params) > 0 {
			fmt.Printf("  %-*s  [%s]\n", maxTestLen, t.name, formatParams(t.params))
		} else {
			fmt.Printf("  %s\n", t.name)
		}
	}
}

func formatParams(params []paramInfo) string {
	parts := make([]string, len(params))
	for i, pi := range params {
		key := constants.EnvPrefix + pi.key
		annotation := ""
		switch {
		case pi.allowedValues != "":
			annotation = "(" + pi.allowedValues + ")"
		case pi.typeHint != "":
			annotation = "(" + pi.typeHint + ")"
		}
		if pi.hasDefault {
			displayDefault := pi.defValue
			if displayDefault == "" {
				displayDefault = `""`
			}
			parts[i] = key + annotation + ", default: " + displayDefault
		} else {
			parts[i] = key + annotation
		}
	}
	return strings.Join(parts, "; ")
}

func formatKVParams(params []kvParam) string {
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = constants.EnvPrefix + p.key + "=" + p.value
	}
	return strings.Join(parts, ", ")
}

// buildPkgContext scans package-level declarations and method definitions to
// build lookup tables used when resolving parameter definitions and variant
// parameter values. It runs in three passes:
//  1. Collect string const values (used to resolve Key fields).
//  2. Parse String() method bodies to map const names to their string
//     representations (used to display variant parameter values).
//  3. Resolve TestParameterDefinition variables.
func buildPkgContext(files []*ast.File) pkgContext {
	ctx := pkgContext{
		constValues:  map[string]string{},
		constStrings: map[string]string{},
		allConsts:    map[string]string{},
		varParams:    map[string]paramInfo{},
	}

	// Pass 1: collect const values (package-level and function-local).
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					// String consts go into constValues (used for key resolution).
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						ctx.constValues[name.Name] = unquote(lit.Value)
					}
					// All simple literal consts go into allConsts (used for display).
					if v, ok := extractConstLiteralValue(vs.Values[i]); ok {
						ctx.allConsts[name.Name] = v
					}
				}
			}
			return true
		})
	}

	// Pass 2: parse String() methods to get human-readable const representations.
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || fd.Name.Name != "String" || fd.Recv == nil {
				continue
			}
			if !returnsSingleString(fd) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				sw, ok := n.(*ast.SwitchStmt)
				if !ok {
					return true
				}
				for _, stmt := range sw.Body.List {
					cc, ok := stmt.(*ast.CaseClause)
					if !ok || len(cc.List) == 0 {
						continue
					}
					retStr := caseReturnString(cc)
					if retStr == "" || retStr == "undefined" {
						continue
					}
					for _, caseExpr := range cc.List {
						if id, ok := caseExpr.(*ast.Ident); ok {
							ctx.constStrings[id.Name] = retStr
						}
					}
				}
				return false
			})
		}
	}

	// Pass 3: resolve TestParameterDefinition variables.
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					pi, ok := extractParamDefLit(vs.Values[i], ctx)
					if !ok {
						continue
					}
					ctx.varParams[name.Name] = pi
				}
			}
		}
	}

	return ctx
}

// caseReturnString extracts the string literal returned by the first ReturnStmt
// in a CaseClause body, or "" if none is found.
func caseReturnString(cc *ast.CaseClause) string {
	for _, s := range cc.Body {
		ret, ok := s.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		lit, ok := ret.Results[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		return unquote(lit.Value)
	}
	return ""
}

// returnsSingleString reports whether fd's sole return value is string.
func returnsSingleString(fd *ast.FuncDecl) bool {
	res := fd.Type.Results
	if res == nil || len(res.List) != 1 {
		return false
	}
	id, ok := res.List[0].Type.(*ast.Ident)
	return ok && id.Name == "string"
}

// buildParamFuncs parses the non-test Go source files in sourceDir and returns
// a map from function name to the paramInfo it produces for every function
// whose sole return type is TestParameterDefinition, plus the package's string
// constant map (used by callers to resolve evetest.XxxKey references).
func buildParamFuncs(sourceDir string) (map[string]paramInfo, map[string]string) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, nil
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(sourceDir, name), nil, 0)
		if err != nil {
			continue
		}
		files = append(files, f)
	}

	ctx := buildPkgContext(files)
	result := map[string]paramInfo{}

	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || !returnsParamDef(fd) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				comp, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				pi, ok := extractParamDefLit(comp, ctx)
				if !ok {
					return true
				}
				result[fd.Name.Name] = pi
				return false
			})
		}
	}
	return result, ctx.constValues
}

// returnsParamDef reports whether fd's sole return value is TestParameterDefinition.
func returnsParamDef(fd *ast.FuncDecl) bool {
	res := fd.Type.Results
	if res == nil || len(res.List) != 1 {
		return false
	}
	id, ok := res.List[0].Type.(*ast.Ident)
	return ok && id.Name == "TestParameterDefinition"
}

// extractParams finds the evetest.DefineTestParameters call in fd and returns
// the resolved parameter definitions.
func extractParams(
	fd *ast.FuncDecl, ctx pkgContext, paramFuncs map[string]paramInfo) []paramInfo {
	var params []paramInfo
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "evetest" || sel.Sel.Name != "DefineTestParameters" {
			return true
		}
		for _, arg := range call.Args {
			if pi, ok := resolveParamArg(arg, ctx, paramFuncs); ok {
				params = append(params, pi)
			}
		}
		return true
	})
	return params
}

// resolveParamArg resolves one argument of DefineTestParameters into a paramInfo.
func resolveParamArg(
	arg ast.Expr, ctx pkgContext, paramFuncs map[string]paramInfo) (paramInfo, bool) {
	switch a := arg.(type) {
	case *ast.CallExpr:
		// evetest.XxxParameter() constructor call.
		sel, ok := a.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "evetest" {
			break
		}
		if pi, ok := paramFuncs[sel.Sel.Name]; ok {
			return pi, true
		}
	case *ast.CompositeLit:
		// Inline evetest.TestParameterDefinition{...} literal.
		return extractParamDefLit(a, ctx)
	case *ast.Ident:
		// Variable reference (e.g. lastResortParam).
		if pi, ok := ctx.varParams[a.Name]; ok {
			return pi, true
		}
	}
	return paramInfo{}, false
}

// extractParamDefLit extracts a paramInfo from an evetest.TestParameterDefinition
// composite literal (qualified or unqualified form). It reads the Key field and
// the Description.Default / Description.AllowedValues string literal fields.
func extractParamDefLit(expr ast.Expr, ctx pkgContext) (paramInfo, bool) {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok || !isParamDefType(comp.Type) {
		return paramInfo{}, false
	}
	var key, defValue, allowedValues, typeHint string
	var hasDefault bool
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		field, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch field.Name {
		case "Key":
			key = resolveStringExpr(kv.Value, ctx)
		case "DefaultValue":
			typeHint = inferSimpleType(kv.Value)
		case "Description":
			descComp, ok := kv.Value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, descElt := range descComp.Elts {
				descKV, ok := descElt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				descField, ok := descKV.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch descField.Name {
				case "Default":
					defValue = resolveStringExpr(descKV.Value, ctx)
					hasDefault = true
				case "AllowedValues":
					allowedValues = resolveStringExpr(descKV.Value, ctx)
				}
			}
		}
	}
	if key == "" {
		return paramInfo{}, false
	}
	return paramInfo{
		key: key, defValue: defValue, hasDefault: hasDefault,
		allowedValues: allowedValues, typeHint: typeHint,
	}, true
}

// inferSimpleType returns a type name for basic literal and bool expressions,
// or "" when the expression is too complex to classify (e.g. a typed const).
func inferSimpleType(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if e.Name == "true" || e.Name == "false" {
			return "bool"
		}
	case *ast.BasicLit:
		switch e.Kind {
		case token.STRING:
			return "string"
		case token.INT:
			return "int"
		case token.FLOAT:
			return "float64"
		}
	}
	return ""
}

func isParamDefType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "evetest" && t.Sel.Name == "TestParameterDefinition"
	case *ast.Ident:
		return t.Name == "TestParameterDefinition"
	}
	return false
}

// resolveStringExpr extracts a string value from an expression expected to be
// a string constant (literal or named const, possibly from another package).
func resolveStringExpr(expr ast.Expr, ctx pkgContext) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return unquote(e.Value)
		}
	case *ast.Ident:
		if v, ok := ctx.constValues[e.Name]; ok {
			return v
		}
	case *ast.SelectorExpr:
		if pkg, ok := e.X.(*ast.Ident); ok {
			if v, ok := ctx.constValues[pkg.Name+"."+e.Sel.Name]; ok {
				return v
			}
		}
	}
	return ""
}

// extractSuiteCases returns the test cases listed in the evetest.RunTestSuite
// call within fd, or nil if fd does not call RunTestSuite.
func extractSuiteCases(fd *ast.FuncDecl, ctx pkgContext) []testCaseInfo {
	var cases []testCaseInfo
	found := false

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "evetest" || sel.Sel.Name != "RunTestSuite" {
			return true
		}
		found = true
		for _, arg := range call.Args {
			comp, ok := arg.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var testName string
			var variants []variantInfo
			for _, elt := range comp.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				field, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch field.Name {
				case "Test":
					if id, ok := kv.Value.(*ast.Ident); ok {
						testName = id.Name
					}
				case "Variants":
					variants = extractVariants(kv.Value, ctx)
				}
			}
			if testName != "" {
				cases = append(cases, testCaseInfo{testName: testName, variants: variants})
			}
		}
		return true
	})

	if !found {
		return nil
	}
	return cases
}

// extractVariants extracts the variant names and their parameter values from a
// []evetest.TestVariant slice expression.
func extractVariants(expr ast.Expr, ctx pkgContext) []variantInfo {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var variants []variantInfo
	for _, elt := range comp.Elts {
		varComp, ok := elt.(*ast.CompositeLit)
		if !ok {
			continue
		}
		var name string
		var params []kvParam
		for _, vElt := range varComp.Elts {
			kv, ok := vElt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			field, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch field.Name {
			case "Name":
				if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					name = unquote(lit.Value)
				}
			case "Parameters":
				params = extractKVParams(kv.Value, ctx)
			}
		}
		if name != "" {
			variants = append(variants, variantInfo{name: name, params: params})
		}
	}
	return variants
}

// extractKVParams extracts []evetest.TestParameterValue into []kvParam,
// resolving Key const references and Value display strings via ctx.
func extractKVParams(expr ast.Expr, ctx pkgContext) []kvParam {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var params []kvParam
	for _, elt := range comp.Elts {
		pvComp, ok := elt.(*ast.CompositeLit)
		if !ok {
			continue
		}
		var key, value string
		for _, pvElt := range pvComp.Elts {
			kv, ok := pvElt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			field, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch field.Name {
			case "Key":
				key = resolveStringExpr(kv.Value, ctx)
			case "Value":
				value = resolveDisplayValue(kv.Value, ctx)
			}
		}
		if key != "" {
			params = append(params, kvParam{key: key, value: value})
		}
	}
	return params
}

// resolveDisplayValue returns a human-readable string for a parameter value
// expression, using String() representations where available.
func resolveDisplayValue(expr ast.Expr, ctx pkgContext) string {
	if id, ok := expr.(*ast.Ident); ok {
		if s, ok := ctx.constStrings[id.Name]; ok {
			return s
		}
		if s, ok := ctx.allConsts[id.Name]; ok {
			return s
		}
		return id.Name
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return unquote(e.Value)
		}
		return e.Value
	case *ast.SelectorExpr:
		if s, ok := ctx.constStrings[e.Sel.Name]; ok {
			return s
		}
		return e.Sel.Name
	case *ast.CallExpr:
		// Handle inline type conversions like uint32(20480).
		if len(e.Args) == 1 {
			if v, ok := extractConstLiteralValue(e.Args[0]); ok {
				return v
			}
		}
	}
	return "?"
}

// extractConstLiteralValue returns the display string for a simple constant
// initializer expression (string/numeric literal, bool ident, or a single-arg
// type-conversion call such as uint32(20480)).
func extractConstLiteralValue(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return unquote(e.Value), true
		}
		return e.Value, true
	case *ast.Ident:
		if e.Name == "true" || e.Name == "false" {
			return e.Name, true
		}
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			if inner, ok := e.Args[0].(*ast.BasicLit); ok {
				if inner.Kind == token.STRING {
					return unquote(inner.Value), true
				}
				return inner.Value, true
			}
		}
	}
	return "", false
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
