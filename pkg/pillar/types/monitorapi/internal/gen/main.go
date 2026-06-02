// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command gen is the monitorapi contract generator: it reads the monitorapi
// package (AST only, offline) and emits BOTH sides of the wire:
//   - idiomatic Rust serde types (-rust <file>, or stdout)
//   - the Go JSON (de)serializer for sealed-interface tagged unions
//     (<src>/union_json.gen.go) — per-variant MarshalJSON, a dispatcher, and a
//     parent UnmarshalJSON for any struct holding a union field.
//
// It is deliberately NOT a general Go->Rust compiler. It understands exactly
// the conventions the contract package uses:
//   - structs                 -> Rust struct (serde, per-field rename to wire tag)
//   - `type X string` + consts -> Rust string enum
//   - sealed interface        -> Rust internally-tagged enum + Go union codec
//
// Usage: go run ./internal/gen -src . -rust path/to/eve_types.gen.rs
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"sort"
	"strings"
)

var fset *token.FileSet

// scalarMap maps Go scalar types (by source spelling) to Rust types.
var scalarMap = map[string]string{
	"string":           "String",
	"bool":             "bool",
	"int":              "i64",
	"int32":            "i32",
	"int64":            "i64",
	"uint":             "u64",
	"uint8":            "u8",
	"uint16":           "u16",
	"uint32":           "u32",
	"uint64":           "u64",
	"float64":          "f64",
	"netip.Addr":       "IpAddr",
	"netip.Prefix":     "IpNet",
	"time.Time":        "DateTime<Utc>",
	"uuid.UUID":        "Uuid",
	"net.HardwareAddr": "MacAddr",
}

// goImportFor maps a Go type spelling prefix to the import it needs (for the
// shadow structs in the generated Go file).
var goImportFor = map[string]string{
	"netip.": "net/netip",
	"time.":  "time",
	"net.":   "net",
}

type field struct {
	goName    string // Go struct field name
	jsonTag   string
	goTypeSrc string // Go source spelling of the type, e.g. "*netip.Addr"
	rustType  string // base Rust type (no Option/Vec wrapper)
	optional  bool   // pointer
	slice     bool
	omitempty bool
	unionName string // non-empty if the field's type is a union interface
}

type enumDef struct {
	name     string
	variants [][2]string // {rustIdent, wireValue}
}

type structDef struct {
	name   string
	fields []field
}

type unionDef struct {
	name     string
	tag      string      // discriminator JSON key
	prefix   string      // common variant-type-name prefix to strip (e.g. "Proxy")
	variants []structDef // each variant: type name + its fields (empty => unit)
}

// package-level state populated during the AST scan
var (
	typeSpecs   = map[string]*ast.TypeSpec{}
	stringEnums = map[string]bool{}
	unionIfaces = map[string]string{} // iface name -> tag key
	sealMethods = map[string]string{} // seal method name -> union name
	constsByTyp = map[string][][2]string{}
)

func main() {
	src := flag.String("src", ".", "directory of the monitorapi package to read")
	rustOut := flag.String("rust", "", "path to write generated Rust (default: stdout)")
	goOut := flag.String("goout", "", "directory to write the generated Go codec (default: -src dir)")
	flag.Parse()
	dir := *src
	goDir := *goOut
	if goDir == "" {
		goDir = dir
	}
	fset = token.NewFileSet()
	// Skip generated and test files so regeneration is idempotent.
	filter := func(fi fs.FileInfo) bool {
		n := fi.Name()
		return !strings.HasSuffix(n, ".gen.go") && !strings.HasSuffix(n, "_test.go")
	}
	pkgs, err := parser.ParseDir(fset, dir, filter, parser.ParseComments)
	if err != nil {
		fail(err)
	}

	methodsByRecv := map[string][]string{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					collectGenDecl(d)
				case *ast.FuncDecl:
					if d.Recv != nil && len(d.Recv.List) == 1 {
						recv := exprName(d.Recv.List[0].Type)
						methodsByRecv[recv] = append(methodsByRecv[recv], d.Name.Name)
					}
				}
			}
		}
	}

	// Resolve union variants: types whose method set contains a seal method.
	unionVariants := map[string]bool{}
	unions := map[string]*unionDef{}
	for iface, tag := range unionIfaces {
		unions[iface] = &unionDef{name: iface, tag: tag}
	}
	for recv, methods := range methodsByRecv {
		for _, m := range methods {
			if union, ok := sealMethods[m]; ok {
				unionVariants[recv] = true
				vd := structDef{name: recv}
				if ts := typeSpecs[recv]; ts != nil {
					if st, ok := ts.Type.(*ast.StructType); ok {
						vd.fields = collectFields(st)
					}
				}
				unions[union].variants = append(unions[union].variants, vd)
			}
		}
	}

	var enums []enumDef
	for name, consts := range constsByTyp {
		if !stringEnums[name] {
			continue
		}
		e := enumDef{name: name}
		for _, c := range consts {
			e.variants = append(e.variants, [2]string{normType(stripPrefix(c[0], name)), c[1]})
		}
		enums = append(enums, e)
	}

	var structs []structDef
	for name, ts := range typeSpecs {
		if stringEnums[name] || unionVariants[name] {
			continue
		}
		if _, isUnion := unionIfaces[name]; isUnion {
			continue
		}
		if st, ok := ts.Type.(*ast.StructType); ok {
			structs = append(structs, structDef{name: name, fields: collectFields(st)})
		}
	}

	sort.Slice(enums, func(i, j int) bool { return enums[i].name < enums[j].name })
	sort.Slice(structs, func(i, j int) bool { return structs[i].name < structs[j].name })
	var unionList []*unionDef
	for _, u := range unions {
		sort.Slice(u.variants, func(i, j int) bool { return u.variants[i].name < u.variants[j].name })
		u.prefix = commonVariantPrefix(u.variants)
		unionList = append(unionList, u)
	}
	sort.Slice(unionList, func(i, j int) bool { return unionList[i].name < unionList[j].name })

	emitRust(enums, structs, unionList, *rustOut)
	emitGo(goDir, structs, unionList)
}

// ---------------- Rust emission ----------------

func emitRust(enums []enumDef, structs []structDef, unions []*unionDef, out string) {
	var b strings.Builder
	b.WriteString("// Copyright (c) 2026 Zededa, Inc.\n")
	b.WriteString("// SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("// @generated by pkg/pillar/types/monitorapi/internal/gen — DO NOT EDIT.\n")
	b.WriteString("// Source of truth: pkg/pillar/types/monitorapi (Go).\n\n")
	// Contract types are introduced ahead of the consumers that use them as
	// messages are migrated one at a time, so some are legitimately unused.
	b.WriteString("#![allow(dead_code)]\n\n")
	for _, imp := range rustImports(structs, unions) {
		b.WriteString(imp)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')

	for _, e := range enums {
		b.WriteString("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]\n")
		fmt.Fprintf(&b, "pub enum %s {\n", normType(e.name))
		for _, v := range e.variants {
			fmt.Fprintf(&b, "    #[serde(rename = %q)]\n    %s,\n", v[1], v[0])
		}
		b.WriteString("}\n\n")
	}

	for _, s := range structs {
		emitDerives(&b, s.fields)
		fmt.Fprintf(&b, "pub struct %s {\n", normType(s.name))
		for _, f := range s.fields {
			emitRustField(&b, f, "    ", true)
		}
		b.WriteString("}\n\n")
	}

	for _, u := range unions {
		b.WriteString("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n")
		fmt.Fprintf(&b, "#[serde(tag = %q, rename_all = \"camelCase\")]\n", u.tag)
		fmt.Fprintf(&b, "pub enum %s {\n", normType(u.name))
		for _, v := range u.variants {
			ident := variantIdent(u.prefix, v.name)
			if len(v.fields) == 0 {
				fmt.Fprintf(&b, "    %s,\n", ident)
				continue
			}
			fmt.Fprintf(&b, "    %s {\n", ident)
			for _, f := range v.fields {
				emitRustField(&b, f, "        ", false)
			}
			b.WriteString("    },\n")
		}
		b.WriteString("}\n\n")
	}

	if out == "" {
		fmt.Print(b.String())
		return
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fail(err)
	}
	fmt.Fprintln(os.Stderr, "wrote", out)
}

// rustImports returns the `use` lines needed by the emitted types. serde is
// always required; the rest depend on which scalar types actually appear.
func rustImports(structs []structDef, unions []*unionDef) []string {
	// rust base type token -> use line
	byToken := map[string]string{
		"IpAddr":   "use std::net::IpAddr;",
		"IpNet":    "use ipnet::IpNet;",
		"Uuid":     "use uuid::Uuid;",
		"DateTime": "use chrono::{DateTime, Utc};",
		"MacAddr":  "use macaddr::MacAddr;",
	}
	needed := map[string]bool{}
	scan := func(fields []field) {
		for _, f := range fields {
			for token := range byToken {
				if strings.Contains(f.rustType, token) {
					needed[byToken[token]] = true
				}
			}
		}
	}
	for _, s := range structs {
		scan(s.fields)
	}
	for _, u := range unions {
		for _, v := range u.variants {
			scan(v.fields)
		}
	}
	imports := []string{"use serde::{Deserialize, Serialize};"}
	for _, line := range byToken {
		if needed[line] {
			imports = append(imports, line)
		}
	}
	sort.Strings(imports)
	return imports
}

func emitDerives(b *strings.Builder, fields []field) {
	eq := true
	for _, f := range fields {
		if strings.Contains(f.rustType, "f64") {
			eq = false
		}
	}
	if eq {
		b.WriteString("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n")
	} else {
		b.WriteString("#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\n")
	}
}

func emitRustField(b *strings.Builder, f field, indent string, withPub bool) {
	ty := normType(f.rustType)
	if f.slice {
		ty = "Vec<" + ty + ">"
	}
	if f.optional {
		ty = "Option<" + ty + ">"
	}
	fmt.Fprintf(b, "%s#[serde(rename = %q", indent, f.jsonTag)
	switch {
	case f.optional && f.omitempty:
		b.WriteString(", default, skip_serializing_if = \"Option::is_none\"")
	case f.slice && f.omitempty:
		b.WriteString(", default, skip_serializing_if = \"Vec::is_empty\"")
	case f.optional || f.slice:
		// present-but-possibly-null/empty on the wire: tolerate on read, don't skip on write
		b.WriteString(", default")
	}
	b.WriteString(")]\n")
	vis := "pub "
	if !withPub { // enum-variant fields take no visibility modifier
		vis = ""
	}
	fmt.Fprintf(b, "%s%s%s: %s,\n", indent, vis, snake(f.jsonTag), ty)
}

// ---------------- Go emission ----------------

func emitGo(dir string, structs []structDef, unions []*unionDef) {
	if len(unions) == 0 {
		return
	}
	var structsWithUnion []structDef
	for _, s := range structs {
		for _, f := range s.fields {
			if f.unionName != "" {
				structsWithUnion = append(structsWithUnion, s)
				break
			}
		}
	}

	var b strings.Builder
	b.WriteString("// Copyright (c) 2026 Zededa, Inc.\n")
	b.WriteString("// SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("// Code generated by pkg/pillar/types/monitorapi/internal/gen — DO NOT EDIT.\n\n")
	b.WriteString("package monitorapi\n\n")

	imports := map[string]bool{"encoding/json": true, "fmt": true}
	for _, s := range structsWithUnion {
		for _, f := range s.fields {
			if f.unionName != "" {
				continue
			}
			for prefix, path := range goImportFor {
				if strings.Contains(f.goTypeSrc, prefix) {
					imports[path] = true
				}
			}
		}
	}
	var impList []string
	for p := range imports {
		impList = append(impList, p)
	}
	sort.Strings(impList)
	b.WriteString("import (\n")
	for _, p := range impList {
		fmt.Fprintf(&b, "\t%q\n", p)
	}
	b.WriteString(")\n\n")

	// shared helper: splice {"<key>":"<tag>"} into an object's fields
	b.WriteString(`// marshalTagged emits an internally-tagged object: {"<key>":"<tag>", ...fields}.
func marshalTagged(key, tag string, v any) ([]byte, error) {
	inner, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("{%q:%q", key, tag)
	if string(inner) == "{}" {
		return []byte(prefix + "}"), nil
	}
	return append([]byte(prefix+","), inner[1:]...), nil
}

`)

	for _, u := range unions {
		for _, v := range u.variants {
			wire := lowerFirst(variantIdent(u.prefix, v.name))
			fmt.Fprintf(&b, "func (v %s) MarshalJSON() ([]byte, error) {\n", v.name)
			fmt.Fprintf(&b, "\ttype alias %s\n", v.name)
			fmt.Fprintf(&b, "\treturn marshalTagged(%q, %q, alias(v))\n}\n\n", u.tag, wire)
		}

		fmt.Fprintf(&b, "// Unmarshal%s decodes an internally-tagged %s.\n", u.name, u.name)
		fmt.Fprintf(&b, "func Unmarshal%s(b []byte) (%s, error) {\n", u.name, u.name)
		fmt.Fprintf(&b, "\tvar disc struct {\n\t\tTag string `json:%q`\n\t}\n", u.tag)
		b.WriteString("\tif err := json.Unmarshal(b, &disc); err != nil {\n\t\treturn nil, err\n\t}\n")
		b.WriteString("\tswitch disc.Tag {\n")
		for _, v := range u.variants {
			wire := lowerFirst(variantIdent(u.prefix, v.name))
			fmt.Fprintf(&b, "\tcase %q:\n", wire)
			fmt.Fprintf(&b, "\t\tvar v %s\n", v.name)
			b.WriteString("\t\tif err := json.Unmarshal(b, &v); err != nil {\n\t\t\treturn nil, err\n\t\t}\n")
			b.WriteString("\t\treturn v, nil\n")
		}
		fmt.Fprintf(&b, "\tdefault:\n\t\treturn nil, fmt.Errorf(\"unknown %s %s %%q\", disc.Tag)\n\t}\n}\n\n", u.name, u.tag)
	}

	for _, s := range structsWithUnion {
		fmt.Fprintf(&b, "func (x *%s) UnmarshalJSON(b []byte) error {\n", s.name)
		b.WriteString("\tvar raw struct {\n")
		for _, f := range s.fields {
			if f.unionName != "" {
				fmt.Fprintf(&b, "\t\t%s json.RawMessage `json:%q`\n", f.goName, f.jsonTag)
			} else {
				fmt.Fprintf(&b, "\t\t%s %s `json:%q`\n", f.goName, f.goTypeSrc, f.jsonTag)
			}
		}
		b.WriteString("\t}\n\tif err := json.Unmarshal(b, &raw); err != nil {\n\t\treturn err\n\t}\n")
		for _, f := range s.fields {
			if f.unionName != "" {
				fmt.Fprintf(&b, "\tif len(raw.%s) > 0 {\n", f.goName)
				fmt.Fprintf(&b, "\t\tv, err := Unmarshal%s(raw.%s)\n", f.unionName, f.goName)
				b.WriteString("\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n")
				fmt.Fprintf(&b, "\t\tx.%s = v\n\t}\n", f.goName)
			} else {
				fmt.Fprintf(&b, "\tx.%s = raw.%s\n", f.goName, f.goName)
			}
		}
		b.WriteString("\treturn nil\n}\n\n")
	}

	src, err := format.Source([]byte(b.String()))
	if err != nil {
		fail(fmt.Errorf("formatting generated Go: %w", err))
	}
	out := dir + "/union_json.gen.go"
	if err := os.WriteFile(out, src, 0o644); err != nil {
		fail(err)
	}
	fmt.Fprintln(os.Stderr, "wrote", out)
}

// ---------------- AST collection ----------------

func collectGenDecl(d *ast.GenDecl) {
	switch d.Tok {
	case token.TYPE:
		for _, spec := range d.Specs {
			ts := spec.(*ast.TypeSpec)
			typeSpecs[ts.Name.Name] = ts
			if id, ok := ts.Type.(*ast.Ident); ok && id.Name == "string" {
				stringEnums[ts.Name.Name] = true
			}
			if iface, ok := ts.Type.(*ast.InterfaceType); ok {
				tag := unionTag(d.Doc, ts.Doc)
				if tag == "" {
					tag = "type"
				}
				unionIfaces[ts.Name.Name] = tag
				for _, m := range iface.Methods.List {
					if len(m.Names) == 1 {
						sealMethods[m.Names[0].Name] = ts.Name.Name
					}
				}
			}
		}
	case token.CONST:
		for _, spec := range d.Specs {
			vs := spec.(*ast.ValueSpec)
			if vs.Type == nil {
				continue
			}
			tname := exprName(vs.Type)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						constsByTyp[tname] = append(constsByTyp[tname], [2]string{n.Name, strings.Trim(lit.Value, "\"")})
					}
				}
			}
		}
	}
}

func collectFields(st *ast.StructType) []field {
	var out []field
	for _, fl := range st.Fields.List {
		if len(fl.Names) == 0 {
			continue // embedded — out of scope for the prototype
		}
		jsonTag, omit := parseTag(fl.Tag)
		base, opt, slice := rustType(fl.Type)
		src := exprSrc(fl.Type)
		union := ""
		if _, ok := unionIfaces[exprName(fl.Type)]; ok {
			union = exprName(fl.Type)
		}
		for _, n := range fl.Names {
			tag := jsonTag
			if tag == "" {
				tag = lowerFirst(n.Name)
			}
			out = append(out, field{
				goName:    n.Name,
				jsonTag:   tag,
				goTypeSrc: src,
				rustType:  base,
				optional:  opt,
				slice:     slice,
				omitempty: omit,
				unionName: union,
			})
		}
	}
	return out
}

// rustType returns (baseType, isPointer, isSlice).
func rustType(e ast.Expr) (string, bool, bool) {
	switch t := e.(type) {
	case *ast.StarExpr:
		base, _, slice := rustType(t.X)
		return base, true, slice
	case *ast.ArrayType:
		base, _, _ := rustType(t.Elt)
		return base, false, true
	case *ast.SelectorExpr:
		if r, ok := scalarMap[exprName(e)]; ok {
			return r, false, false
		}
		return t.Sel.Name, false, false
	case *ast.Ident:
		if r, ok := scalarMap[t.Name]; ok {
			return r, false, false
		}
		return t.Name, false, false
	}
	return "/*unsupported*/", false, false
}

func parseTag(t *ast.BasicLit) (json string, omitempty bool) {
	if t == nil {
		return "", false
	}
	raw := strings.Trim(t.Value, "`")
	idx := strings.Index(raw, `json:"`)
	if idx < 0 {
		return "", false
	}
	rest := raw[idx+len(`json:"`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", false
	}
	parts := strings.Split(rest[:end], ",")
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
	}
	return parts[0], omitempty
}

func unionTag(docs ...*ast.CommentGroup) string {
	for _, dg := range docs {
		if dg == nil {
			continue
		}
		for _, c := range dg.List {
			if i := strings.Index(c.Text, "monitorapi:union"); i >= 0 {
				if j := strings.Index(c.Text, "tag="); j >= 0 {
					return strings.Fields(c.Text[j+4:])[0]
				}
			}
		}
	}
	return ""
}

// ---------------- string helpers ----------------

func exprSrc(e ast.Expr) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, e)
	return b.String()
}

func exprName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprName(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return exprName(t.X)
	}
	return ""
}

func stripPrefix(s, prefix string) string { return strings.TrimPrefix(s, prefix) }

// variantIdent strips the union's common variant prefix to yield the Rust enum
// variant name, e.g. prefix "Proxy" + "ProxyManual" -> "Manual".
func variantIdent(prefix, typeName string) string {
	if prefix != "" && strings.HasPrefix(typeName, prefix) && len(typeName) > len(prefix) {
		return typeName[len(prefix):]
	}
	return typeName
}

// commonVariantPrefix returns the longest shared prefix of the variant type
// names, trimmed so every variant's remainder starts with an uppercase letter
// (so it stays a clean PascalCase identifier). With <2 variants there is
// nothing to infer, so it returns "".
func commonVariantPrefix(variants []structDef) string {
	if len(variants) < 2 {
		return ""
	}
	p := variants[0].name
	for _, v := range variants[1:] {
		minLen := len(p)
		if len(v.name) < minLen {
			minLen = len(v.name)
		}
		i := 0
		for i < minLen && p[i] == v.name[i] {
			i++
		}
		p = p[:i]
	}
	// Trim back to a PascalCase boundary: each remainder must start uppercase.
	for len(p) > 0 {
		ok := true
		for _, v := range variants {
			rest := v.name[len(p):]
			if rest == "" || rest[0] < 'A' || rest[0] > 'Z' {
				ok = false
				break
			}
		}
		if ok {
			break
		}
		p = p[:len(p)-1]
	}
	return p
}

// normType normalizes a Go type name to idiomatic Rust PascalCase, collapsing
// acronym runs: StaticIPConfig -> StaticIpConfig. Already-normalized names
// (IpAddr, String, u16, DateTime<Utc>) pass through unchanged.
func normType(s string) string {
	rs := []rune(s)
	out := make([]rune, 0, len(rs))
	isUpper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	for i, r := range rs {
		if isUpper(r) {
			prevUpper := i > 0 && isUpper(rs[i-1])
			nextUpper := i+1 < len(rs) && isUpper(rs[i+1])
			atEnd := i+1 == len(rs)
			if prevUpper && (nextUpper || atEnd) {
				out = append(out, r+32)
				continue
			}
		}
		out = append(out, r)
	}
	return string(out)
}

func pascal(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
