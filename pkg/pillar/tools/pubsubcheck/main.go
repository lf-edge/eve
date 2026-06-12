// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// pubsubcheck statically analyzes the Persistent flag of pubsub
// publications and subscriptions. It parses all Go sources under the given
// root directories (skipping vendor directories and tests), collects every
// pubsub.PublicationOptions and pubsub.SubscriptionOptions composite
// literal and resolves the agent name and scope (string literals and
// package-level string constants). It serves two purposes:
//
// As a CI check (make check-pubsub-persistence), it reports every
// persistent subscription whose publication is known not to be persistent.
// Such a subscription pre-loads the publisher's persisted state from disk
// at activation time; with a non-persistent publication the pre-load
// silently finds nothing, or stale state left behind by an older EVE
// version. Publisher and subscriber often live in different containers and
// even different Go modules, so the compiler cannot catch the disagreement
// and at runtime it surfaces only as an error log once both sides are up.
// Entries whose agent name or persistence cannot be resolved statically are
// skipped: the runtime check in the socketdriver remains the backstop.
//
// As a build-time generator (-list-non-persistent), it emits the list of
// non-persistent publications that the pillar container image embeds for
// upgradeconverter. At boot upgradeconverter removes the matching directories
// under /persist/status: a topic that is non-persistent now but whose
// directory still exists was persistent in a previous EVE version, and its
// stale state would otherwise be pre-loaded by a persistent subscriber. Only
// statically resolvable non-persistent publications are listed; anything
// ambiguous, removed entirely, or published outside these sources is left in
// place, which is the safe direction.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// optionsLit is one parsed pubsub.PublicationOptions or
// pubsub.SubscriptionOptions composite literal.
type optionsLit struct {
	pos             token.Position
	isSubscription  bool
	agent           string // empty if not statically resolvable
	scope           string // AgentScope, usually empty
	topic           string // bare type name, empty if not resolvable
	persistent      bool
	persistentKnown bool // false if Persistent is not a true/false literal
}

// key returns the "<agent>[/<scope>]/<topic>" path of the topic relative to
// the pubsub directory, mirroring nameString() of the pubsub package.
func (o optionsLit) key() string {
	if o.scope != "" {
		return o.agent + "/" + o.scope + "/" + o.topic
	}
	return o.agent + "/" + o.topic
}

// analysis is the result of scanning the source tree.
type analysis struct {
	errors   []string
	warnings []string
	// nonPersistentPublications are the keys of all topics that are
	// statically known to be published only non-persistently, sorted and
	// unique. A topic with any persistent or any unresolvable publication
	// is excluded, so that its /persist/status directory is never removed.
	nonPersistentPublications []string
}

func main() {
	verbose := flag.Bool("v", false, "verbose output (warnings and skipped entries)")
	listNonPersistent := flag.Bool("list-non-persistent", false,
		"list all topics published only non-persistently and exit")
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	result, err := analyze(roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubsubcheck: %v\n", err)
		os.Exit(2)
	}
	if *listNonPersistent {
		for _, key := range result.nonPersistentPublications {
			fmt.Println(key)
		}
		return
	}
	if *verbose {
		for _, warning := range result.warnings {
			fmt.Printf("WARNING: %s\n", warning)
		}
	}
	for _, errMsg := range result.errors {
		fmt.Printf("ERROR: %s\n", errMsg)
	}
	if len(result.errors) > 0 {
		os.Exit(1)
	}
	fmt.Println("pubsubcheck: no persistence mismatches found")
}

func analyze(roots []string) (*analysis, error) {
	packageDirs, err := collectPackageDirs(roots)
	if err != nil {
		return nil, err
	}

	var subscriptions []optionsLit
	publications := make(map[string][]optionsLit)
	fset := token.NewFileSet()
	for _, dir := range packageDirs {
		entries, err := parsePackageDir(fset, dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.isSubscription {
				subscriptions = append(subscriptions, entry)
			} else {
				publications[entry.key()] = append(publications[entry.key()], entry)
			}
		}
	}

	result := &analysis{}
	for _, sub := range subscriptions {
		if !sub.persistentKnown || !sub.persistent {
			continue
		}
		if sub.agent == "" || sub.topic == "" {
			result.warnings = append(result.warnings, fmt.Sprintf(
				"%s: cannot statically resolve agent or topic of a persistent subscription",
				sub.pos))
			continue
		}
		result.check(sub, publications[sub.key()])
	}
	result.collectNonPersistentPublications(publications)
	sort.Strings(result.errors)
	sort.Strings(result.warnings)
	return result, nil
}

// collectNonPersistentPublications fills nonPersistentPublications with the
// keys of all topics published only non-persistently. A topic is included
// only if it has at least one statically resolvable non-persistent
// publication and no publication that is persistent or whose persistence
// cannot be resolved statically. upgradeconverter removes the matching
// directories under /persist/status at boot, so any ambiguity must keep a
// topic off the list rather than risk removing live state.
func (a *analysis) collectNonPersistentPublications(publications map[string][]optionsLit) {
	for key, pubs := range publications {
		var hasNonPersistent, blocked bool
		for _, pub := range pubs {
			if pub.agent == "" || pub.topic == "" {
				// Cannot form a /persist/status path for it anyway.
				continue
			}
			if !pub.persistentKnown {
				// Persistence set from a variable: cannot rule out that
				// it is persistent, so do not list the topic.
				a.warnings = append(a.warnings, fmt.Sprintf(
					"%s: cannot statically resolve persistence of the publication of %s",
					pub.pos, pub.key()))
				blocked = true
				continue
			}
			if pub.persistent {
				blocked = true
				continue
			}
			hasNonPersistent = true
		}
		if hasNonPersistent && !blocked {
			a.nonPersistentPublications = append(a.nonPersistentPublications, key)
		}
	}
	sort.Strings(a.nonPersistentPublications)
}

// check validates one persistent subscription against the publications of
// the same agent and topic.
func (a *analysis) check(sub optionsLit, pubs []optionsLit) {
	if len(pubs) == 0 {
		a.warnings = append(a.warnings, fmt.Sprintf(
			"%s: no statically resolvable publication found for persistent subscription to %s",
			sub.pos, sub.key()))
		return
	}
	var nonPersistent []optionsLit
	for _, pub := range pubs {
		if !pub.persistentKnown {
			// Persistence set from a variable; cannot judge.
			a.warnings = append(a.warnings, fmt.Sprintf(
				"%s: cannot statically resolve persistence of the publication of %s",
				pub.pos, pub.key()))
			return
		}
		if pub.persistent {
			// At least one persistent publication exists.
			return
		}
		nonPersistent = append(nonPersistent, pub)
	}
	for _, pub := range nonPersistent {
		a.errors = append(a.errors, fmt.Sprintf(
			"%s: persistent subscription to %s, but the publication at %s is not persistent",
			sub.pos, sub.key(), pub.pos))
	}
}

// collectPackageDirs returns all directories under the given roots that
// contain Go files, skipping vendor and hidden directories.
func collectPackageDirs(roots []string) ([]string, error) {
	dirSet := make(map[string]bool)
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if name == "vendor" || name == "testdata" ||
					(strings.HasPrefix(name, ".") && path != root) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				dirSet[filepath.Dir(path)] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	dirs := make([]string, 0, len(dirSet))
	for dir := range dirSet {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// parsePackageDir parses all non-test Go files of one directory and returns
// the pubsub options literals found in them. Package-level string constants
// of the same package are used to resolve agent names.
func parsePackageDir(fset *token.FileSet, dir string) ([]optionsLit, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var parsed []*ast.File
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			// Tolerate unparsable files (e.g. build-tag exotica);
			// they will be caught by the regular build.
			continue
		}
		parsed = append(parsed, astFile)
	}

	consts := collectStringConsts(parsed)
	var entries []optionsLit
	for _, astFile := range parsed {
		ast.Inspect(astFile, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			selector, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			var isSubscription bool
			switch selector.Sel.Name {
			case "SubscriptionOptions":
				isSubscription = true
			case "PublicationOptions":
				isSubscription = false
			default:
				return true
			}
			entry := parseOptionsLit(fset, lit, isSubscription, consts)
			entries = append(entries, entry)
			return true
		})
	}
	return entries, nil
}

// collectStringConsts returns the package-level string constants defined in
// the given files.
func collectStringConsts(files []*ast.File) map[string]string {
	consts := make(map[string]string)
	for _, file := range files {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.CONST {
				continue
			}
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok || len(valueSpec.Names) != len(valueSpec.Values) {
					continue
				}
				for i, name := range valueSpec.Names {
					if value := stringLiteral(valueSpec.Values[i]); value != "" {
						consts[name.Name] = value
					}
				}
			}
		}
	}
	return consts
}

// parseOptionsLit extracts agent, topic and persistence from one options
// composite literal.
func parseOptionsLit(fset *token.FileSet, lit *ast.CompositeLit,
	isSubscription bool, consts map[string]string) optionsLit {

	entry := optionsLit{
		pos:             fset.Position(lit.Pos()),
		isSubscription:  isSubscription,
		persistentKnown: true, // absent Persistent field means false
	}
	for _, element := range lit.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyValue.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "AgentName":
			if value := stringLiteral(keyValue.Value); value != "" {
				entry.agent = value
			} else if ident, ok := keyValue.Value.(*ast.Ident); ok {
				entry.agent = consts[ident.Name]
			}
		case "AgentScope":
			if value := stringLiteral(keyValue.Value); value != "" {
				entry.scope = value
			} else if ident, ok := keyValue.Value.(*ast.Ident); ok {
				entry.scope = consts[ident.Name]
			}
		case "TopicImpl", "TopicType":
			entry.topic = bareTypeName(keyValue.Value)
		case "Persistent":
			ident, ok := keyValue.Value.(*ast.Ident)
			switch {
			case ok && ident.Name == "true":
				entry.persistent = true
			case ok && ident.Name == "false":
				entry.persistent = false
			default:
				entry.persistentKnown = false
			}
		}
	}
	return entry
}

// stringLiteral returns the value of a string literal expression, or "".
func stringLiteral(expr ast.Expr) string {
	basicLit, ok := expr.(*ast.BasicLit)
	if !ok || basicLit.Kind != token.STRING {
		return ""
	}
	value, err := strconv.Unquote(basicLit.Value)
	if err != nil {
		return ""
	}
	return value
}

// bareTypeName returns the bare type name of a composite literal expression
// like types.DomainStatus{} or localType{}. The package qualifier is
// dropped on purpose: pubsub derives the topic name from the bare type name
// via reflection, so this mirrors the runtime matching.
func bareTypeName(expr ast.Expr) string {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	switch litType := lit.Type.(type) {
	case *ast.SelectorExpr:
		return litType.Sel.Name
	case *ast.Ident:
		return litType.Name
	}
	return ""
}
