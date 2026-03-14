// Copyright(c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/containerd/platforms"
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/moby"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

// Target information
const (
	TARGETOS      = "linux"
	TARGETARCH    = "amd64"
	TARGETVARIANT = ""
)

var (
	outputImgFile  string
	outputMakeFile string
	hashDir        string
	hashOnly       bool
	rootfsDeps     bool
)

type printer interface {
	printSingleDep(dep string) string
	printDep(pkg string, dep string) string
	printHead() string
	printTail() string
	generate(filename string) string
}

type makefilePrinter struct {
}

type dotfilePrinter struct {
}

// Parse YML file and return all lfedge/* packages inside it
func parseYMLfile(fileName string) []string {
	var deps []string

	// Open and read the file
	bs, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	// Parses the file
	m, err := moby.NewConfig(bs, func(path string) (tag string, err error) {
		return path, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	deps = append(deps, m.Init...)
	for _, img := range m.Onboot {
		deps = append(deps, img.Image)
	}
	for _, img := range m.Onshutdown {
		deps = append(deps, img.Image)
	}
	for _, img := range m.Services {
		deps = append(deps, img.Image)
	}

	return deps
}

type argsEnvGetter struct {
	args map[string]string
}

func (aeg *argsEnvGetter) Get(key string) (string, bool) {
	val, found := aeg.args[key]
	return val, found
}

func (aeg *argsEnvGetter) Keys() []string {
	keys := make([]string, 0, len(aeg.args))
	for key := range aeg.args {
		keys = append(keys, key)
	}

	return keys
}

func parseDockerfile(pkgName string) []string {
	dockerfilePath := filepath.Join(pkgName, "Dockerfile")
	dt, err := os.ReadFile(dockerfilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}
		}
		panic(err)
	}

	dockerfile, err := parser.Parse(bytes.NewReader(dt))
	if err != nil {
		panic(err)
	}
	stages, metaArgs, err := instructions.Parse(dockerfile.AST, nil)
	if err != nil {
		log.Fatalf("parsing instructions of %s failed: %v", dockerfilePath, err)
	}

	// If no FROM line references a build arg (no '$' in the base name), skip the
	// slow lktBuildArgs dry-run. Generated Dockerfiles (via parse-pkgs.sh) have
	// fully-resolved image names, so this fast path covers the common case.
	needsArgResolution := false
	for _, st := range stages {
		if strings.Contains(st.BaseName, "$") {
			needsArgResolution = true
			break
		}
	}
	var aeg argsEnvGetter
	if needsArgResolution {
		aeg = createDockerEnvGetter(filepath.Join(pkgName, "build.yml"), metaArgs)
	} else {
		aeg = makePlatformEnvGetter(metaArgs)
	}

	shlex := shell.NewLex(dockerfile.EscapeToken)

	targetsMap := make(map[string]struct{})
	for _, st := range stages {
		pResult, err := shlex.ProcessWordWithMatches(st.BaseName, &aeg)
		if err != nil {
			panic(err)
		}
		targetsMap[pResult.Result] = struct{}{}
	}
	targets := make([]string, 0)
	for target := range targetsMap {
		targets = append(targets, target)
	}
	return targets
}

// makePlatformEnvGetter builds an argsEnvGetter with platform args and
// Dockerfile ARG defaults — without the slow lktBuildArgs dry-run.
func makePlatformEnvGetter(metaArgs []instructions.ArgCommand) argsEnvGetter {
	buildPlatform := []ocispecs.Platform{platforms.DefaultSpec()}[0]
	targetPlatform := ocispecs.Platform{
		Architecture: TARGETARCH,
		OS:           TARGETOS,
		Variant:      TARGETVARIANT,
	}
	aeg := argsEnvGetter{
		args: map[string]string{
			"BUILDPLATFORM":  platforms.Format(buildPlatform),
			"BUILDOS":        buildPlatform.OS,
			"BUILDARCH":      buildPlatform.Architecture,
			"BUILDVARIANT":   buildPlatform.Variant,
			"TARGETPLATFORM": platforms.Format(targetPlatform),
			"TARGETOS":       targetPlatform.OS,
			"TARGETARCH":     targetPlatform.Architecture,
			"TARGETVARIANT":  targetPlatform.Variant,
		},
	}
	for _, ma := range metaArgs {
		for _, arg := range ma.Args {
			aeg.args[arg.Key] = arg.ValueString()
		}
	}
	return aeg
}

func createDockerEnvGetter(buildYmlFile string, metaArgs []instructions.ArgCommand) argsEnvGetter {
	aeg := makePlatformEnvGetter(metaArgs)
	for k, v := range lktBuildArgs(buildYmlFile) {
		aeg.args[k] = v
	}
	return aeg
}

// Print a single dependency package, only suitable for dot file
func (mp makefilePrinter) printSingleDep(dep string) string {
	return ""
}

func (dp dotfilePrinter) printSingleDep(dep string) string {
	return "\"" + dep + "\";"
}

// Print a package and one of its dependency
func (mp makefilePrinter) printDep(pkg string, dep string) string {
	return pkg + ": " + dep + "\n"
}

func (dp dotfilePrinter) printDep(pkg string, dep string) string {
	return "\"" + pkg + "\" -> \"" + dep + "\";\n"
}

// Print the header and/or the initialization commands (for dot file)
func (mp makefilePrinter) printHead() string {
	return "#\n# This file was generated by EVE's build system. DO NOT EDIT.\n#\n"
}

func (dp dotfilePrinter) printHead() string {
	return "digraph unix {\n   rankdir=\"LR\";\n"
}

// Print the end of the generated file
func (mp makefilePrinter) printTail() string {
	return ""
}

func (dp dotfilePrinter) printTail() string {
	return "\n}\n"
}

// Generate the output file
func (mp makefilePrinter) generate(outfileName string) string {
	return outfileName
}

func (dp dotfilePrinter) generate(outfileName string) string {
	_, err := exec.Command("dot", "-Tpng", outfileName, "-o", outputImgFile).Output()
	if err != nil {
		fmt.Println("Failed to run dot utility.")
	}

	// Remove temporary file
	os.Remove(outfileName)

	// Set the final output file name
	outfileName = outputImgFile
	return outfileName
}

// Filter packages from the list of dependencies
func filterPkg(deps []string) []string {
	var depList []string
	dpList := make(map[string]bool)

	reLF := regexp.MustCompile("lfedge/.*")
	rePkg := regexp.MustCompile("lfedge/(?:eve-)?(.*):.*")
	for _, s := range deps {
		// We are just interested on packages from lfegde (those that we
		// published)
		if reLF.MatchString(s) {
			str := rePkg.ReplaceAllString(s, "pkg/$1")
			// Check that the directory ./pkg/$1 exists.
			// It doesn't exist for lfedge packages outside eve source tree e.g. eve-rust
			if _, err := os.Stat(str); err != nil {
				continue
			}
			if !dpList[str] {
				dpList[str] = true
				depList = append(depList, str)
			}
		}
	}

	return depList
}

// Return a list of all dependencies (packages) listed in a Dockerfile
func getDeps(pkgName string) []string {
	ss := parseDockerfile(pkgName)

	return filterPkg(ss)
}

// writeHashFile writes content to dir/<name>.hash using write-if-changed
// semantics (only updates mtime when content differs).
func writeHashFile(dir, name, content string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %v", dir, err)
	}
	hashFile := filepath.Join(dir, name+".hash")
	newContent := []byte(content)
	if existing, err := os.ReadFile(hashFile); err == nil && bytes.Equal(existing, newContent) {
		// unchanged — preserve mtime
		return nil
	}
	return os.WriteFile(hashFile, newContent, 0644)
}

// pkgBaseName returns the short package name from "pkg/foo" → "foo".
func pkgBaseName(pkg string) string {
	return strings.TrimPrefix(pkg, "pkg/")
}

func main() {
	mkfile := false
	imgfile := false
	pkgName := ""
	var p printer

	// Build and validate the command line
	flag.Usage = func() {
		fmt.Printf("Create dependency packages tree\n\n")
		fmt.Printf("Use:\n    %s [-r] [-d <hashdir>] <-i|-m|-H> <output_file>\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&outputImgFile, "i", "", "Generate a PNG image file")
	flag.StringVar(&outputMakeFile, "m", "", "Generate a Makefile auxiliary file")
	flag.StringVar(&hashDir, "d", "", "Directory for per-package .hash and .built files")
	flag.BoolVar(&hashOnly, "H", false, "Hash-update-only mode: write .hash files for all pkg/*/build.yml packages and exit (no Dockerfile scan)")
	flag.BoolVar(&rootfsDeps, "r", false, "Also generates dependencies for rootfs image")
	flag.Parse()

	// -H: fast hash-update mode — iterate all pkg/*/build.yml, compute linuxkit
	// tag via pkglib (pure git, no Docker), write hashDir/<pkg>.hash with
	// write-if-changed semantics.  No Dockerfile scan is performed.
	if hashOnly {
		if hashDir == "" {
			log.Fatal("-H requires -d <hashdir>")
		}
		ent, err := os.ReadDir("./pkg")
		if err != nil {
			log.Fatal(err)
		}
		if err := os.MkdirAll(hashDir, 0755); err != nil {
			log.Fatal(err)
		}
		for _, e := range ent {
			if !e.IsDir() {
				continue
			}
			pkgDir := filepath.Join("pkg", e.Name())
			buildYML := filepath.Join(pkgDir, defaultPkgBuildYML)
			if _, err := os.Stat(buildYML); err != nil {
				continue // not a linuxkit package
			}
			tag, err := getPkgTag(pkgDir, defaultPkgBuildYML)
			if err != nil {
				log.Printf("Warning: could not compute tag for %s: %v", pkgDir, err)
				continue
			}
			if err := writeHashFile(hashDir, e.Name(), tag); err != nil {
				log.Printf("Warning: could not write hash file for %s: %v", pkgDir, err)
			}
		}
		return
	}

	if len(outputImgFile) > 0 {
		imgfile = true
		p = dotfilePrinter{}
	}
	if len(outputMakeFile) > 0 {
		mkfile = true
		p = makefilePrinter{}
	}
	if !imgfile && !mkfile {
		flag.Usage()
		os.Exit(1)
	} else if imgfile && mkfile {
		flag.Usage()
		log.Fatal("Only one type of output dependency tree can be provided.\n")
	}

	// allPkgDeps maps consumer → list of deps (for DEPS_FORCE generation).
	// depOf tracks which packages appear as a dependency of at least one other
	// package (non-leaf set — these are the ones that get .hash files).
	allPkgDeps := make(map[string][]string)
	depOf := make(map[string]bool)

	// For dot output we still write directly to a temp file.
	// For makefile output we accumulate in a strings.Builder and do
	// write-if-changed at the end.
	var mkBuf strings.Builder
	var outfile *os.File

	if imgfile {
		var errF error
		outfile, errF = os.CreateTemp("", "eve-dot-")
		if errF != nil {
			log.Fatal(errF)
		}
	}

	writeOut := func(s string) {
		if mkfile {
			mkBuf.WriteString(s)
		} else {
			_, err := outfile.WriteString(s)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	// Beginning of the output
	writeOut(p.printHead())

	// Scan all directories of pkg/
	ent, err := os.ReadDir("./pkg")
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range ent {
		if !e.IsDir() {
			continue
		}
		dockerFile := filepath.Join("./pkg/", e.Name(), "/Dockerfile")
		dockerFileIn := dockerFile + ".in"

		// Regenerate from Dockerfile.in if Dockerfile is missing or empty.
		dfStat, dfErr := os.Stat(dockerFile)
		if dfErr != nil || dfStat.Size() == 0 {
			if _, errIn := os.Stat(dockerFileIn); errIn == nil {
				cmd := exec.Command("make", "-o", "pkg-deps.mk", dockerFile)
				out, err := cmd.Output()
				if err != nil {
					log.Printf("Failed to process %s: %s", dockerFileIn, out)
					continue
				}
			} else if dfErr != nil {
				continue
			}
		}
		pkgName = "pkg/" + e.Name()

		// Get package dependencies from Dockerfile
		writeOut(p.printSingleDep(pkgName))
		depList := getDeps(pkgName)
		if len(depList) > 0 {
			allPkgDeps[pkgName] = depList
		}
		for _, d := range depList {
			if d != pkgName {
				// Write a single dependency of the package
				writeOut(p.printDep(pkgName, d))
				exportPkgName := fmt.Sprintf("%s-cache-export-docker-load", pkgName[4:])
				exportD := fmt.Sprintf("%s-cache-export-docker-load", d[4:])
				writeOut(p.printDep(exportPkgName, exportD))
				// Track which packages are non-leaf (have consumers)
				depOf[d] = true
			}
		}
	}

	// Scan rootfs dependencies
	if rootfsDeps {
		ent, err = os.ReadDir("./images/out/")
		if err == nil {
			for _, e := range ent {
				if !e.IsDir() {
					// Process yml file
					ymlFile := filepath.Join("images/out/", e.Name())
					depYML := parseYMLfile(ymlFile)
					depList := filterPkg(depYML)
					for _, d := range depList {
						writeOut(p.printDep(ymlFile, d))
					}
				}
			}
		}
	}

	// We reach the end of the main dep rules
	writeOut(p.printTail())

	// --- Makefile-only: hash tracking rules ---
	// Emitted only when -d <hashdir> is given.
	// Per-consumer (packages with non-leaf deps only):
	//   pkg/<consumer>: .gen-deps/<dep>.hash  (file prereq — triggers get-deps -H)
	//   pkg/<consumer>: DEPS_FORCE = ...       (target-specific var, propagates to eve-%)
	// The .gen-deps/%.hash pattern rule lives in the root Makefile.
	if mkfile && hashDir != "" {
		consumers := make([]string, 0, len(allPkgDeps))
		for pkg := range allPkgDeps {
			consumers = append(consumers, pkg)
		}
		sort.Strings(consumers)

		// Collect consumers that actually have non-leaf (tracked) deps.
		type consumerEntry struct {
			name        string
			trackedDeps []string
		}
		var tracked []consumerEntry
		for _, consumer := range consumers {
			var tDeps []string
			for _, d := range allPkgDeps[consumer] {
				if depOf[d] && d != consumer {
					tDeps = append(tDeps, d)
				}
			}
			if len(tDeps) > 0 {
				tracked = append(tracked, consumerEntry{consumer, tDeps})
			}
		}

		if len(tracked) > 0 {
			mkBuf.WriteString("\n# Universal dependency hash tracking (generated by get-deps -d)\n")
			mkBuf.WriteString("# Hash file rules live in the root Makefile (.gen-deps/%.hash pattern);\n")
			mkBuf.WriteString("# only direct file prereqs and DEPS_FORCE assignments are emitted here.\n")

			for _, e := range tracked {
				consumerBase := pkgBaseName(e.name)
				consumerHash := fmt.Sprintf("%s/%s.hash", hashDir, consumerBase)

				var conditions []string
				for _, d := range e.trackedDeps {
					hashFile := fmt.Sprintf("%s/%s.hash", hashDir, pkgBaseName(d))
					mkBuf.WriteString(fmt.Sprintf("pkg/%s: %s\n", consumerBase, hashFile))
					conditions = append(conditions, fmt.Sprintf("[ %s -nt %s ]", hashFile, consumerHash))
				}

				mkBuf.WriteString(fmt.Sprintf(
					"pkg/%s: DEPS_FORCE = $(if $(shell [ -f %s ] && { %s; } 2>/dev/null && echo y),--force,)\n",
					consumerBase, consumerHash, strings.Join(conditions, " || ")))
			}
		}
	}

	// --- Finalize output ---
	if imgfile {
		outfileName := outfile.Name()
		outfile.Close()
		outfileName = p.generate(outfileName)
		fmt.Println("Done. Output file written to " + outfileName + ".")
	} else {
		// Makefile: write-if-changed to avoid spurious Make restarts
		outContent := []byte(mkBuf.String())
		if existing, err := os.ReadFile(outputMakeFile); err == nil && bytes.Equal(existing, outContent) {
			fmt.Println("Done. " + outputMakeFile + " unchanged.")
			return
		}
		if err := os.WriteFile(outputMakeFile, outContent, 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Done. Output file written to " + outputMakeFile + ".")
	}
}
