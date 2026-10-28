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
	"slices"
	"strconv"
	"strings"

	"github.com/containerd/platforms"
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/moby"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/lf-edge/eve/tools/dockerfile-from-checker/dockerfilefrom"
)

// TARGETOS is the OS of both the build and the target platform.
const TARGETOS = "linux"

var (
	outputImgFile  string
	outputMakeFile string
	rootfsDeps     bool
	targetArch     string
	buildArch      string
	hostArchPkgs   string
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

// parseDockerfile returns the images that building pkgName's Dockerfile
// for each of targetArches on a buildArch host pulls in.
func parseDockerfile(pkgName string, targetArches []string, buildArch string) []string {
	dockerfilePath := filepath.Join(pkgName, "Dockerfile")
	dt, err := os.ReadFile(dockerfilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}
		}
		panic(err)
	}

	res, err := dockerfilefrom.Scan(bytes.NewReader(dt))
	if err != nil {
		log.Fatalf("parsing %s failed: %+v", dockerfilePath, err)
	}

	targetsMap := make(map[string]struct{})
	for _, arch := range targetArches {
		args := createDockerEnvGetter(filepath.Join(pkgName, "build.yml"), res.Args, arch, buildArch)
		g := newStageGraph(res, args)
		refs, unresolved := g.reachableImages()
		if unresolved != "" {
			log.Printf("%s: stage %q does not resolve for %s on %s, keeping every stage",
				dockerfilePath, unresolved, arch, buildArch)
			refs = g.allImages()
		}
		for _, ref := range refs {
			targetsMap[ref] = struct{}{}
		}
	}
	targets := make([]string, 0, len(targetsMap))
	for target := range targetsMap {
		targets = append(targets, target)
	}
	return targets
}

func expandArgs(word string, args map[string]string) string {
	return dockerfilefrom.Expand(word, func(name string) (string, bool) {
		val, ok := args[name]
		return val, ok
	})
}

// stageGraph resolves the references of a scanned Dockerfile for one
// target and build platform.
type stageGraph struct {
	res      *dockerfilefrom.Result
	args     map[string]string
	stageIdx map[string]int
}

func newStageGraph(res *dockerfilefrom.Result, args map[string]string) *stageGraph {
	g := &stageGraph{res: res, args: args, stageIdx: make(map[string]int)}
	for i, st := range res.Stages {
		if st.Name != "" {
			g.stageIdx[st.Name] = i
		}
	}
	return g
}

// classify reports whether a reference of stage from names another stage
// (stage >= 0) or an image. Like buildkit, a FROM base (n == 0) only names
// an earlier stage, while a --from source (n > 0) may also be an index. A
// reference built from variables that names neither is ambiguous: it is
// most likely a stage selection with no matching stage.
func (g *stageGraph) classify(ref string, from, n int) (stage int, image string, ambiguous bool) {
	val := expandArgs(ref, g.args)
	if i, ok := g.stageIdx[strings.ToLower(val)]; ok && (i < from || n > 0 && i != from) {
		return i, "", false
	}
	if i, err := strconv.Atoi(val); n > 0 && err == nil && i >= 0 && i < len(g.res.Stages) && i != from {
		return i, "", false
	}
	// Stage names cannot contain these, image references usually do.
	if strings.Contains(ref, "$") && !strings.ContainsAny(val, "/:@") {
		return -1, "", true
	}
	return -1, val, false
}

// refs returns the base and --from references of stage i.
func (g *stageGraph) refs(i int) []string {
	st := g.res.Stages[i]
	return append([]string{st.Base}, st.CopyFrom...)
}

// reachableImages returns the images that building the last stage pulls
// in: those of every stage it transitively depends on, as buildkit skips
// the others. It returns the first ambiguous reference on the way as
// unresolved, since the set of built stages is then unknown.
func (g *stageGraph) reachableImages() (images []string, unresolved string) {
	visited := make(map[int]bool)
	var visit func(i int) string
	visit = func(i int) string {
		if visited[i] {
			return ""
		}
		visited[i] = true
		for n, ref := range g.refs(i) {
			stage, image, ambiguous := g.classify(ref, i, n)
			switch {
			case ambiguous:
				return ref
			case stage >= 0:
				if u := visit(stage); u != "" {
					return u
				}
			default:
				images = append(images, image)
			}
		}
		return ""
	}
	if len(g.res.Stages) == 0 {
		return nil, ""
	}
	if u := visit(len(g.res.Stages) - 1); u != "" {
		return nil, u
	}
	return images, ""
}

// allImages returns the images referenced by any stage.
func (g *stageGraph) allImages() []string {
	var images []string
	for i := range g.res.Stages {
		for n, ref := range g.refs(i) {
			if _, image, _ := g.classify(ref, i, n); image != "" {
				images = append(images, image)
			}
		}
	}
	return images
}

func createDockerEnvGetter(buildYmlFile string, metaArgs map[string]string, targetArch, buildArch string) map[string]string {
	buildPlatform := platforms.Normalize(ocispecs.Platform{
		Architecture: buildArch,
		OS:           TARGETOS,
	})
	targetPlatform := platforms.Normalize(ocispecs.Platform{
		Architecture: targetArch,
		OS:           TARGETOS,
	})

	args := map[string]string{
		// from github.com/moby/buildkit/frontend/dockerfile/dockerfile2llb/platform.go:getPlatformArgs
		"BUILDPLATFORM":  platforms.Format(buildPlatform),
		"BUILDOS":        buildPlatform.OS,
		"BUILDARCH":      buildPlatform.Architecture,
		"BUILDVARIANT":   buildPlatform.Variant,
		"TARGETPLATFORM": platforms.Format(targetPlatform),
		"TARGETOS":       targetPlatform.OS,
		"TARGETARCH":     targetPlatform.Architecture,
		"TARGETVARIANT":  targetPlatform.Variant,
	}
	for key, val := range metaArgs {
		args[key] = val
	}

	for k, v := range lktBuildArgs(buildYmlFile, targetArch) {
		args[k] = v
	}

	return args
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
	arches := []string{targetArch}
	if targetArch != buildArch && slices.Contains(strings.Fields(hostArchPkgs), pkgName[len("pkg/"):]) {
		arches = append(arches, buildArch)
	}
	ss := parseDockerfile(pkgName, arches, buildArch)

	return filterPkg(ss)
}

// Write string to file with error checking
func writeToFile(f *os.File, str string) {
	_, err := f.WriteString(str)
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	mkfile := false
	imgfile := false
	pkgName := ""
	var p printer

	// Build and validate the command line
	flag.Usage = func() {
		fmt.Printf("Create dependency packages tree\n\n")
		fmt.Printf("Use:\n    %s [-r] [-arch <arch>] [-build-arch <arch>] [-hostarch-pkgs <pkgs>] <-i|-m> <output_file>\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&outputImgFile, "i", "", "Generate a PNG image file")
	flag.StringVar(&outputMakeFile, "m", "", "Generate a Makefile auxiliary file")
	flag.BoolVar(&rootfsDeps, "r", false, "Also generates dependencies for rootfs image")
	flag.StringVar(&targetArch, "arch", platforms.DefaultSpec().Architecture, "Architecture the packages are built for")
	flag.StringVar(&buildArch, "build-arch", platforms.DefaultSpec().Architecture, "Architecture of the build host")
	flag.StringVar(&hostArchPkgs, "hostarch-pkgs", "", "Space-separated packages also built for the build host's architecture")
	flag.Parse()

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

	// Create the output file, if we are generating image tree, then an
	// intermediate file (.dot) must be created
	var outfile *os.File
	var errF error
	if len(outputImgFile) > 0 {
		outfile, errF = os.CreateTemp("", "eve-dot-")
		if errF != nil {
			log.Fatal(errF)
		}
	} else {
		outfile, errF = os.Create(outputMakeFile)
		if errF != nil {
			log.Fatal(errF)
		}
	}

	// Beginning of the output file
	writeToFile(outfile, p.printHead())

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

		if _, err := os.Stat(dockerFile); err != nil {
			if _, errIn := os.Stat(dockerFileIn); errIn == nil {
				// Process Dockerfile.in
				cmd := exec.Command("make", dockerFile)
				out, err := cmd.Output()
				if err != nil {
					log.Printf("Failed to %s process, out: %s", dockerFileIn, out)
					continue
				}

			} else {
				continue
			}

		}
		pkgName = "pkg/" + e.Name()

		// Get package dependencies from Dockerfile
		writeToFile(outfile, p.printSingleDep(pkgName))
		depList := getDeps(pkgName)
		for _, d := range depList {
			if d != pkgName {
				// Write a single dependency of the package
				writeToFile(outfile, p.printDep(pkgName, d))
				exportPkgName := fmt.Sprintf("%s-cache-export-docker-load", pkgName[4:])
				exportD := fmt.Sprintf("%s-cache-export-docker-load", d[4:])
				writeToFile(outfile, p.printDep(exportPkgName, exportD))
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
						writeToFile(outfile, p.printDep(ymlFile, d))
					}
				}
			}
		}
	}

	// We reach the end of the file
	writeToFile(outfile, p.printTail())
	outfileName := outfile.Name()
	outfile.Close()

	outfileName = p.generate(outfileName)

	fmt.Println("Done. Output file written to " + outfileName + ".")
}
