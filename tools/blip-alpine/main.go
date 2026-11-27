// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/openshift/imagebuilder"
	"github.com/openshift/imagebuilder/dockerfile/parser"
	"github.com/spf13/cobra"
)

const fromBranch = "blip-alpine"
const repo = "eve"
const targetOwner = "lf-edge"

// prBody is the description of the pull request, after
// .github/pull_request_template.md. It is a template for fillPRBody: its
// changelog notes list the names of the Alpine packages that it is given,
// a []string.
const prBody = `# Description

Bump the Alpine packages.

pkg/alpine now builds on top of the latest eve-alpine image. That makes
eve-alpine a new image, and building it fetches the current versions of the
Alpine packages that it mirrors. All Dockerfiles that are built from
eve-alpine, or from a package whose hash changed because of this, are
updated to the new package hashes.

This PR was created by tools/blip-alpine. Its single commit changes nothing
but the lfedge/eve-* image tags in FROM lines and in ARG defaults of
Dockerfiles.

## How to test and validate this PR

- make check-docker-hashes-consistency passes.
- CI builds eve-alpine and every package that depends on it for all
  architectures, and runs the regular tests on the resulting images.

There is no feature to test beyond that: any change in behavior comes from
newer versions of Alpine packages.

## Changelog notes

Updated the Alpine Linux packages that EVE is built from and ships to their
current versions{{if .}}:

{{range .}}- {{.}}
{{end}}{{else}}.
{{end}}
## PR Backports

- 17.0-stable: No, a stable branch has its own eve-alpine and package hashes.
- 16.0-stable: No, a stable branch has its own eve-alpine and package hashes.
- 14.5-stable: No, a stable branch has its own eve-alpine and package hashes.
- 13.4-stable: No, a stable branch has its own eve-alpine and package hashes.

## Checklist

- [X] I've provided a proper description
- [X] I've added the proper documentation
- [X] I've tested my PR on amd64 device
- [ ] I've tested my PR on arm64 device
- [X] I've written the test verification instructions
- [X] I've set the proper labels to this PR

And the last but not least:

- [X] I've checked the boxes above, or I've provided a good reason why I didn't
  check them.
`

// fillPRBody returns the description of a pull request that changes the
// packages diffPkgs. prBodyTemplate is the description as a template of
// text/template: it is given the names of the packages as a []string, each
// name once and in the order of the alphabet.
func fillPRBody(prBodyTemplate string, diffPkgs []apk) (string, error) {
	description, err := template.New("prBody").Parse(prBodyTemplate)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(diffPkgs))
	for _, pkg := range diffPkgs {
		names = append(names, pkg.Name)
	}
	slices.Sort(names)
	names = slices.Compact(names)

	var body strings.Builder
	if err := description.Execute(&body, names); err != nil {
		return "", err
	}
	return body.String(), nil
}

func imageNames(root *os.Root, exclude string) []string {
	entries, err := fs.ReadDir(root.FS(), "pkg")
	if err != nil {
		panic(err)
	}

	images := make([]string, 0)
	for _, entry := range entries {
		pkgDir := filepath.Join(root.Name(), "pkg", entry.Name())

		if entry.Name() == exclude {
			continue
		}

		by := parseBuildYaml(filepath.Join(pkgDir, "build.yml"))
		if by == nil {
			continue
		}

		tag, err := lktPkgHash(pkgDir)
		if err != nil {
			panic(err)
		}

		imageName := fmt.Sprintf("%s/%s:%s", by.Org, by.Image, tag)

		images = append(images, imageName)
	}

	return images
}

func dockerfilePaths(root *os.Root) []string {
	paths := make([]string, 0)
	err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		if filepath.Base(path) == "Dockerfile" || filepath.Base(path) == "Dockerfile.in" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	return paths
}

func main() {
	var dryRun bool

	blip := &cobra.Command{
		Use:   "blip",
		Short: "Bump pkg/alpine and all packages that depend on it, and open a pull request",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			blip(dryRun)
		},
	}
	blip.Flags().BoolVarP(&dryRun, "dry-run", "d", false,
		"bump and commit on the current branch as it is: no branch switch, no reset to origin/master, no push, no pull request")

	list := &cobra.Command{
		Use:     "list-apks",
		Aliases: []string{"la", "ls"},
		Args:    cobra.ExactArgs(1),
		Short:   "list remote apks, e.g. docker://lfedge/eve-alpine:latest or https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz",
		Run: func(cmd *cobra.Command, args []string) {
			u, err := url.Parse(args[0])
			if err != nil {
				panic(err)
			}

			var rc io.ReadCloser
			if u.Scheme == "http" || u.Scheme == "https" {
				resp, err := http.Get(u.String())
				if err != nil {
					panic(err)
				}
				if resp.Body == nil {
					panic("no content")
				}
				rc = resp.Body
			} else if u.Scheme == "docker" {
				r, err := extractFromDockerImage(u.Host+u.Path, "/mirror/3.22/x86_64/APKINDEX.tar.gz")
				if err != nil {
					panic(err)
				}
				rc = r
			} else {
				panic("cannot list, unknown url scheme " + u.Scheme)
			}
			defer rc.Close()
			pkgs, err := parseAPKINDEX(rc)
			if err != nil {
				panic(err)
			}

			for _, pkg := range pkgs {
				fmt.Printf("- %s\n", pkg.Name)
			}
		},
	}

	compare := &cobra.Command{
		Use:     "compare",
		Aliases: []string{"comp"},
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			git, err := newGitRepo("")
			if err != nil {
				panic(err)
			}
			diffPkgs := compareLocalVSRemoteApks(git)
			fmt.Println("pkgs in different versions:")
			for _, pkg := range diffPkgs {
				fmt.Printf("- %s\n", pkg.Name)
			}
		},
	}

	clone := &cobra.Command{
		Use:     "clone <directory>",
		Aliases: []string{"checkout", "co"},
		Args:    cobra.ExactArgs(1),
		Short:   "check out the newest commit of EVE's master into a directory: no history, no other branch, no tag",
		Run: func(cmd *cobra.Command, args []string) {
			upstream := "https://github.com/" + targetOwner + "/" + repo + ".git"
			fmt.Printf("cloning master of %s into %s\n", upstream, args[0])
			_, err := cloneShallow(upstream, "master", args[0])
			if err != nil {
				panic(err)
			}
		},
	}

	whoamiCmd := &cobra.Command{
		Use:     "whoami",
		Aliases: []string{"who"},
		Args:    cobra.NoArgs,
		Short:   "shows which github user is used",
		Run: func(cmd *cobra.Command, args []string) {
			gh, err := newGitHub()
			if err != nil {
				panic(err)
			}

			user, err := gh.currentUser()
			if err != nil {
				panic(err)
			}

			mail, err := gh.currentMail()
			if err != nil {
				panic(err)
			}

			fmt.Printf("using user %s - email: %s\n", user, mail)
		},
	}

	rootCmd := &cobra.Command{}

	rootCmd.AddCommand(blip, list, compare, clone, whoamiCmd)

	rootCmd.Execute()
}

func compareLocalVSRemoteApks(git *gitRepo) []apk {
	root, err := git.openRoot()
	if err != nil {
		panic(err)
	}
	pkgDir := filepath.Join(root.Name(), "pkg", "alpine")
	tag, err := lktPkgHash(pkgDir)
	if err != nil {
		panic(err)
	}

	imageName := "lfedge/eve-alpine:" + tag
	// the image says which versions of Alpine it has packages of, and
	// pkg/alpine from which repositories of a version they are
	mirrors, err := apkMirrors(imageName)
	if err != nil {
		panic(err)
	}

	var diffApks []apk
	for _, mirror := range mirrors {
		rDocker, err := extractFromDockerImage(imageName, mirror.Index)
		if err != nil {
			panic(err)
		}
		eveAlpineApks, err := parseAPKINDEX(rDocker)
		rDocker.Close()
		if err != nil {
			panic(err)
		}

		repositories, err := apkRepositories(root, mirror.Version)
		if err != nil {
			panic(err)
		}
		// all repositories at once: a package can be in more than one
		var upstreamApks []apk
		for _, repository := range repositories {
			index := mirror.upstreamIndex(repository)
			resp, err := http.Get(index)
			if err != nil {
				panic(err)
			}
			if resp.StatusCode != http.StatusOK {
				panic(fmt.Errorf("%s: %s", index, resp.Status))
			}
			apks, err := parseAPKINDEX(resp.Body)
			resp.Body.Close()
			if err != nil {
				panic(fmt.Errorf("%s: %w", index, err))
			}
			upstreamApks = append(upstreamApks, apks...)
		}

		diffApks = append(diffApks, compareApks(eveAlpineApks, upstreamApks)...)
	}
	return diffApks
}

// blip bumps the Dockerfiles, commits that and makes a pull request of it.
// With dryRun it leaves out what goes beyond a commit on the current branch:
// the switch to the branch of the pull request, its reset to origin/master,
// the push and the pull request.
func blip(dryRun bool) {

	gh, err := newGitHub()
	if err != nil {
		panic(err)
	}

	owner, err := gh.currentUser()
	if err != nil {
		panic(err)
	}
	headBranch := fmt.Sprintf("%s:%s", owner, fromBranch)

	mailAddress, err := gh.currentMail()
	if err != nil {
		panic(err)
	}

	rootDir := ""
	if !dryRun {
		dir, err := os.MkdirTemp("/var/tmp", "blip-alpine-")
		if err != nil {
			panic(err)
		}

		rootDir = dir
		defer os.RemoveAll(dir)

		upstream := "https://github.com/" + targetOwner + "/" + repo + ".git"
		_, err = cloneShallow(upstream, "master", dir)
		if err != nil {
			panic(err)
		}
	}

	git, err := newGitRepo(rootDir)
	if err != nil {
		panic(err)
	}
	diffPkgs := compareLocalVSRemoteApks(git)
	if len(diffPkgs) == 0 && !dryRun {
		fmt.Println("no packages to update")

		prURL, err := gh.openPR(targetOwner, repo, headBranch)
		if err != nil {
			panic(err)
		}
		if prURL == "" {
			return
		}
		err = gh.closePR(prURL)
		if err != nil {
			panic(err)
		}

		return
	}

	root, err := git.openRoot()
	if err != nil {
		panic(err)
	}

	err = git.fetchOrigin()
	if err != nil {
		panic(err)
	}
	if !dryRun {
		err := git.checkoutNewBranch("blip-alpine")
		if err != nil {
			panic(err)
		}
		err = git.resetHardOriginMaster()
		if err != nil {
			panic(err)
		}
	}

	ignoreDockerfilePaths := map[string]struct{}{
		"pkg/cross-compilers/Dockerfile": struct{}{},
	}

	dp := dockerfilePaths(root)
	images := imageNames(root, "")

	for _, dockerfilePath := range dp {
		_, ignore := ignoreDockerfilePaths[dockerfilePath]
		if ignore {
			continue
		}
		for _, image := range images {
			bump(root, dockerfilePath, image)
		}
	}

	clean, err := git.worktreeClean()
	if err != nil {
		panic(err)
	}
	if clean {
		fmt.Printf("no bump necessary\n")
		os.Exit(0)
	}

	commitMsg := `pkgs: bump pkg/alpine and all dependent pkgs

let's use the newest alpine packages with the fixes`

	commitMsg += fmt.Sprintf("\n\nSigned-off-by: Alpine Blipper <%s>", mailAddress)
	_, err = git.commitTracked(commitMsg, false)
	if err != nil {
		panic(err)
	}

	for {
		images := imageNames(root, "")

		for _, dockerfilePath := range dp {
			dockerfilePath = filepath.Clean(dockerfilePath)
			if dockerfilePath == "pkg/alpine/Dockerfile" {
				continue
			}
			_, ignore := ignoreDockerfilePaths[dockerfilePath]
			if ignore {
				continue
			}
			for _, image := range images {
				bump(root, dockerfilePath, image)
			}
		}

		clean, err := git.worktreeClean()
		if err != nil {
			panic(err)
		}
		if clean {
			break
		}
		git.commitTracked(commitMsg, true)
	}

	_, err = git.commitTracked(commitMsg, true)
	if err != nil {
		panic(err)
	}

	if dryRun {
		fmt.Printf("dry run: no push, no pull request\n")
		return
	}

	err = gh.push(git, owner, repo, fromBranch, true)
	if err != nil {
		panic(err)
	}
	prURL, err := gh.openPR(targetOwner, repo, headBranch)
	if err != nil {
		panic(err)
	}
	body, err := fillPRBody(prBody, diffPkgs)
	if err != nil {
		panic(err)
	}
	if prURL == "" {
		prURL, err = gh.createPR(pullRequest{
			Owner: targetOwner,
			Repo:  repo,
			Head:  headBranch,
			Base:  "master",
			Title: "Blip alpine packages",
			Body:  body,
			Draft: true,
		})
	} else {
		// the packages may be others than when the pull request was opened
		err = gh.updatePR(prURL, body)
	}
	if err != nil {
		panic(err)
	}
	fmt.Printf("PR URL: %s\n", prURL)
}

// bump makes the Dockerfile file in root use ref, an image with a tag,
// wherever it uses that image.
func bump(root *os.Root, file, ref string) error {
	colon := strings.LastIndex(ref, ":")
	if colon <= 0 || colon == len(ref)-1 || strings.Contains(ref[colon:], "/") {
		return fmt.Errorf("%q is not an image with a tag", ref)
	}
	src, err := root.ReadFile(file)
	if err != nil {
		return err
	}
	out, err := retag(src, ref[:colon], ref[colon+1:])
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	if bytes.Equal(out, src) {
		return nil
	}
	return root.WriteFile(file, out, 0644)
}

// retag gives every reference to image in a Dockerfile the tag, whichever
// tag it has.
//
// Which flag or argument of the syntax tree holds the tag of a reference
// is found out by trying: where the old tag occurs it is replaced by the
// new one, and that stays if the images that imagebuilder resolves for the
// Dockerfile then differ in nothing but the reference having the new tag.
// That finds the tag in a FROM, in the default of an ARG that a FROM uses
// and in a --from, and leaves it alone in an ENV, in a command and where
// it is the tag of another image.
func retag(src []byte, image, tag string) ([]byte, error) {
	// most Dockerfiles do not name the image at all: no need to parse those
	if !bytes.Contains(src, []byte(image)) {
		return nil, fmt.Errorf("no reference to %s with a tag", image)
	}
	root, err := imagebuilder.ParseDockerfile(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	refs, err := imageRefs(root)
	if err != nil {
		return nil, err
	}
	newRef := image + ":" + tag
	tagged := false
	for _, oldRef := range refs {
		oldTag, ok := strings.CutPrefix(oldRef, image+":")
		if !ok {
			continue
		}
		tagged = true
		if oldRef == newRef {
			continue
		}
		for _, n := range root.Children {
			for _, word := range words(n) {
				tryEach(word, oldTag, tag, func() bool {
					now, err := imageRefs(root)
					if err != nil || !retagged(refs, now, oldRef, newRef) {
						return false
					}
					refs = now
					return true
				})
			}
		}
		if slices.Contains(refs, oldRef) {
			return nil, fmt.Errorf("cannot change the tag of %s: no flag or argument holds it for this image alone", oldRef)
		}
	}
	if !tagged {
		return nil, fmt.Errorf("no reference to %s with a tag", image)
	}
	return unparse(src, root)
}

// tryEach replaces from by to in word, one place after the other, and
// undoes it where keep does not agree with the result.
func tryEach(word *string, from, to string, keep func() bool) {
	if from == "" {
		return
	}
	for at := 0; ; {
		i := strings.Index((*word)[at:], from)
		if i < 0 {
			return
		}
		at += i
		was := *word
		*word = was[:at] + to + was[at+len(from):]
		if keep() {
			at += len(to)
		} else {
			*word = was
			at++
		}
	}
}

// retagged tells whether the image references differ, and in nothing but
// oldRef having become newRef.
func retagged(before, after []string, oldRef, newRef string) bool {
	if len(before) != len(after) {
		return false
	}
	changed := false
	for i := range before {
		if before[i] == after[i] {
			continue
		}
		if before[i] != oldRef || after[i] != newRef {
			return false
		}
		changed = true
	}
	return changed
}

// imageRefs returns the images and stages that a Dockerfile builds on: the
// base of every stage as imagebuilder resolves it for a build, that is
// with the ARGs before the first FROM filled in, and the sources of
// COPY --from and RUN --mount.
func imageRefs(root *parser.Node) ([]string, error) {
	var refs []string
	for _, n := range root.Children {
		for _, flag := range n.Flags {
			if from, ok := strings.CutPrefix(flag, "--from="); ok {
				refs = append(refs, from)
			}
			if mount, ok := strings.CutPrefix(flag, "--mount="); ok {
				for _, option := range strings.Split(mount, ",") {
					if from, ok := strings.CutPrefix(option, "from="); ok {
						refs = append(refs, from)
					}
				}
			}
		}
	}

	// NewStages and From take the list of instructions apart, so they get
	// a list of their own. The instructions they leave as they are.
	tree := *root
	tree.Children = slices.Clone(root.Children)
	stages, err := imagebuilder.NewStages(&tree, imagebuilder.NewBuilder(nil))
	if err != nil {
		return nil, err
	}
	for _, stage := range stages {
		base, err := stage.Builder.From(stage.Node)
		if err != nil {
			return nil, err
		}
		refs = append(refs, base)
	}
	return refs, nil
}

// words returns the flags and the arguments of an instruction, for
// reading and for changing them.
func words(n *parser.Node) []*string {
	var all []*string
	for i := range n.Flags {
		all = append(all, &n.Flags[i])
	}
	for arg := n.Next; arg != nil; arg = arg.Next {
		all = append(all, &arg.Value)
	}
	return all
}

// unparse writes a changed syntax tree back as a Dockerfile.
//
// imagebuilder has no function for that, and none could give the file back
// as it was: the tree has no comments, no blank lines and no line breaks
// within an instruction. So the text is not generated from the tree.
// Instead src, the text that the tree was parsed from, is patched where a
// flag or an argument of an instruction is another one now, and all the
// rest of it stays. A tree that differs in more than that is refused.
func unparse(src []byte, root *parser.Node) ([]byte, error) {
	cur, err := imagebuilder.ParseDockerfile(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	for i := range min(len(cur.Children), len(root.Children)) {
		n := cur.Children[i]
		have, want := words(n), words(root.Children[i])
		for k := range min(len(have), len(want)) {
			if *have[k] == *want[k] {
				continue
			}
			was := *have[k]
			*have[k] = *want[k]
			if src, err = patch(src, cur, n.StartLine, n.EndLine, was, *want[k]); err != nil {
				return nil, err
			}
		}
	}
	if cur.Dump() != root.Dump() {
		return nil, errors.New("the syntax tree differs from the text in more than flags and arguments")
	}
	return src, nil
}

// patch replaces from by to in the lines first to last of src, at the
// place where that makes src the text of the syntax tree want.
func patch(src []byte, want *parser.Node, first, last int, from, to string) ([]byte, error) {
	lines := bytes.SplitAfter(src, []byte("\n"))
	head := bytes.Join(lines[:first-1], nil)
	body := bytes.Join(lines[first-1:last], nil)
	tail := bytes.Join(lines[last:], nil)
	dump := want.Dump()
	for at := 0; at+len(from) <= len(body); at++ {
		i := bytes.Index(body[at:], []byte(from))
		if i < 0 {
			break
		}
		at += i
		out := slices.Concat(head, body[:at], []byte(to), body[at+len(from):], tail)
		if got, err := imagebuilder.ParseDockerfile(bytes.NewReader(out)); err == nil && got.Dump() == dump {
			return out, nil
		}
	}
	return nil, fmt.Errorf("line %d: no place to change %q to %q", first, from, to)
}
