// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// lktPkgHash returns what linuxkit's "pkg show-tag" substitutes for {{.Hash}}:
// the git tree hash of dir at HEAD, folded together with the tree hashes of
// any extra source directories the way build.yml "extra-sources:" entries
// are, and suffixed with "-dirty-<7 hex of a content hash>" while dir has
// uncommitted changes. The repository is read with go-git; no git binary is
// involved.
func lktPkgHash(dir string, extraSources ...string) (string, error) {
	pkg, err := openPkgDir(dir)
	if err != nil {
		return "", err
	}
	hash, err := pkg.treeHash()
	if err != nil {
		return "", err
	}
	slices.Sort(extraSources)
	if len(extraSources) > 0 {
		combined := hash
		for _, src := range extraSources {
			extra, err := openPkgDir(src)
			if err != nil {
				return "", err
			}
			h, err := extra.treeHash()
			if err != nil {
				return "", err
			}
			combined += h
		}
		hash = fmt.Sprintf("%x", sha1.Sum([]byte(combined)))
	}
	state, err := pkg.scanWorktree()
	if err != nil {
		return "", err
	}
	if state.dirty {
		content, err := pkg.contentHash(state)
		if err != nil {
			return "", err
		}
		hash += "-dirty-" + content[:7]
	}
	return hash, nil
}

// pkgDir is a directory inside a git worktree.
type pkgDir struct {
	repo *git.Repository
	root string // absolute worktree root
	abs  string // absolute package directory
	rel  string // slash-separated path of abs below root, "" for the root itself
}

func openPkgDir(dir string) (*pkgDir, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	repo, err := git.PlainOpenWithOptions(abs, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	root := wt.Filesystem.Root()
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, fmt.Errorf("%s is outside the worktree %s", abs, root)
	}
	if rel == "." {
		rel = ""
	}
	return &pkgDir{repo: repo, root: root, abs: abs, rel: filepath.ToSlash(rel)}, nil
}

// headTree returns the HEAD commit and its root tree.
func (p *pkgDir) headTree() (*object.Commit, *object.Tree, error) {
	ref, err := p.repo.Head()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: resolving HEAD: %w", p.root, err)
	}
	commit, err := p.repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: reading HEAD commit: %w", p.root, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, nil, err
	}
	return commit, tree, nil
}

// treeHash is what "git ls-tree --full-tree HEAD -- <dir>" prints for the
// package, or the commit's tree when the package is the worktree root.
func (p *pkgDir) treeHash() (string, error) {
	commit, tree, err := p.headTree()
	if err != nil {
		return "", err
	}
	if p.rel == "" {
		return commit.TreeHash.String(), nil
	}
	entry, err := tree.FindEntry(p.rel)
	if err != nil {
		return "", fmt.Errorf("package %s is not in git", p.abs)
	}
	return entry.Hash.String(), nil
}

// headSubtree returns the tree object for the package directory at HEAD.
func (p *pkgDir) headSubtree() (*object.Tree, error) {
	_, tree, err := p.headTree()
	if err != nil {
		return nil, err
	}
	if p.rel == "" {
		return tree, nil
	}
	sub, err := tree.Tree(p.rel)
	if err != nil {
		return nil, fmt.Errorf("package %s is not a directory in git", p.abs)
	}
	return sub, nil
}

// worktreeState is what "git diff HEAD" and "git ls-files" would report for
// the package directory.
type worktreeState struct {
	dirty     bool
	tracked   []*index.Entry // index entries below the package, in index order
	untracked []string       // worktree files neither in the index nor ignored
}

// scanWorktree reproduces linuxkit's isDirty: "git diff --quiet HEAD -- dir"
// finding a change, or "git ls-files --others --exclude-standard -- dir"
// listing anything. Paths are relative to the worktree root throughout.
func (p *pkgDir) scanWorktree() (*worktreeState, error) {
	idx, err := p.repo.Storer.Index()
	if err != nil {
		return nil, fmt.Errorf("%s: reading the index: %w", p.root, err)
	}
	st := &worktreeState{}
	byName := map[string]*index.Entry{}
	prefix := p.rel + "/"
	for _, e := range idx.Entries {
		if p.rel == "" || strings.HasPrefix(e.Name, prefix) {
			st.tracked = append(st.tracked, e)
			byName[e.Name] = e
		}
	}
	slices.SortStableFunc(st.tracked, func(a, b *index.Entry) int { return strings.Compare(a.Name, b.Name) })

	indexTime := p.indexModTime()
	tree, err := p.headSubtree()
	if err != nil {
		return nil, err
	}
	inHead := map[string]bool{}
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		name, entry, err := walker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if entry.Mode == filemode.Dir || entry.Mode == filemode.Submodule {
			continue
		}
		full := path.Join(p.rel, name)
		inHead[full] = true
		if st.dirty {
			continue
		}
		changed, err := p.differsFromHead(entry, byName[full], indexTime)
		if err != nil {
			return nil, err
		}
		st.dirty = changed
	}
	for _, e := range st.tracked {
		if !inHead[e.Name] {
			st.dirty = true
		}
	}

	patterns, err := p.ignorePatterns()
	if err != nil {
		return nil, err
	}
	if err := p.walkUntracked(p.rel, patterns, byName, st); err != nil {
		return nil, err
	}
	slices.Sort(st.untracked)
	if len(st.untracked) > 0 {
		st.dirty = true
	}
	return st, nil
}

// differsFromHead reports whether the worktree file behind a HEAD tree entry
// is missing or has a different mode or content, the way "git diff HEAD" sees
// it: paths dropped from the index count as deleted, and the index entry's
// stat data stands in for hashing the file when it still matches.
func (p *pkgDir) differsFromHead(head object.TreeEntry, ie *index.Entry, indexTime time.Time) (bool, error) {
	if ie == nil {
		return true, nil
	}
	abs := filepath.Join(p.root, filepath.FromSlash(ie.Name))
	fi, err := os.Lstat(abs)
	if err != nil {
		return true, nil
	}
	mode, err := filemode.NewFromOSFileMode(fi.Mode())
	if err != nil || mode != head.Mode {
		return true, nil
	}
	if statMatches(ie, fi) && !racyTimestamp(ie, indexTime) {
		return ie.Hash != head.Hash, nil
	}
	h, err := blobHash(abs, fi)
	if err != nil {
		return false, err
	}
	return h != head.Hash, nil
}

// statMatches applies git's default stat cache rule (ce_match_stat_basic
// without USE_NSEC): size, whole-second mtime and ctime, owner and inode.
func statMatches(e *index.Entry, fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return e.Size == uint32(st.Size) &&
		e.ModifiedAt.Unix() == st.Mtim.Sec &&
		e.CreatedAt.Unix() == st.Ctim.Sec &&
		e.UID == st.Uid && e.GID == st.Gid &&
		e.Inode == uint32(st.Ino)
}

// racyTimestamp is git's "racily clean" rule: an entry whose mtime is not
// older than the index file itself may have changed after being hashed, so it
// cannot be trusted without re-reading the file.
func racyTimestamp(e *index.Entry, indexTime time.Time) bool {
	return indexTime.IsZero() || e.ModifiedAt.Unix() >= indexTime.Unix()
}

func (p *pkgDir) indexModTime() time.Time {
	s, ok := p.repo.Storer.(*filesystem.Storage)
	if !ok {
		return time.Time{}
	}
	fi, err := s.Filesystem().Stat("index")
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func blobHash(abs string, fi os.FileInfo) (plumbing.Hash, error) {
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(abs)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		return plumbing.ComputeHash(plumbing.BlobObject, []byte(target)), nil
	}
	f, err := os.Open(abs)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	defer f.Close()
	h := plumbing.NewHasher(plumbing.BlobObject, fi.Size())
	if _, err := io.Copy(h, f); err != nil {
		return plumbing.ZeroHash, err
	}
	return h.Sum(), nil
}

// ignorePatterns collects what --exclude-standard applies above the package
// directory, lowest precedence first: core.excludesFile from the system and
// user config, .git/info/exclude, then .gitignore of the root and of every
// ancestor directory. The package's own .gitignore files are read while
// walking it.
func (p *pkgDir) ignorePatterns() ([]gitignore.Pattern, error) {
	rootFS := osfs.New("/")
	patterns, _ := gitignore.LoadSystemPatterns(rootFS)
	global, _ := gitignore.LoadGlobalPatterns(rootFS)
	patterns = append(patterns, global...)
	if s, ok := p.repo.Storer.(*filesystem.Storage); ok {
		if f, err := s.Filesystem().Open("info/exclude"); err == nil {
			patterns = append(patterns, parseIgnore(f, nil)...)
			f.Close()
		}
	}
	var domain []string
	patterns = append(patterns, p.readIgnoreFile(domain)...)
	if p.rel != "" {
		comps := strings.Split(p.rel, "/")
		for _, c := range comps[:len(comps)-1] {
			domain = append(domain, c)
			patterns = append(patterns, p.readIgnoreFile(domain)...)
		}
	}
	return patterns, nil
}

func (p *pkgDir) readIgnoreFile(domain []string) []gitignore.Pattern {
	f, err := os.Open(filepath.Join(p.root, filepath.Join(domain...), ".gitignore"))
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseIgnore(f, domain)
}

func parseIgnore(r io.Reader, domain []string) []gitignore.Pattern {
	var ps []gitignore.Pattern
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		ps = append(ps, gitignore.ParsePattern(line, slices.Clone(domain)))
	}
	return ps
}

// walkUntracked lists what "git ls-files --others --exclude-standard" would
// print below dir: files absent from the index and not ignored, with ignored
// directories pruned. A directory holding its own .git is a nested repository
// and is reported as a single untracked entry unless it is a gitlink.
func (p *pkgDir) walkUntracked(dir string, patterns []gitignore.Pattern, byName map[string]*index.Entry, st *worktreeState) error {
	var domain []string
	if dir != "" {
		domain = strings.Split(dir, "/")
	}
	patterns = append(patterns[:len(patterns):len(patterns)], p.readIgnoreFile(domain)...)
	matcher := gitignore.NewMatcher(patterns)
	entries, err := os.ReadDir(filepath.Join(p.root, filepath.FromSlash(dir)))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == ".git" {
			continue
		}
		full := path.Join(dir, e.Name())
		comps := append(slices.Clone(domain), e.Name())
		if !e.IsDir() {
			if byName[full] == nil && !matcher.Match(comps, false) {
				st.untracked = append(st.untracked, full)
			}
			continue
		}
		if matcher.Match(comps, true) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(p.root, filepath.FromSlash(full), ".git")); err == nil {
			if byName[full] == nil {
				st.untracked = append(st.untracked, full)
			}
			continue
		}
		if err := p.walkUntracked(full, patterns, byName, st); err != nil {
			return err
		}
	}
	return nil
}

// contentHash reproduces linuxkit's contentHash: a sha256 over the raw
// contents of the tracked files, then the untracked ones, each list in
// git's byte order. Directories and symlinks are skipped, and so are names
// git would C-quote in its output, because linuxkit feeds that quoted output
// to Lstat and silently skips what it cannot find.
func (p *pkgDir) contentHash(st *worktreeState) (string, error) {
	h := sha256.New()
	add := func(name string) error {
		if gitQuotesName(strings.TrimPrefix(name, p.rel+"/")) {
			return nil
		}
		abs := filepath.Join(p.root, filepath.FromSlash(name))
		fi, err := os.Lstat(abs)
		if err != nil || fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		f, err := os.Open(abs)
		if err != nil {
			return nil
		}
		defer f.Close()
		_, err = io.Copy(h, f)
		return err
	}
	for _, e := range st.tracked {
		if err := add(e.Name); err != nil {
			return "", err
		}
	}
	for _, name := range st.untracked {
		if err := add(name); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// gitQuotesName reports whether git's default core.quotePath output wraps
// the path in C-style quotes: control characters, DEL, non-ASCII bytes,
// double quotes and backslashes all trigger it.
func gitQuotesName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return true
		}
	}
	return false
}
