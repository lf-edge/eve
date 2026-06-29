// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/sync/errgroup"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage/memory"
)

// LineOp represents a diff line operation (add, delete, or no-op).
type LineOp uint8

// Line operation constants.
const (
	LineAdd LineOp = iota
	LineDel
	LineNop
)

func (o LineOp) String() string {
	if o == LineAdd {
		return "+"
	}
	if o == LineDel {
		return "-"
	}
	if o == LineNop {
		return "="
	}

	return " "
}

// LineDiff represents a single line-level diff entry.
type LineDiff struct {
	Operation  LineOp
	Line       string
	LineNumber uint64
	TypeOfLine LineProperty
}

func (ld LineDiff) String() string {
	return fmt.Sprintf("%s %d: %s\n\t%s\n", ld.Operation.String(), ld.LineNumber, ld.Line, ld.TypeOfLine.String())
}

func (ld LineDiff) startCol() int {
	for i, r := range []rune(ld.Line) {
		if !unicode.IsSpace(r) {
			return i
		}
	}
	return len([]rune(ld.Line))
}

// CommentType classifies whether a line is a comment.
type CommentType uint8

func (c CommentType) String() string {
	switch c {
	case Undecided:
		return "undecided"
	case NotComment:
		return "not a comment"
	case IsComment:
		return "comment"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

// CommentType constants.
const (
	Undecided CommentType = iota
	NotComment
	IsComment
)

// IsCommentString returns a stringified IsComment()
func (ld LineDiff) IsCommentString() string {
	return ld.IsComment().String()
}

// IsComment determines whether this line is a comment.
func (ld LineDiff) IsComment() CommentType {
	// did not parse, so we don't know
	if len(ld.TypeOfLine) == 0 {
		return Undecided
	}
	cs, found := ld.TypeOfLine["comment"]
	if !found {
		return NotComment
	}

	for _, c := range cs {
		if (c.ColFrom == 0 || c.ColFrom <= uint32(ld.startCol())) &&
			(c.ColTo == uint32(math.MaxUint32) || c.ColTo >= uint32(len(ld.Line))) {
			return IsComment
		}
	}

	return Undecided
}

// GitChangeExec orchestrates git-based change detection and action execution.
type GitChangeExec struct {
	ActionsToCheck []Action
	ActionDos      ActionToDos
	GitPath        string
	G              *git.Repository
	relPaths       map[string]struct{}
	baseCommit     *object.Commit
	originPath     string
	di             diffInfo

	diffMutex sync.Mutex
}

// CountRelPaths returns the number of tracked relative paths.
func (gce *GitChangeExec) CountRelPaths() int {
	return len(gce.relPaths)
}

func debugLog(fmt string, args ...any) {
	if debug {
		log.Printf(fmt, args...)
	}
}

// NewGitChangeExec creates a new GitChangeExec instance.
func NewGitChangeExec() *GitChangeExec {
	gce := GitChangeExec{
		ActionDos: ActionToDos{
			Actions: map[string][]ActionToDo{},
		},
		ActionsToCheck: []Action{},
		relPaths:       map[string]struct{}{},
	}

	return &gce
}

// GoToGitRootDir changes the working directory to the git repository root.
func (gce *GitChangeExec) GoToGitRootDir() {
	var err error

	gce.originPath, err = os.Getwd()
	if err != nil {
		log.Fatalf("getting current working directory: %v", err)
	}

	wt, err := gce.G.Worktree()
	if err != nil {
		log.Fatalf("could not determine worktree: %v", err)
	}
	gce.GitPath = wt.Filesystem.Root()

	err = os.Chdir(gce.GitPath)
	if err != nil {
		log.Fatalf("could not change to %s: %v", gce.GitPath, err)
	}
}

// Close restores the working directory and closes all actions.
func (gce *GitChangeExec) Close() {
	gce.ChangeBackDir()

	for _, a := range gce.ActionsToCheck {
		a.Close()
	}
}

// ChangeBackDir restores the working directory to the original path.
func (gce *GitChangeExec) ChangeBackDir() {
	if gce.originPath == "" {
		return
	}

	err := os.Chdir(gce.originPath)
	if err != nil {
		log.Fatalf("changing back to %s failed: %v", gce.originPath, err)
	}
}

// FetchOrigin fetches from the origin remote.
func (gce *GitChangeExec) FetchOrigin() {
	err := gce.G.Fetch(&git.FetchOptions{
		RemoteName: "origin",
		Tags:       git.AllTags,
	})
	if err != nil {
		debugLog("fetching from origin failed: %v", err)
	}
}

type diffInfoFile struct {
	idx       int
	fromCount int
	toCount   int
	t         time.Time
}

type diffInfo struct {
	currentProcessingFiles map[string]diffInfoFile
	countFiles             int

	doneState atomic.Bool

	addedFileCount int
	sync.RWMutex
}

func (di *diffInfo) addFile(file string, fromCount, toCount int) {
	di.Lock()
	di.addedFileCount++
	di.currentProcessingFiles[file] = diffInfoFile{
		idx:       di.addedFileCount,
		fromCount: fromCount,
		toCount:   toCount,
		t:         time.Now(),
	}
	di.Unlock()
}
func (di *diffInfo) delFile(file string) {
	di.Lock()
	delete(di.currentProcessingFiles, file)
	di.Unlock()
}
func (di *diffInfo) print() {
	type idxFile struct {
		file string
		diffInfoFile
	}
	di.RLock()
	files := make([]idxFile, 0, len(di.currentProcessingFiles))
	for file, val := range di.currentProcessingFiles {
		files = append(files, idxFile{
			file: file,
			diffInfoFile: diffInfoFile{
				idx:       val.idx,
				fromCount: val.fromCount,
				toCount:   val.toCount,
				t:         val.t,
			},
		})
	}
	di.RUnlock()
	if len(files) == 0 {
		return
	}
	log.Printf("Currently processing:")
	slices.SortFunc(files, func(a, b idxFile) int {
		return a.idx - b.idx
	})
	for _, file := range files {
		dur := time.Since(file.t)
		log.Printf("\t%d %s (%d -> %d) - %s", file.idx, file.file, file.fromCount, file.toCount, dur)
	}
}

func (di *diffInfo) printRoutine() {
	for {
		di.print()
		time.Sleep(1 * time.Second)

		if di.doneState.Load() {
			return
		}
	}
}

func (di *diffInfo) done() {
	di.doneState.Store(true)
}

// Diff computes line-level diffs for all tracked paths.
func (gce *GitChangeExec) Diff() {
	eg := errgroup.Group{}
	eg.SetLimit(runtime.NumCPU())

	gce.di = diffInfo{
		currentProcessingFiles: map[string]diffInfoFile{},
		RWMutex:                sync.RWMutex{},
		countFiles:             len(gce.relPaths),
		doneState:              atomic.Bool{},
		addedFileCount:         0,
	}

	if len(gce.relPaths) > 1000 {
		go gce.di.printRoutine()
		defer gce.di.done()
	}

	for path := range gce.relPaths {

		eg.Go(func() error {
			gce.diffPath(path)
			return nil
		})
	}

	eg.Wait()
}

func (gce *GitChangeExec) diffPath(path string) {
	var oldContent string

	gce.diffMutex.Lock()
	file, err := gce.baseCommit.File(path)
	if err == nil {
		oldContent, err = file.Contents()
		if err != nil {
			log.Fatalf("could not get file contents of %s: %v", path, err)
		}
	}
	gce.diffMutex.Unlock()

	linesFrom := Parse(path, oldContent)

	bs, err := os.ReadFile(path)
	if err != nil {
		return
	}
	linesTo := Parse(path, string(bs))

	fromLines := strings.Split(oldContent, "\n")
	toLines := strings.Split(string(bs), "\n")
	gce.di.addFile(path, len(fromLines), len(toLines))
	defer gce.di.delFile(path)

	dfs := Diff(fromLines, toLines)
	for i := range dfs {
		if dfs[i].Operation == LineDel {
			dfs[i].TypeOfLine = linesFrom[uint32(dfs[i].LineNumber)]
		}
		if dfs[i].Operation == LineAdd {
			dfs[i].TypeOfLine = linesTo[uint32(dfs[i].LineNumber)]
		}
	}

	allEqual := true
	for _, df := range dfs {
		if df.Operation != LineNop {
			allEqual = false
		}
		gce.diffMutex.Lock()
		gce.addActionByLineDiff(path, df)
		gce.diffMutex.Unlock()
	}
	if allEqual {
		return
	}
	gce.diffMutex.Lock()
	gce.addActionByPath(path)
	gce.diffMutex.Unlock()

}

// CalculateBaseCommit finds the common ancestor commit with the base branch.
func (gce *GitChangeExec) CalculateBaseCommit() {
	logIter, err := gce.G.Log(&git.LogOptions{})
	if err != nil {
		log.Fatalf("getting log failed: %v", err)
	}

	branchHead, err := logIter.Next()
	if err != nil {
		log.Fatalf("getting log.Next failed: %v", err)
	}

	commonBase := gce.findCommonBase(branchHead)

	logIter, err = gce.G.Log(&git.LogOptions{})
	if err != nil {
		log.Fatalf("getting log for iteration failed: %v", err)
	}

	var baseCommit *object.Commit
	err = logIter.ForEach(func(c *object.Commit) error {
		for _, cb := range commonBase {
			if c.Hash == cb.Hash {
				baseCommit = c
				return storer.ErrStop
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("iterating over commits failed: %v", err)
	}
	logIter.Close()

	gce.baseCommit = baseCommit
}

// BaseCommit returns the calculated base commit.
func (gce *GitChangeExec) BaseCommit() *object.Commit {
	return gce.baseCommit
}

// CollectActionsGitTree collects changed file paths from the git commit history.
func (gce *GitChangeExec) CollectActionsGitTree() {
	logIter, err := gce.G.Log(&git.LogOptions{})
	if err != nil {
		log.Fatalf("getting log for iteration failed: %v", err)
	}

	err = logIter.ForEach(func(c *object.Commit) error {
		if c.Hash == gce.baseCommit.Hash {
			return storer.ErrStop
		}

		commitStats, err := c.Stats()
		if err != nil {
			log.Fatalf("getting commit stats failed: %v", err)
		}

		for _, st := range commitStats {
			gce.storePath(st.Name)
		}

		return nil
	})
	if err != nil {
		log.Fatalf("iterating over commits failed: %v", err)
	}
	logIter.Close()
}

func (gce *GitChangeExec) findCommonBase(branchHead *object.Commit) []*object.Commit {
	var commonBase []*object.Commit
	refs := gce.retrieveBaseBranchRefs()

	for _, ref := range refs {
		commit, err := gce.G.CommitObject(ref.Hash())
		if err != nil {
			log.Printf("retrieve commit object from ref %v failed: %v", ref, err)
			continue
		}
		commonBase = append(commonBase, commit)
		addBase, err := branchHead.MergeBase(commit)
		if err != nil {
			debugLog("finding merge base failed: %v", err)
		}
		commonBase = append(commonBase, addBase...)
	}
	return commonBase
}

// BaseBranches returns all base branch names including stable branches.
func (gce *GitChangeExec) BaseBranches() []string {
	baseBranches := map[string]struct{}{}

	for _, branch := range mainBranches {
		baseBranches[branch] = struct{}{}
		baseBranches[fmt.Sprintf("refs/heads/%s", branch)] = struct{}{}
		baseBranches[fmt.Sprintf("refs/remotes/origin/%s", branch)] = struct{}{}
	}

	remoteCfg := config.RemoteConfig{
		Name:   "origin",
		URLs:   []string{gitRemote},
		Mirror: false,
		Fetch:  []config.RefSpec{},
	}
	gitStorage := memory.NewStorage()
	gitRemote := git.NewRemote(gitStorage, &remoteCfg)
	rfs, err := gitRemote.List(&git.ListOptions{})
	if err == nil {
		for _, rf := range rfs {
			branch := rf.Name().Short()
			if !strings.HasSuffix(branch, "-stable") {
				continue
			}
			baseBranches[branch] = struct{}{}
			baseBranches[fmt.Sprintf("refs/heads/%s", branch)] = struct{}{}
			baseBranches[fmt.Sprintf("refs/remotes/origin/%s", branch)] = struct{}{}
		}
	}

	iter, err := gce.G.Branches()
	if err != nil {
		log.Fatalf("could not iterate over branches: %+v", err)
	}

	iter.ForEach(func(r *plumbing.Reference) error {
		branch := r.Name().Short()
		if !strings.HasSuffix(branch, "-stable") {
			return nil
		}
		baseBranches[branch] = struct{}{}
		baseBranches[fmt.Sprintf("refs/heads/%s", branch)] = struct{}{}
		baseBranches[fmt.Sprintf("refs/remotes/origin/%s", branch)] = struct{}{}
		return nil
	})

	ret := make([]string, 0, len(baseBranches))
	for branch := range baseBranches {
		ret = append(ret, branch)
	}

	return ret
}

func (gce *GitChangeExec) retrieveBaseBranchRefs() []*plumbing.Reference {
	refs := []*plumbing.Reference{}

	baseBranches := gce.BaseBranches()

	for _, nameOfMaster := range baseBranches {
		var err error

		ref, err := gce.G.Reference(plumbing.ReferenceName(nameOfMaster), true)
		if err == nil {
			refs = append(refs, ref)
		}
	}

	if len(refs) == 0 {
		log.Fatalf("could not find a base commit - check your main branch name")
	}
	return refs
}

func (gce *GitChangeExec) storePath(path string) {
	gce.relPaths[path] = struct{}{}
}

// DumpActionToDos writes the action todos as JSON to the writer.
func (gce *GitChangeExec) DumpActionToDos(w io.Writer) {
	gce.ActionDos.dumpActionToDos(w)
}

func (gce *GitChangeExec) addActionByLineDiff(path string, ld LineDiff) {
	for _, a := range gce.ActionsToCheck {
		ad, ok := a.(ActionDiff)
		if !ok {
			continue
		}
		if ad.MatchDiff(path, ld) {
			gce.ActionDos.addActionToDo(a, path, &ld)
		}
	}
}

func (gce *GitChangeExec) addActionByPath(path string) {
	for _, a := range gce.ActionsToCheck {
		ap, ok := a.(ActionPath)
		if ok && ap.MatchPath(path) {
			gce.ActionDos.addActionToDo(a, path, nil)
		}
	}
}

// ForceRunActionDos runs all actions unconditionally.
func (gce *GitChangeExec) ForceRunActionDos() error {
	var allErr error
	for _, a := range gce.ActionsToCheck {
		err := a.Do(nil)
		if err != nil {
			log.Printf("%s failed with: %v", ID(a), err)
		}
		allErr = errors.Join(allErr, err)
	}

	return allErr
}

// DryRunActionDos logs which actions would run without executing them.
func (gce *GitChangeExec) DryRunActionDos() {
	for _, a := range gce.ActionsToCheck {
		_, found := gce.ActionDos.Actions[ID(a)]
		if !found {
			continue
		}
		log.Printf("would run %s, but running dry ...", ID(a))
	}
}

// RunActionDos executes actions that have matching todos.
func (gce *GitChangeExec) RunActionDos() error {
	var allErr error
	for _, a := range gce.ActionsToCheck {
		actionToDos, found := gce.ActionDos.Actions[ID(a)]
		if !found {
			continue
		}
		log.Printf("--- running %s ...", ID(a))
		err := a.Do(actionToDos)
		log.Printf("--- running %s done", ID(a))
		if err != nil {
			log.Printf("%s failed with: %v", ID(a), err)
		}
		allErr = errors.Join(allErr, err)
	}

	return allErr
}

// CollectDirtyGitTree collects changed file paths from the dirty worktree.
func (gce *GitChangeExec) CollectDirtyGitTree() {
	ignoredStatusCodes := map[git.StatusCode]struct{}{
		git.Unmodified: {},
		git.Untracked:  {},
	}
	worktree, err := gce.G.Worktree()
	if err != nil {
		log.Fatalf("getting current worktree: %v", err)
	}

	stats, err := worktree.Status()
	if err != nil {
		log.Fatalf("getting current worktree status: %v", err)
	}

	for file, gitSt := range stats {
		_, foundStaging := ignoredStatusCodes[gitSt.Staging]
		_, foundWorkTree := ignoredStatusCodes[gitSt.Worktree]

		if foundStaging && foundWorkTree {
			continue
		}

		fp := filepath.Join(gce.GitPath, file)
		st, err := os.Stat(fp)
		if err != nil {
			continue
		}

		// git-go has some bug with links, so only consider files
		if !st.Mode().IsRegular() {
			continue
		}
		gce.storePath(file)
	}
}

// InternalActions returns built-in actions keyed by their ID.
func InternalActions() map[string]Action {
	lintSpdx := &LintSpdx{}
	internalActions := map[string]Action{
		lintSpdx.ID(): lintSpdx,
	}

	return internalActions
}

// LoadActions loads actions from the given argument list (Lua files or built-in IDs).
func (gce *GitChangeExec) LoadActions(args []string) {

	luaFiles := make([]string, 0)
	for _, path := range args {
		var luaPath string

		if strings.HasPrefix(path, "lua:") {
			luaPath = strings.TrimPrefix(path, "lua:")
		}
		if !strings.Contains(path, ":") {
			_, err := os.Stat(path)
			if err == nil {
				luaPath = path
			}
		}

		if luaPath != "" {
			actionsPath, err := filepath.Abs(luaPath)
			if err != nil {
				log.Fatalf("could not get absolute path of %s: %v", path, err)
			}
			luaFiles = append(luaFiles, ListLuaActions(actionsPath)...)
		} else if strings.HasPrefix(path, "gce:") {
			action, found := InternalActions()[path]
			if !found {
				log.Fatalf("could not find action '%s'", path)
			}
			gce.ActionsToCheck = append(gce.ActionsToCheck, action)
		} else {
			log.Fatalf("cannot find action %s", path)
		}
	}
	for _, luaFile := range luaFiles {
		content, err := os.ReadFile(luaFile)
		if err != nil {
			log.Fatalf("could not read file %s: %v", luaFile, err)
		}
		log.Printf("Loading %s ...\n", luaFile)
		la := LuaLoad("lua:"+luaFile, string(content))
		gce.ActionsToCheck = append(gce.ActionsToCheck, la)
	}

}
