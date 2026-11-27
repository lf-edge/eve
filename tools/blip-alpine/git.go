// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// gitRepo is a git repository with its worktree, as openWorktree opens it.
//
// It is opened once and kept. What it fetches and commits itself it sees;
// objects that something else brings into the repository later on, another
// gitRepo or git itself, it may not see.
type gitRepo struct {
	repo *git.Repository
	wt   *git.Worktree
	// dir is the directory that the repository was opened for: the root of
	// the worktree or a directory below it
	dir string
}

// newGitRepo opens the repository that dir is in, or the current directory
// for "".
func newGitRepo(dir string) (*gitRepo, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	repo, wt, err := openWorktree(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	return &gitRepo{repo: repo, wt: wt, dir: abs}, nil
}

// openWorktree opens the repository that dir is in, be it a plain checkout
// or a linked worktree, and its worktree.
func openWorktree(dir string) (*git.Repository, *git.Worktree, error) {
	if dir == "" {
		dir = "."
	}
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err != nil {
		return nil, nil, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, nil, err
	}
	return repo, wt, nil
}

// cloneShallow does what "git clone --depth 1 --single-branch --branch
// branch --no-tags url dir" does, and returns the repository as newGitRepo
// does: dir becomes a checkout of the branch as it is at url now, with url as
// the remote origin. It gets the newest commit of the branch and nothing
// else: no history, no other branch, no tag and no submodule. That is the
// least that go-git can fetch: it has no partial clone, which would leave
// out files as well.
//
// dir may be there if it is empty; directories above it are made as needed.
// If the clone fails, nothing of it is left in dir.
func cloneShallow(url, branch, dir string) (*gitRepo, error) {
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("could not create dir %s: %v", dir, err)
	}
	// go-git clones into a directory that has files and writes over them
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("cloning into %s: %w", dir, err)
	}
	if len(entries) > 0 {
		return nil, fmt.Errorf("cloning into %s: the directory is not empty", dir)
	}
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL:           url,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	})
	if err != nil {
		return nil, fmt.Errorf("cloning the branch %s of %s into %s: %w", branch, url, dir, err)
	}
	return newGitRepo(dir)
}

// commitTracked does what "git add -u; git commit -m msg" does: it commits
// the changed and the removed files that git tracks in the worktree,
// together with what is in the index already, and leaves files that git does
// not track alone. It returns the hash of the commit, or git.ErrEmptyCommit
// if there is nothing to commit. The author is the user of the git config.
//
// With amend it does what "git add -u; git commit --amend --no-edit" does
// instead: the commit at HEAD is replaced by one that has the changes as
// well. msg is not used then; message and author stay those of the replaced
// commit, and the user of the git config becomes the committer.
//
// The repository is written with go-git; no git binary is involved, so no
// hook runs and the commit is not signed.
func (g *gitRepo) commitTracked(msg string, amend bool) (plumbing.Hash, error) {
	hash, err := g.commitTrackedIn(msg, amend)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("commit %w", err)
	}
	return hash, nil
}

func (g *gitRepo) commitTrackedIn(msg string, amend bool) (plumbing.Hash, error) {
	if !amend {
		return g.wt.Commit(msg, &git.CommitOptions{All: true})
	}

	ref, err := g.repo.Head()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	head, err := g.repo.CommitObject(ref.Hash())
	if err != nil {
		return plumbing.ZeroHash, err
	}
	// go-git gives the new commit the first parent only
	if len(head.ParentHashes) > 1 {
		return plumbing.ZeroHash, errors.New("cannot amend a merge commit")
	}
	// go-git cannot amend and stage in one go
	if err := g.addTracked(); err != nil {
		return plumbing.ZeroHash, err
	}
	// Validate fills in who commits from the git config
	who := &git.CommitOptions{}
	if err := who.Validate(g.repo); err != nil {
		return plumbing.ZeroHash, err
	}
	return g.wt.Commit(head.Message, &git.CommitOptions{
		Amend:     true,
		Author:    &head.Author,
		Committer: who.Committer,
	})
}

// addTracked does what "git add -u" does: it puts the changed and the
// removed files that git tracks into the index.
func (g *gitRepo) addTracked() error {
	status, err := g.wt.Status()
	if err != nil {
		return err
	}
	for path, s := range status {
		switch s.Worktree {
		case git.Modified:
			err = g.wt.AddWithOptions(&git.AddOptions{Path: path, SkipStatus: true})
		case git.Deleted:
			_, err = g.wt.Remove(path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// worktreeClean tells whether "git status" has nothing to report about the
// files that git tracks in the worktree: no change in the index and none in
// the worktree, so that commitTracked has nothing to commit. Files that git
// does not track do not count, as with "git status -uno": go-git takes some
// ignored files for untracked ones.
func (g *gitRepo) worktreeClean() (bool, error) {
	clean, err := g.worktreeCleanIn()
	if err != nil {
		return false, fmt.Errorf("clean %w", err)
	}
	return clean, nil
}

func (g *gitRepo) worktreeCleanIn() (bool, error) {
	status, err := g.wt.Status()
	if err != nil {
		return false, err
	}
	var head *object.Tree
	if ref, err := g.repo.Head(); err == nil {
		commit, err := g.repo.CommitObject(ref.Hash())
		if err != nil {
			return false, err
		}
		if head, err = commit.Tree(); err != nil {
			return false, err
		}
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return false, err
	}
	for path, s := range status {
		if s.Staging == git.Untracked && s.Worktree == git.Untracked {
			// go-git says this too of a file that is still there while the
			// index has its removal
			if head == nil {
				continue
			}
			if _, err := head.FindEntry(path); err != nil {
				continue
			}
			return false, nil
		}
		if s.Staging != git.Unmodified || s.Worktree != git.Unmodified {
			return false, nil
		}
	}
	return true, nil
}

// openRoot opens the directory that "git rev-parse --show-toplevel" prints:
// the root of the worktree.
func (g *gitRepo) openRoot() (*os.Root, error) {
	return os.OpenRoot(g.wt.Filesystem.Root())
}

// fetchOrigin does what "git fetch origin" does: it gets the new commits of
// the remote origin and moves the remote-tracking branches to them; HEAD and
// the worktree stay as they are. For a remote that is reached over ssh the
// key has to be in the ssh agent: go-git does not read the identity files of
// the ssh config.
func (g *gitRepo) fetchOrigin() error {
	err := g.repo.Fetch(&git.FetchOptions{RemoteName: "origin"})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("fetching origin: %w", err)
	}
	return nil
}

// resetHardOriginMaster does what "git reset --hard origin/master" does:
// the branch that HEAD is on, the index and the files that git tracks become
// those of origin/master as it was fetched last. Commits and changes that
// origin/master does not have are gone from the branch and the worktree
// after it. Files that git does not track stay.
func (g *gitRepo) resetHardOriginMaster() error {
	if err := g.resetHardIn(plumbing.NewRemoteReferenceName("origin", "master")); err != nil {
		return fmt.Errorf("reset %w", err)
	}
	return nil
}

func (g *gitRepo) resetHardIn(to plumbing.ReferenceName) error {
	ref, err := g.repo.Reference(to, true)
	if err != nil {
		return fmt.Errorf("%s: %w", to.Short(), err)
	}
	return g.resetTracked(ref.Hash())
}

// resetTracked makes the branch that HEAD is on, the index and the files
// that git tracks those of a commit.
func (g *gitRepo) resetTracked(to plumbing.Hash) error {
	// A hard reset of go-git removes every file that git does not track,
	// the ignored ones too, unless it is told which files to deal with:
	// those that git tracks now and those of the commit.
	tracked, err := g.commitFiles(to)
	if err != nil {
		return err
	}
	idx, err := g.repo.Storer.Index()
	if err != nil {
		return err
	}
	for _, e := range idx.Entries {
		tracked = append(tracked, e.Name)
	}
	return g.wt.Reset(&git.ResetOptions{Commit: to, Mode: git.HardReset, Files: tracked})
}

// checkoutNewBranch does what "git checkout -b name" does: it makes a
// branch at the commit that HEAD is at and puts HEAD on it. Index and
// worktree stay as they are, changes included.
//
// If there is a branch of that name already, it does what "git checkout -f
// name" does instead: it switches to that branch, and index and tracked
// files become those of its commit. Changes to tracked files are lost by
// that, and a file that git does not track is written over where the branch
// has a file of that name. Other files that git does not track stay.
func (g *gitRepo) checkoutNewBranch(name string) error {
	if err := g.checkoutBranchIn(name); err != nil {
		return fmt.Errorf("co %w", err)
	}
	return nil
}

func (g *gitRepo) checkoutBranchIn(name string) error {
	branch := plumbing.NewBranchReferenceName(name)
	to, err := g.repo.Reference(branch, true)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		// Keep makes go-git move HEAD only
		return g.wt.Checkout(&git.CheckoutOptions{Branch: branch, Create: true, Keep: true})
	}
	if err != nil {
		return err
	}
	// HEAD moves only if the files can follow it
	if _, err := g.commitFiles(to.Hash()); err != nil {
		return err
	}
	if err := g.repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branch)); err != nil {
		return err
	}
	return g.resetTracked(to.Hash())
}

// commitFiles returns the paths of all files and submodules of a commit.
//
// It fails if go-git cannot read all of the commit, which is what keeps a
// reset from doing harm. Git has objects that go-git does not find: go-git
// reads no packs but those named pack-…, and "git maintenance" puts loose
// objects into packs named loose-…. A directory that go-git cannot read it
// takes for the end of the directory above it, without an error, so that a
// reset to such a commit would remove most of what git tracks.
func (g *gitRepo) commitFiles(hash plumbing.Hash) ([]string, error) {
	var files []string
	commit, err := g.repo.CommitObject(hash)
	if err == nil {
		var tree *object.Tree
		if tree, err = commit.Tree(); err == nil {
			err = g.treeFiles(tree, "", &files)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("go-git cannot read all of the commit %s: %w. "+
			"It reads no packs but those named pack-*: \"git repack -a -d\" makes one such pack of all objects", hash, err)
	}
	return files, nil
}

// treeFiles adds the paths of all files and submodules in a tree, which is
// the directory dir of a commit, to files. It fails for a directory or a
// file that go-git cannot read.
func (g *gitRepo) treeFiles(tree *object.Tree, dir string, files *[]string) error {
	for _, entry := range tree.Entries {
		name := path.Join(dir, entry.Name)
		switch entry.Mode {
		case filemode.Dir:
			below, err := g.repo.TreeObject(entry.Hash)
			if err != nil {
				return fmt.Errorf("the directory %s, %s: %w", name, entry.Hash, err)
			}
			if err := g.treeFiles(below, name, files); err != nil {
				return err
			}
			continue
		case filemode.Submodule:
			// a commit of another repository
		default:
			if err := g.repo.Storer.HasEncodedObject(entry.Hash); err != nil {
				return fmt.Errorf("the file %s, %s: %w", name, entry.Hash, err)
			}
		}
		*files = append(*files, name)
	}
	return nil
}

// cleanWorktree does what "git clean -x -f -d" does in the directory that
// the repository was opened for: below that directory it removes every file
// and directory that git does not track, the ignored ones too. Like git it
// leaves a directory alone that is a repository of its own, and what is
// above that directory.
func (g *gitRepo) cleanWorktree() error {
	root := g.wt.Filesystem.Root()
	rel, err := filepath.Rel(root, g.dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside the worktree %s", g.dir, root)
	}
	if rel == "." {
		rel = ""
	}
	idx, err := g.repo.Storer.Index()
	if err != nil {
		return fmt.Errorf("repo idx %w", err)
	}
	c := cleaner{files: map[string]bool{}, dirs: map[string]bool{}}
	for _, e := range idx.Entries {
		c.files[e.Name] = true
		for d := path.Dir(e.Name); d != "." && !c.dirs[d]; d = path.Dir(d) {
			c.dirs[d] = true
		}
	}
	return c.clean(g.dir, filepath.ToSlash(rel))
}

// cleaner knows what git tracks in a worktree: the files and submodules,
// and the directories that they are in.
type cleaner struct {
	files, dirs map[string]bool
}

// clean removes what git does not track in the directory abs, which is rel
// in the worktree. It goes on after a failure and returns all of them.
func (c cleaner) clean(abs, rel string) error {
	entries, err := os.ReadDir(abs)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		entry, name := filepath.Join(abs, e.Name()), path.Join(rel, e.Name())
		if e.Name() == ".git" || c.files[name] {
			continue
		}
		if !e.IsDir() {
			errs = append(errs, os.Remove(entry))
			continue
		}
		// git clean wants a second -f for a repository of its own
		if _, err := os.Lstat(filepath.Join(entry, ".git")); err == nil {
			continue
		}
		errs = append(errs, c.clean(entry, name))
		if c.dirs[name] {
			continue
		}
		// a repository further down keeps the directory from being empty
		if err := os.Remove(entry); err != nil && !errors.Is(err, syscall.ENOTEMPTY) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// pushTo does what "git push url branch" does: it gives the repository at
// url the commits of the branch and puts its branch of that name on them.
// If that repository would lose commits by that, it fails, or with force
// does it all the same, as "git push --force" does. No remote has to be set
// up for it. auth is how to log in at url, or nil for no login.
func (g *gitRepo) pushTo(url string, auth transport.AuthMethod, branch string, force bool) error {
	ref := plumbing.NewBranchReferenceName(branch)
	// go-git pushes nothing, without a word, for a branch that is not there
	if _, err := g.repo.Reference(ref, true); err != nil {
		return fmt.Errorf("push: branch %s: %w", branch, err)
	}
	// a remote for this push alone, which the configuration does not get
	remote := git.NewRemote(g.repo.Storer, &config.RemoteConfig{Name: "push", URLs: []string{url}})
	err := remote.Push(&git.PushOptions{
		RemoteName: "push",
		RefSpecs:   []config.RefSpec{config.RefSpec(ref + ":" + ref)},
		Auth:       auth,
		Force:      force,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("pushing %s to %s: %w", branch, url, err)
	}
	return nil
}
