// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// TestMain runs the tests in an empty directory that no repository is
// around. The tests commit, reset and switch branches: whatever opens the
// repository of the current directory by mistake must not find the checkout
// that these sources are in.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "blip-alpine-test-")
	if err == nil {
		err = os.Chdir(dir)
	}
	if err == nil {
		if _, wt, found := openWorktree(""); found == nil {
			err = fmt.Errorf("the tests would run inside the repository %s", wt.Filesystem.Root())
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "not running the tests:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// A gitRepo keeps the repository open that it was made for. in opens the
// repository that dir is in anew and runs one method on it, so that every
// call sees what the calls before it left behind.
func in[T any](dir string, f func(*gitRepo) (T, error)) (T, error) {
	g, err := newGitRepo(dir)
	if err != nil {
		var none T
		return none, err
	}
	return f(g)
}

// inErr is in for a method that returns nothing but an error.
func inErr(dir string, f func(*gitRepo) error) error {
	_, err := in(dir, func(g *gitRepo) (struct{}, error) { return struct{}{}, f(g) })
	return err
}

func commitTrackedAt(dir, msg string, amend bool) (plumbing.Hash, error) {
	return in(dir, func(g *gitRepo) (plumbing.Hash, error) { return g.commitTracked(msg, amend) })
}

func worktreeCleanAt(dir string) (bool, error) {
	return in(dir, (*gitRepo).worktreeClean)
}

func fetchOriginAt(dir string) error { return inErr(dir, (*gitRepo).fetchOrigin) }

func resetHardOriginMasterAt(dir string) error { return inErr(dir, (*gitRepo).resetHardOriginMaster) }

func checkoutNewBranchAt(dir, name string) error {
	return inErr(dir, func(g *gitRepo) error { return g.checkoutNewBranch(name) })
}

func cleanWorktreeAt(dir string) error { return inErr(dir, (*gitRepo).cleanWorktree) }

func pushToAt(dir, url string, auth transport.AuthMethod, branch string, force bool) error {
	return inErr(dir, func(g *gitRepo) error { return g.pushTo(url, auth, branch, force) })
}

// testRepo is a repository in a temporary directory with one commit that
// holds a/kept, a/changed and b/removed.
type testRepo struct {
	t    *testing.T
	dir  string
	repo *git.Repository
	base plumbing.Hash
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	r := &testRepo{t: t, dir: t.TempDir()}
	var err error
	if r.repo, err = git.PlainInit(r.dir, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := r.repo.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.User.Name, cfg.User.Email = "Bumper", "bumper@example.com"
	if err := r.repo.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	r.write("a/kept", "kept\n")
	r.write("a/changed", "before\n")
	r.write("b/removed", "removed\n")
	wt, err := r.repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a/kept", "a/changed", "b/removed"} {
		if _, err := wt.Add(name); err != nil {
			t.Fatal(err)
		}
	}
	if r.base, err = wt.Commit("base", &git.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *testRepo) write(name, content string) {
	r.t.Helper()
	path := filepath.Join(r.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		r.t.Fatal(err)
	}
}

// head returns the commit that HEAD is at and the files in it with their
// contents.
func (r *testRepo) head() (*object.Commit, map[string]string) {
	r.t.Helper()
	ref, err := r.repo.Head()
	if err != nil {
		r.t.Fatal(err)
	}
	commit, err := r.repo.CommitObject(ref.Hash())
	if err != nil {
		r.t.Fatal(err)
	}
	files, err := commit.Files()
	if err != nil {
		r.t.Fatal(err)
	}
	contents := map[string]string{}
	err = files.ForEach(func(f *object.File) error {
		content, err := f.Contents()
		contents[f.Name] = content
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return commit, contents
}

func sameFiles(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for name, content := range want {
		if c, ok := got[name]; !ok || c != content {
			return false
		}
	}
	return true
}

func TestCommitTracked(t *testing.T) {
	t.Run("commits changed and removed files and leaves new ones out", func(t *testing.T) {
		r := newTestRepo(t)
		r.write("a/changed", "after\n")
		if err := os.Remove(filepath.Join(r.dir, "b", "removed")); err != nil {
			t.Fatal(err)
		}
		r.write("a/new", "new\n")

		hash, err := commitTrackedAt(r.dir, "m", false)
		if err != nil {
			t.Fatalf("commitTracked: %v", err)
		}

		commit, files := r.head()
		if commit.Hash != hash {
			t.Errorf("HEAD is at %s, commitTracked returned %s", commit.Hash, hash)
		}
		if commit.Message != "m" {
			t.Errorf("message %q, want %q", commit.Message, "m")
		}
		if !slices.Equal(commit.ParentHashes, []plumbing.Hash{r.base}) {
			t.Errorf("parents %v, want %v", commit.ParentHashes, r.base)
		}
		if commit.Author.Name != "Bumper" || commit.Author.Email != "bumper@example.com" {
			t.Errorf("author %s <%s>, want the user of the git config", commit.Author.Name, commit.Author.Email)
		}
		want := map[string]string{"a/kept": "kept\n", "a/changed": "after\n"}
		if !sameFiles(files, want) {
			t.Errorf("files %q, want %q", files, want)
		}
		if _, err := os.Stat(filepath.Join(r.dir, "a", "new")); err != nil {
			t.Errorf("the new file is gone: %v", err)
		}
	})

	t.Run("commits what is in the index already", func(t *testing.T) {
		r := newTestRepo(t)
		r.write("a/added", "added\n")
		wt, err := r.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("a/added"); err != nil {
			t.Fatal(err)
		}

		if _, err := commitTrackedAt(r.dir, "m", false); err != nil {
			t.Fatalf("commitTracked: %v", err)
		}

		_, files := r.head()
		want := map[string]string{"a/kept": "kept\n", "a/changed": "before\n", "b/removed": "removed\n", "a/added": "added\n"}
		if !sameFiles(files, want) {
			t.Errorf("files %q, want %q", files, want)
		}
	})

	t.Run("commits the whole worktree from a directory in it", func(t *testing.T) {
		r := newTestRepo(t)
		r.write("a/changed", "after\n")

		if _, err := commitTrackedAt(filepath.Join(r.dir, "b"), "m", false); err != nil {
			t.Fatalf("commitTracked: %v", err)
		}

		_, files := r.head()
		if files["a/changed"] != "after\n" {
			t.Errorf("a/changed is %q in the commit, want %q", files["a/changed"], "after\n")
		}
	})

	t.Run("makes no commit when nothing changed", func(t *testing.T) {
		r := newTestRepo(t)
		r.write("a/new", "new\n")

		_, err := commitTrackedAt(r.dir, "m", false)
		if !errors.Is(err, git.ErrEmptyCommit) {
			t.Errorf("got error %v, want %v", err, git.ErrEmptyCommit)
		}
		if commit, _ := r.head(); commit.Hash != r.base {
			t.Errorf("HEAD moved to %s", commit.Hash)
		}
	})

	t.Run("fails outside a repository", func(t *testing.T) {
		if hash, err := commitTrackedAt(t.TempDir(), "m", false); err == nil {
			t.Errorf("commitTracked gave no error, but %s", hash)
		}
	})
}

func TestCommitTrackedAmend(t *testing.T) {
	author := object.Signature{
		Name:  "Author",
		Email: "author@example.com",
		When:  time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	// second puts a commit by author on top of the base that changes a/kept.
	second := func(r *testRepo) plumbing.Hash {
		r.t.Helper()
		r.write("a/kept", "second\n")
		wt, err := r.repo.Worktree()
		if err != nil {
			r.t.Fatal(err)
		}
		if _, err := wt.Add("a/kept"); err != nil {
			r.t.Fatal(err)
		}
		hash, err := wt.Commit("second\n\nwith a body\n", &git.CommitOptions{Author: &author})
		if err != nil {
			r.t.Fatal(err)
		}
		return hash
	}

	t.Run("puts the changes into the commit at HEAD and keeps its message and author", func(t *testing.T) {
		r := newTestRepo(t)
		replaced := second(r)
		r.write("a/changed", "after\n")
		if err := os.Remove(filepath.Join(r.dir, "b", "removed")); err != nil {
			t.Fatal(err)
		}
		r.write("a/new", "new\n")

		hash, err := commitTrackedAt(r.dir, "not used", true)
		if err != nil {
			t.Fatalf("commitTracked: %v", err)
		}

		commit, files := r.head()
		if commit.Hash != hash || hash == replaced {
			t.Errorf("HEAD is at %s, commitTracked returned %s, the commit before was %s", commit.Hash, hash, replaced)
		}
		if !slices.Equal(commit.ParentHashes, []plumbing.Hash{r.base}) {
			t.Errorf("parents %v, want %v", commit.ParentHashes, r.base)
		}
		if want := "second\n\nwith a body\n"; commit.Message != want {
			t.Errorf("message %q, want %q", commit.Message, want)
		}
		if commit.Author.Name != author.Name || commit.Author.Email != author.Email || !commit.Author.When.Equal(author.When) {
			t.Errorf("author %v, want %v", commit.Author, author)
		}
		if commit.Committer.Name != "Bumper" || time.Since(commit.Committer.When) > time.Hour {
			t.Errorf("committer %v, want the user of the git config and the time of now", commit.Committer)
		}
		want := map[string]string{"a/kept": "second\n", "a/changed": "after\n"}
		if !sameFiles(files, want) {
			t.Errorf("files %q, want %q", files, want)
		}
	})

	t.Run("makes the commit anew when nothing changed", func(t *testing.T) {
		r := newTestRepo(t)
		second(r)

		if _, err := commitTrackedAt(r.dir, "not used", true); err != nil {
			t.Fatalf("commitTracked: %v", err)
		}

		commit, files := r.head()
		if !slices.Equal(commit.ParentHashes, []plumbing.Hash{r.base}) {
			t.Errorf("parents %v, want %v", commit.ParentHashes, r.base)
		}
		if commit.Committer.Name != "Bumper" {
			t.Errorf("committer %v, want the user of the git config", commit.Committer)
		}
		want := map[string]string{"a/kept": "second\n", "a/changed": "before\n", "b/removed": "removed\n"}
		if !sameFiles(files, want) {
			t.Errorf("files %q, want %q", files, want)
		}
	})

	t.Run("refuses a merge commit, which would lose a parent", func(t *testing.T) {
		r := newTestRepo(t)
		side := second(r)
		wt, err := r.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		merge, err := wt.Commit("merge", &git.CommitOptions{
			Parents:           []plumbing.Hash{side, r.base},
			AllowEmptyCommits: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		r.write("a/changed", "after\n")

		if hash, err := commitTrackedAt(r.dir, "not used", true); err == nil {
			t.Errorf("commitTracked gave no error, but %s", hash)
		}
		if commit, _ := r.head(); commit.Hash != merge {
			t.Errorf("HEAD moved to %s", commit.Hash)
		}
	})
}

func TestWorktreeClean(t *testing.T) {
	cases := []struct {
		name   string
		change func(r *testRepo)
		want   bool
	}{
		{
			name:   "nothing changed",
			change: func(*testRepo) {},
			want:   true,
		},
		{
			name:   "only a file that git does not track",
			change: func(r *testRepo) { r.write("a/new", "new\n") },
			want:   true,
		},
		{
			name:   "changed file",
			change: func(r *testRepo) { r.write("a/changed", "after\n") },
			want:   false,
		},
		{
			name: "removed file",
			change: func(r *testRepo) {
				if err := os.Remove(filepath.Join(r.dir, "b", "removed")); err != nil {
					r.t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "file that became executable",
			change: func(r *testRepo) {
				if err := os.Chmod(filepath.Join(r.dir, "a", "kept"), 0755); err != nil {
					r.t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "new file in the index",
			change: func(r *testRepo) {
				r.write("a/added", "added\n")
				wt, err := r.repo.Worktree()
				if err != nil {
					r.t.Fatal(err)
				}
				if _, err := wt.Add("a/added"); err != nil {
					r.t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "change in the index that the worktree does not have any more",
			change: func(r *testRepo) {
				r.write("a/changed", "after\n")
				wt, err := r.repo.Worktree()
				if err != nil {
					r.t.Fatal(err)
				}
				if _, err := wt.Add("a/changed"); err != nil {
					r.t.Fatal(err)
				}
				r.write("a/changed", "before\n")
			},
			want: false,
		},
		{
			name: "removal in the index of a file that is still there",
			change: func(r *testRepo) {
				wt, err := r.repo.Worktree()
				if err != nil {
					r.t.Fatal(err)
				}
				if _, err := wt.Remove("b/removed"); err != nil {
					r.t.Fatal(err)
				}
				r.write("b/removed", "removed\n")
			},
			want: false,
		},
		{
			name: "changes that commitTracked committed",
			change: func(r *testRepo) {
				r.write("a/changed", "after\n")
				r.write("a/new", "new\n")
				if _, err := commitTrackedAt(r.dir, "m", false); err != nil {
					r.t.Fatal(err)
				}
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRepo(t)
			tc.change(r)
			// asked from a directory that has no change of its own
			got, err := worktreeCleanAt(filepath.Join(r.dir, "b"))
			if err != nil {
				t.Fatalf("worktreeClean: %v", err)
			}
			if got != tc.want {
				t.Fatalf("worktreeClean = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("repository without a commit", func(t *testing.T) {
		dir := t.TempDir()
		repo, err := git.PlainInit(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "new"), []byte("new\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if clean, err := worktreeCleanAt(dir); err != nil || !clean {
			t.Errorf("with a file that git does not track: worktreeClean = %v, %v, want true", clean, err)
		}
		wt, err := repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("new"); err != nil {
			t.Fatal(err)
		}
		if clean, err := worktreeCleanAt(dir); err != nil || clean {
			t.Errorf("with a file in the index: worktreeClean = %v, %v, want false", clean, err)
		}
	})

	t.Run("fails outside a repository", func(t *testing.T) {
		if clean, err := worktreeCleanAt(t.TempDir()); err == nil {
			t.Errorf("worktreeClean gave no error, but %v", clean)
		}
	})
}

func TestOpenRoot(t *testing.T) {
	r := newTestRepo(t)
	for _, from := range []string{".", "a"} {
		root, err := in(filepath.Join(r.dir, from), (*gitRepo).openRoot)
		if err != nil {
			t.Fatalf("openRoot in %s: %v", from, err)
		}
		if got, err := root.ReadFile("a/kept"); err != nil || string(got) != "kept\n" {
			t.Errorf("openRoot in %s: a/kept is %q (%v)", from, got, err)
		}
		if !filepath.IsAbs(root.Name()) {
			t.Errorf("openRoot in %s: the name %s is not absolute", from, root.Name())
		}
		root.Close()
	}
	if root, err := in(t.TempDir(), (*gitRepo).openRoot); err == nil {
		t.Errorf("openRoot gave no error outside a repository, but %s", root.Name())
	}
}

// serveHTTP serves the repository over http, the way a git server does it,
// and returns its URL.
func serveHTTP(t *testing.T, r *testRepo) string {
	t.Helper()
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git is needed to serve a repository over http: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git is needed to serve a repository over http: %v", err)
	}
	server := httptest.NewServer(&cgi.Handler{
		Path: backend,
		Env:  []string{"GIT_PROJECT_ROOT=" + filepath.Dir(r.dir), "GIT_HTTP_EXPORT_ALL=1"},
	})
	t.Cleanup(server.Close)
	return server.URL + "/" + filepath.Base(r.dir) + "/.git"
}

func TestFetchOrigin(t *testing.T) {
	if _, err := exec.LookPath("git-upload-pack"); err != nil {
		t.Skip("go-git reads a repository in a local directory with git-upload-pack")
	}
	// remoteHead returns what the clone in dir knows as the branch of origin.
	remoteHead := func(t *testing.T, dir string, origin *testRepo) plumbing.Hash {
		t.Helper()
		head, err := origin.repo.Head()
		if err != nil {
			t.Fatal(err)
		}
		clone, err := git.PlainOpen(dir)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := clone.Reference(plumbing.NewRemoteReferenceName("origin", head.Name().Short()), true)
		if err != nil {
			t.Fatal(err)
		}
		return ref.Hash()
	}

	transports := []struct {
		name string
		url  func(t *testing.T, origin *testRepo) string
	}{
		{"from a local directory", func(_ *testing.T, origin *testRepo) string { return origin.dir }},
		{"over http", serveHTTP},
	}
	for _, transport := range transports {
		t.Run(transport.name, func(t *testing.T) {
			t.Run("gets the new commits of origin and leaves HEAD where it is", func(t *testing.T) {
				origin := newTestRepo(t)
				dir := t.TempDir()
				if _, err := git.PlainClone(dir, false, &git.CloneOptions{URL: transport.url(t, origin)}); err != nil {
					t.Fatal(err)
				}
				origin.write("a/changed", "after\n")
				added, err := commitTrackedAt(origin.dir, "more", false)
				if err != nil {
					t.Fatal(err)
				}

				if err := fetchOriginAt(filepath.Join(dir, "a")); err != nil {
					t.Fatalf("fetchOrigin: %v", err)
				}

				if got := remoteHead(t, dir, origin); got != added {
					t.Errorf("the branch of origin is at %s, want %s", got, added)
				}
				// opened after the fetch: a repository that is open does not see new packs
				clone, err := git.PlainOpen(dir)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := clone.CommitObject(added); err != nil {
					t.Errorf("the new commit is not there: %v", err)
				}
				if head, err := clone.Head(); err != nil || head.Hash() != origin.base {
					t.Errorf("HEAD is at %v (%v), want %s", head, err, origin.base)
				}
			})

			t.Run("succeeds when there is nothing new", func(t *testing.T) {
				origin := newTestRepo(t)
				dir := t.TempDir()
				if _, err := git.PlainClone(dir, false, &git.CloneOptions{URL: transport.url(t, origin)}); err != nil {
					t.Fatal(err)
				}

				if err := fetchOriginAt(dir); err != nil {
					t.Fatalf("fetchOrigin: %v", err)
				}

				if got := remoteHead(t, dir, origin); got != origin.base {
					t.Errorf("the branch of origin is at %s, want %s", got, origin.base)
				}
			})
		})
	}

	t.Run("fails without a remote called origin", func(t *testing.T) {
		r := newTestRepo(t)
		if err := fetchOriginAt(r.dir); err == nil {
			t.Error("fetchOrigin gave no error")
		}
	})

	t.Run("fails when origin does not answer", func(t *testing.T) {
		origin := newTestRepo(t)
		url := serveHTTP(t, origin)
		dir := t.TempDir()
		if _, err := git.PlainClone(dir, false, &git.CloneOptions{URL: url}); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(origin.dir, ".git")); err != nil {
			t.Fatal(err)
		}

		if err := fetchOriginAt(dir); err == nil {
			t.Error("fetchOrigin gave no error")
		}
	})
}

func TestResetHardOriginMaster(t *testing.T) {
	if _, err := exec.LookPath("git-upload-pack"); err != nil {
		t.Skip("go-git reads a repository in a local directory with git-upload-pack")
	}
	exists := func(dir, name string) bool {
		_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(name)))
		return err == nil
	}
	content := func(t *testing.T, dir, name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("makes branch, index and tracked files those of origin/master and keeps other files", func(t *testing.T) {
		origin := newTestRepo(t)
		if origin.branch() != "master" {
			t.Skipf("the test repository is on %s", origin.branch())
		}
		dir := t.TempDir()
		if _, err := git.PlainClone(dir, false, &git.CloneOptions{URL: origin.dir}); err != nil {
			t.Fatal(err)
		}
		clone := &testRepo{t: t, dir: dir}

		// origin moves on: one file changed, one removed, one added
		origin.write("a/changed", "after\n")
		if err := os.Remove(filepath.Join(origin.dir, "b", "removed")); err != nil {
			t.Fatal(err)
		}
		origin.write("c/added", "added\n")
		wt, err := origin.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("c/added"); err != nil {
			t.Fatal(err)
		}
		target, err := commitTrackedAt(origin.dir, "more", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := fetchOriginAt(dir); err != nil {
			t.Fatal(err)
		}

		// the clone has a commit of its own, a change that is not committed,
		// a file in the index, and files that git does not track
		clone.write("a/kept", "committed here\n")
		if _, err := commitTrackedAt(dir, "local", false); err != nil {
			t.Fatal(err)
		}
		clone.write("a/kept", "changed here\n")
		clone.write("d/staged", "staged\n")
		if clone.repo, err = git.PlainOpen(dir); err != nil {
			t.Fatal(err)
		}
		cwt, err := clone.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cwt.Add("d/staged"); err != nil {
			t.Fatal(err)
		}
		clone.write("a/untracked", "untracked\n")
		clone.write("e/untracked", "untracked\n")
		clone.write(".gitignore", "ignored/\n")
		clone.write("ignored/file", "ignored\n")

		if err := resetHardOriginMasterAt(filepath.Join(dir, "a")); err != nil {
			t.Fatalf("resetHardOriginMaster: %v", err)
		}

		if clone.repo, err = git.PlainOpen(dir); err != nil {
			t.Fatal(err)
		}
		head, err := clone.repo.Head()
		if err != nil {
			t.Fatal(err)
		}
		if head.Hash() != target || head.Name().Short() != "master" {
			t.Errorf("HEAD is %s at %s, want master at %s", head.Name(), head.Hash(), target)
		}
		for name, want := range map[string]string{"a/kept": "kept\n", "a/changed": "after\n", "c/added": "added\n"} {
			if got := content(t, dir, name); got != want {
				t.Errorf("%s is %q, want %q", name, got, want)
			}
		}
		for _, name := range []string{"b/removed", "d/staged"} {
			if exists(dir, name) {
				t.Errorf("%s is still there", name)
			}
		}
		for _, name := range []string{"a/untracked", "e/untracked", ".gitignore", "ignored/file"} {
			if !exists(dir, name) {
				t.Errorf("%s is gone", name)
			}
		}
		if clean, err := worktreeCleanAt(dir); err != nil || !clean {
			t.Errorf("worktreeClean = %v, %v, want true", clean, err)
		}
	})

	t.Run("fails and changes nothing without an origin/master", func(t *testing.T) {
		r := newTestRepo(t)
		r.write("a/changed", "changed here\n")
		if err := resetHardOriginMasterAt(r.dir); err == nil {
			t.Error("resetHardOriginMaster gave no error")
		}
		if got := content(t, r.dir, "a/changed"); got != "changed here\n" {
			t.Errorf("a/changed is %q, want it as it was", got)
		}
	})
}

// branch returns the name of the branch that HEAD is on.
func (r *testRepo) branch() string {
	r.t.Helper()
	head, err := r.repo.Head()
	if err != nil {
		r.t.Fatal(err)
	}
	return head.Name().Short()
}

func TestCheckoutNewBranch(t *testing.T) {
	t.Run("puts HEAD on a new branch at the same commit and keeps all changes", func(t *testing.T) {
		r := newTestRepo(t)
		was := r.branch()
		r.write("a/changed", "after\n")
		r.write("a/new", "new\n")
		r.write("s/staged", "staged\n")
		wt, err := r.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("s/staged"); err != nil {
			t.Fatal(err)
		}

		if err := checkoutNewBranchAt(filepath.Join(r.dir, "a"), "bump"); err != nil {
			t.Fatalf("checkoutNewBranch: %v", err)
		}

		if r.repo, err = git.PlainOpen(r.dir); err != nil {
			t.Fatal(err)
		}
		head, err := r.repo.Head()
		if err != nil {
			t.Fatal(err)
		}
		if head.Name() != plumbing.NewBranchReferenceName("bump") || head.Hash() != r.base {
			t.Errorf("HEAD is %s at %s, want the branch bump at %s", head.Name(), head.Hash(), r.base)
		}
		for name, want := range map[string]string{"a/changed": "after\n", "a/new": "new\n", "s/staged": "staged\n", "a/kept": "kept\n"} {
			got, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(name)))
			if err != nil || string(got) != want {
				t.Errorf("%s is %q (%v), want %q", name, got, err, want)
			}
		}

		// what was changed and staged goes into a commit on the new branch only
		added, err := commitTrackedAt(r.dir, "m", false)
		if err != nil {
			t.Fatalf("commitTracked: %v", err)
		}
		if r.repo, err = git.PlainOpen(r.dir); err != nil {
			t.Fatal(err)
		}
		_, files := r.head()
		want := map[string]string{"a/kept": "kept\n", "a/changed": "after\n", "b/removed": "removed\n", "s/staged": "staged\n"}
		if !sameFiles(files, want) {
			t.Errorf("files %q, want %q", files, want)
		}
		for branch, want := range map[string]plumbing.Hash{"bump": added, was: r.base} {
			ref, err := r.repo.Reference(plumbing.NewBranchReferenceName(branch), true)
			if err != nil || ref.Hash() != want {
				t.Errorf("branch %s is at %v (%v), want %s", branch, ref, err, want)
			}
		}
	})

	t.Run("fails when the branch cannot have that name", func(t *testing.T) {
		r := newTestRepo(t)
		for _, name := range []string{"two words", "", "a..b"} {
			if err := checkoutNewBranchAt(r.dir, name); err == nil {
				t.Errorf("checkoutNewBranchAt(%q) gave no error", name)
			}
			if got := r.branch(); got != "master" {
				t.Errorf("after checkoutNewBranchAt(%q) HEAD is on %s", name, got)
			}
		}
	})
}

func TestCheckoutNewBranchThatExists(t *testing.T) {
	read := func(t *testing.T, r *testRepo, name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(name)))
		if errors.Is(err, os.ErrNotExist) {
			return "(none)"
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// onBranch tells the branch that HEAD is on, read anew from the disk.
	onBranch := func(t *testing.T, r *testRepo) string {
		t.Helper()
		var err error
		if r.repo, err = git.PlainOpen(r.dir); err != nil {
			t.Fatal(err)
		}
		return r.branch()
	}
	// other makes a branch "other" with a commit that changes a/changed,
	// removes b/removed and adds c/added, and leaves HEAD on it.
	other := func(t *testing.T, r *testRepo) {
		t.Helper()
		if err := checkoutNewBranchAt(r.dir, "other"); err != nil {
			t.Fatal(err)
		}
		r.write("a/changed", "on other\n")
		if err := os.Remove(filepath.Join(r.dir, "b", "removed")); err != nil {
			t.Fatal(err)
		}
		r.write("c/added", "added\n")
		wt, err := r.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("c/added"); err != nil {
			t.Fatal(err)
		}
		if _, err := commitTrackedAt(r.dir, "on other", false); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("at the same commit: drops the changes to tracked files and keeps the others", func(t *testing.T) {
		r := newTestRepo(t)
		if err := checkoutNewBranchAt(r.dir, "same"); err != nil {
			t.Fatal(err)
		}
		if err := checkoutNewBranchAt(r.dir, "master"); err != nil {
			t.Fatalf("back to master: %v", err)
		}
		r.write("a/changed", "after\n")
		r.write("a/new", "new\n")
		r.write("s/staged", "staged\n")
		wt, err := r.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("s/staged"); err != nil {
			t.Fatal(err)
		}

		if err := checkoutNewBranchAt(r.dir, "same"); err != nil {
			t.Fatalf("checkoutNewBranch: %v", err)
		}

		if got := onBranch(t, r); got != "same" {
			t.Errorf("HEAD is on %s, want same", got)
		}
		for name, want := range map[string]string{"a/changed": "before\n", "a/new": "new\n", "s/staged": "(none)"} {
			if got := read(t, r, name); got != want {
				t.Errorf("%s is %q, want %q", name, got, want)
			}
		}
		if clean, err := worktreeCleanAt(r.dir); err != nil || !clean {
			t.Errorf("worktreeClean = %v, %v, want true", clean, err)
		}
	})

	t.Run("at another commit: brings the tracked files along and keeps the others", func(t *testing.T) {
		r := newTestRepo(t)
		other(t, r)
		r.write("a/untracked", "untracked\n")
		r.write(".gitignore", "ignored/\n")
		r.write("ignored/file", "ignored\n")

		steps := []struct {
			branch                  string
			changed, removed, added string
		}{
			{"master", "before\n", "removed\n", "(none)"},
			{"other", "on other\n", "(none)", "added\n"},
			{"master", "before\n", "removed\n", "(none)"},
		}
		for _, step := range steps {
			if err := checkoutNewBranchAt(filepath.Join(r.dir, "a"), step.branch); err != nil {
				t.Fatalf("to %s: %v", step.branch, err)
			}
			if got := onBranch(t, r); got != step.branch {
				t.Errorf("HEAD is on %s, want %s", got, step.branch)
			}
			for name, want := range map[string]string{
				"a/changed": step.changed, "b/removed": step.removed, "c/added": step.added,
				"a/kept": "kept\n", "a/untracked": "untracked\n", "ignored/file": "ignored\n", ".gitignore": "ignored/\n",
			} {
				if got := read(t, r, name); got != want {
					t.Errorf("on %s: %s is %q, want %q", step.branch, name, got, want)
				}
			}
			if clean, err := worktreeCleanAt(r.dir); err != nil || !clean {
				t.Errorf("on %s: worktreeClean = %v, %v, want true", step.branch, clean, err)
			}
		}
	})

	t.Run("at another commit: drops changes to tracked files, in the index or not", func(t *testing.T) {
		for _, staged := range []bool{false, true} {
			r := newTestRepo(t)
			other(t, r)
			r.write("a/kept", "changed here\n")
			if staged {
				wt, err := r.repo.Worktree()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := wt.Add("a/kept"); err != nil {
					t.Fatal(err)
				}
			}

			if err := checkoutNewBranchAt(r.dir, "master"); err != nil {
				t.Fatalf("staged=%v: checkoutNewBranch: %v", staged, err)
			}

			if got := onBranch(t, r); got != "master" {
				t.Errorf("staged=%v: HEAD is on %s, want master", staged, got)
			}
			for name, want := range map[string]string{"a/kept": "kept\n", "a/changed": "before\n", "c/added": "(none)"} {
				if got := read(t, r, name); got != want {
					t.Errorf("staged=%v: %s is %q, want %q", staged, name, got, want)
				}
			}
			if clean, err := worktreeCleanAt(r.dir); err != nil || !clean {
				t.Errorf("staged=%v: worktreeClean = %v, %v, want true", staged, clean, err)
			}
		}
	})

	t.Run("at another commit: writes over a file in the way that git does not track", func(t *testing.T) {
		r := newTestRepo(t)
		other(t, r)
		if err := checkoutNewBranchAt(r.dir, "master"); err != nil {
			t.Fatal(err)
		}
		r.write("c/added", "mine, not committed anywhere\n")
		r.write("c/untracked", "untracked\n")

		if err := checkoutNewBranchAt(r.dir, "other"); err != nil {
			t.Fatalf("checkoutNewBranch: %v", err)
		}

		if got := onBranch(t, r); got != "other" {
			t.Errorf("HEAD is on %s, want other", got)
		}
		for name, want := range map[string]string{"c/added": "added\n", "c/untracked": "untracked\n", "a/changed": "on other\n"} {
			if got := read(t, r, name); got != want {
				t.Errorf("%s is %q, want %q", name, got, want)
			}
		}
		if clean, err := worktreeCleanAt(r.dir); err != nil || !clean {
			t.Errorf("worktreeClean = %v, %v, want true", clean, err)
		}
	})
}

func TestCleanWorktree(t *testing.T) {
	// dirty makes a repository with all kinds of files that git does not
	// track, and returns it with a file outside of it that a link points to.
	dirty := func(t *testing.T) (*testRepo, string) {
		t.Helper()
		r := newTestRepo(t)
		r.write(".gitignore", "ignored/\n*.log\n")
		wt, err := r.repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add(".gitignore"); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Commit("ignore", &git.CommitOptions{}); err != nil {
			t.Fatal(err)
		}
		r.write("a/changed", "after\n")
		r.write("s/staged", "staged\n")
		if _, err := wt.Add("s/staged"); err != nil {
			t.Fatal(err)
		}
		r.write("a/new", "new\n")
		r.write("a/debug.log", "log\n")
		r.write("u/deep/file", "untracked\n")
		r.write("ignored/file", "ignored\n")
		if err := os.Mkdir(filepath.Join(r.dir, "empty"), 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := git.PlainInit(filepath.Join(r.dir, "u", "nested"), false); err != nil {
			t.Fatal(err)
		}
		r.write("u/nested/file", "of another repository\n")
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(outside), filepath.Join(r.dir, "link")); err != nil {
			t.Fatal(err)
		}
		return r, outside
	}
	// left lists what is in the directory of the repository, .git aside.
	left := func(t *testing.T, r *testRepo) []string {
		t.Helper()
		var names []string
		err := filepath.WalkDir(r.dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(r.dir, path)
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			if rel != "." && !d.IsDir() {
				names = append(names, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// empty directories count as well
		for _, dir := range []string{"empty", "u", "u/deep", "ignored"} {
			if entries, err := os.ReadDir(filepath.Join(r.dir, dir)); err == nil && len(entries) == 0 {
				names = append(names, dir+"/")
			}
		}
		slices.Sort(names)
		return names
	}

	t.Run("removes what git does not track, ignored or not, and nothing else", func(t *testing.T) {
		r, outside := dirty(t)

		if err := cleanWorktreeAt(r.dir); err != nil {
			t.Fatalf("cleanWorktree: %v", err)
		}

		want := []string{".gitignore", "a/changed", "a/kept", "b/removed", "s/staged", "u/nested/file"}
		if got := left(t, r); !slices.Equal(got, want) {
			t.Errorf("left: %q, want %q", got, want)
		}
		if got, err := os.ReadFile(filepath.Join(r.dir, "a", "changed")); err != nil || string(got) != "after\n" {
			t.Errorf("a/changed is %q (%v), want the change kept", got, err)
		}
		if _, err := os.Stat(outside); err != nil {
			t.Errorf("the file that the link pointed to is gone: %v", err)
		}
		if _, err := git.PlainOpen(filepath.Join(r.dir, "u", "nested")); err != nil {
			t.Errorf("the repository inside is broken: %v", err)
		}
		if clean, err := worktreeCleanAt(r.dir); err != nil || clean {
			t.Errorf("worktreeClean = %v, %v, want the tracked changes still there", clean, err)
		}
	})

	t.Run("cleans only below the directory it is given", func(t *testing.T) {
		r, _ := dirty(t)

		if err := cleanWorktreeAt(filepath.Join(r.dir, "a")); err != nil {
			t.Fatalf("cleanWorktree: %v", err)
		}

		want := []string{".gitignore", "a/changed", "a/kept", "b/removed", "empty/", "ignored/file", "link", "s/staged", "u/deep/file", "u/nested/file"}
		if got := left(t, r); !slices.Equal(got, want) {
			t.Errorf("left: %q, want %q", got, want)
		}
	})

	t.Run("removes nothing outside a repository", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := cleanWorktreeAt(dir); err == nil {
			t.Error("cleanWorktree gave no error")
		}
		if _, err := os.Stat(file); err != nil {
			t.Errorf("the file is gone: %v", err)
		}
	})
}

func TestPush(t *testing.T) {
	if _, err := exec.LookPath("git-receive-pack"); err != nil {
		t.Skip("go-git writes to a repository in a local directory with git-receive-pack")
	}
	// fork makes an empty repository to push to, which no remote of r
	// stands for, and returns how to ask it where a branch is, and its URL.
	fork := func(t *testing.T, _ *testRepo) (func(branch string) plumbing.Hash, string) {
		t.Helper()
		dir := t.TempDir()
		if _, err := git.PlainInit(dir, true); err != nil {
			t.Fatal(err)
		}
		return func(branch string) plumbing.Hash {
			t.Helper()
			remote, err := git.PlainOpen(dir)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := remote.Reference(plumbing.NewBranchReferenceName(branch), true)
			if errors.Is(err, plumbing.ErrReferenceNotFound) {
				return plumbing.ZeroHash
			}
			if err != nil {
				t.Fatal(err)
			}
			return ref.Hash()
		}, dir
	}

	t.Run("puts the branch on the remote and follows it up", func(t *testing.T) {
		r := newTestRepo(t)
		at, forkURL := fork(t, r)
		if err := checkoutNewBranchAt(r.dir, "bump"); err != nil {
			t.Fatal(err)
		}
		r.write("a/changed", "after\n")
		first, err := commitTrackedAt(r.dir, "bump", false)
		if err != nil {
			t.Fatal(err)
		}

		if err := pushToAt(filepath.Join(r.dir, "a"), forkURL, nil, "bump", false); err != nil {
			t.Fatalf("push: %v", err)
		}
		if got := at("bump"); got != first {
			t.Errorf("bump is at %s on the remote, want %s", got, first)
		}
		if got := at("master"); !got.IsZero() {
			t.Errorf("master is on the remote as well, at %s", got)
		}

		if err := pushToAt(r.dir, forkURL, nil, "bump", false); err != nil {
			t.Errorf("push with nothing new: %v", err)
		}

		r.write("a/changed", "and once more\n")
		second, err := commitTrackedAt(r.dir, "more", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := pushToAt(r.dir, forkURL, nil, "bump", false); err != nil {
			t.Fatalf("push of a commit on top: %v", err)
		}
		if got := at("bump"); got != second {
			t.Errorf("bump is at %s on the remote, want %s", got, second)
		}
	})

	t.Run("pushes the branch it is given, not the one that HEAD is on", func(t *testing.T) {
		r := newTestRepo(t)
		at, forkURL := fork(t, r)
		if err := checkoutNewBranchAt(r.dir, "bump"); err != nil {
			t.Fatal(err)
		}
		r.write("a/changed", "after\n")
		if _, err := commitTrackedAt(r.dir, "bump", false); err != nil {
			t.Fatal(err)
		}

		if err := pushToAt(r.dir, forkURL, nil, "master", false); err != nil {
			t.Fatalf("push: %v", err)
		}
		if got := at("master"); got != r.base {
			t.Errorf("master is at %s on the remote, want %s", got, r.base)
		}
		if got := at("bump"); !got.IsZero() {
			t.Errorf("bump is on the remote as well, at %s", got)
		}
	})

	t.Run("does not replace commits that the remote has", func(t *testing.T) {
		r := newTestRepo(t)
		at, forkURL := fork(t, r)
		r.write("a/changed", "after\n")
		pushed, err := commitTrackedAt(r.dir, "bump", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := pushToAt(r.dir, forkURL, nil, "master", false); err != nil {
			t.Fatal(err)
		}
		r.write("a/changed", "amended\n")
		if _, err := commitTrackedAt(r.dir, "", true); err != nil {
			t.Fatal(err)
		}

		if err := pushToAt(r.dir, forkURL, nil, "master", false); err == nil {
			t.Error("push gave no error")
		}
		if got := at("master"); got != pushed {
			t.Errorf("master is at %s on the remote, want it left at %s", got, pushed)
		}
	})

	t.Run("with force replaces commits that the remote has", func(t *testing.T) {
		r := newTestRepo(t)
		at, forkURL := fork(t, r)
		r.write("a/changed", "after\n")
		if _, err := commitTrackedAt(r.dir, "bump", false); err != nil {
			t.Fatal(err)
		}
		if err := pushToAt(r.dir, forkURL, nil, "master", true); err != nil {
			t.Fatalf("first push: %v", err)
		}
		r.write("a/changed", "amended\n")
		amended, err := commitTrackedAt(r.dir, "", true)
		if err != nil {
			t.Fatal(err)
		}

		if err := pushToAt(r.dir, forkURL, nil, "master", true); err != nil {
			t.Fatalf("push: %v", err)
		}
		if got := at("master"); got != amended {
			t.Errorf("master is at %s on the remote, want %s", got, amended)
		}
	})

	t.Run("needs no remote in the configuration of the repository", func(t *testing.T) {
		r := newTestRepo(t)
		at, forkURL := fork(t, r)
		if remotes, err := r.repo.Remotes(); err != nil || len(remotes) != 0 {
			t.Fatalf("the repository has remotes %v (%v), want none", remotes, err)
		}

		if err := pushToAt(r.dir, forkURL, nil, "master", false); err != nil {
			t.Fatalf("push: %v", err)
		}
		if got := at("master"); got != r.base {
			t.Errorf("master is at %s on the remote, want %s", got, r.base)
		}
		if remotes, err := r.repo.Remotes(); err != nil || len(remotes) != 0 {
			t.Errorf("the repository has remotes %v (%v) after the push, want none", remotes, err)
		}
	})

	t.Run("fails for a branch or a remote that is not there", func(t *testing.T) {
		r := newTestRepo(t)
		at, forkURL := fork(t, r)
		if err := pushToAt(r.dir, forkURL, nil, "nonesuch", false); err == nil {
			t.Error("push of a branch that is not there gave no error")
		}
		if err := pushToAt(r.dir, filepath.Join(t.TempDir(), "nonesuch"), nil, "master", false); err == nil {
			t.Error("push to a repository that is not there gave no error")
		}
		if got := at("master"); !got.IsZero() {
			t.Errorf("master is on the remote, at %s", got)
		}
	})
}

// hideFromGoGit packs objects of a repository the way "git maintenance"
// packs loose objects: into a pack whose name starts with loose-. Git reads
// such a pack, go-git does not.
func hideFromGoGit(t *testing.T, dir string, revs ...string) {
	t.Helper()
	git := func(stdin string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if errors.Is(err, exec.ErrNotFound) {
			t.Skipf("git is needed to pack objects: %v", err)
		}
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	var ids []string
	for _, rev := range revs {
		ids = append(ids, git("", "rev-parse", "--verify", rev))
	}
	git(strings.Join(ids, "\n")+"\n", "pack-objects", "--quiet", filepath.Join(".git", "objects", "pack", "loose"))
	git("", "prune-packed")
	packs, err := filepath.Glob(filepath.Join(dir, ".git", "objects", "pack", "loose-*.pack"))
	if err != nil || len(packs) != 1 {
		t.Fatalf("got the packs %q (%v), want one whose name starts with loose-", packs, err)
	}
	// git still has all of the commit
	git("", "ls-tree", "-r", "HEAD")
	git("", "cat-file", "-e", ids[0])
}

func TestResetOfWhatGoGitCannotRead(t *testing.T) {
	// intact checks that the files, the index and the branch are those of
	// a new test repository.
	intact := func(t *testing.T, r *testRepo) {
		t.Helper()
		for name, want := range map[string]string{"a/kept": "kept\n", "a/changed": "before\n", "b/removed": "removed\n"} {
			got, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(name)))
			if err != nil || string(got) != want {
				t.Errorf("%s has %q (%v), want %q", name, got, err, want)
			}
		}
		status, err := exec.Command("git", "-C", r.dir, "status", "--porcelain").CombinedOutput()
		if err != nil || len(status) != 0 {
			t.Errorf("git status says %q (%v), want nothing", status, err)
		}
		repo, err := git.PlainOpen(r.dir)
		if err != nil {
			t.Fatal(err)
		}
		head, err := repo.Head()
		if err != nil || head.Name().Short() != "master" || head.Hash() != r.base {
			t.Errorf("HEAD is %v (%v), want master at %s", head, err, r.base)
		}
	}
	// branch makes a branch at the commit of the test repository, as an
	// earlier run of blip leaves one.
	branch := func(t *testing.T, r *testRepo, name plumbing.ReferenceName) {
		t.Helper()
		if err := r.repo.Storer.SetReference(plumbing.NewHashReference(name, r.base)); err != nil {
			t.Fatal(err)
		}
	}

	hidden := map[string][]string{
		"a directory":              {"HEAD:a"},
		"the first directory":      {"HEAD:a", "HEAD:a/kept", "HEAD:a/changed"},
		"the last directory":       {"HEAD:b"},
		"a file":                   {"HEAD:a/kept"},
		"a file in a directory":    {"HEAD:b", "HEAD:b/removed"},
		"all but commit and trees": {"HEAD:a/kept", "HEAD:a/changed", "HEAD:b/removed"},
	}
	for what, revs := range hidden {
		t.Run("checkoutNewBranch does not switch to a branch if go-git cannot read "+what+" of it", func(t *testing.T) {
			r := newTestRepo(t)
			branch(t, r, plumbing.NewBranchReferenceName("blip-alpine"))
			hideFromGoGit(t, r.dir, revs...)

			err := checkoutNewBranchAt(r.dir, "blip-alpine")

			if err == nil {
				t.Errorf("checkoutNewBranch gave no error")
			}
			intact(t, r)
		})

		t.Run("resetHardOriginMaster does not reset if go-git cannot read "+what+" of origin/master", func(t *testing.T) {
			r := newTestRepo(t)
			branch(t, r, plumbing.NewRemoteReferenceName("origin", "master"))
			hideFromGoGit(t, r.dir, revs...)

			err := resetHardOriginMasterAt(r.dir)

			if err == nil {
				t.Errorf("resetHardOriginMaster gave no error")
			}
			intact(t, r)
		})
	}

	t.Run("says which object it is and how to get it readable", func(t *testing.T) {
		r := newTestRepo(t)
		branch(t, r, plumbing.NewRemoteReferenceName("origin", "master"))
		hideFromGoGit(t, r.dir, "HEAD:b")
		tree, err := exec.Command("git", "-C", r.dir, "rev-parse", "HEAD:b").Output()
		if err != nil {
			t.Fatal(err)
		}

		err = resetHardOriginMasterAt(r.dir)

		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(string(tree))) || !strings.Contains(err.Error(), "git repack") {
			t.Errorf("got error %v, want one that names the object %s and git repack", err, strings.TrimSpace(string(tree)))
		}
	})

	t.Run("both go on with a repository that git has packed in the usual way", func(t *testing.T) {
		r := newTestRepo(t)
		branch(t, r, plumbing.NewBranchReferenceName("blip-alpine"))
		branch(t, r, plumbing.NewRemoteReferenceName("origin", "master"))
		if out, err := exec.Command("git", "-C", r.dir, "repack", "-a", "-d", "-q").CombinedOutput(); err != nil {
			t.Skipf("git is needed to pack a repository: %v\n%s", err, out)
		}
		if loose, _ := filepath.Glob(filepath.Join(r.dir, ".git", "objects", "[0-9a-f][0-9a-f]")); len(loose) != 0 {
			t.Fatalf("there are loose objects left: %q", loose)
		}

		if err := checkoutNewBranchAt(r.dir, "blip-alpine"); err != nil {
			t.Errorf("checkoutNewBranch: %v", err)
		}
		if err := resetHardOriginMasterAt(r.dir); err != nil {
			t.Errorf("resetHardOriginMaster: %v", err)
		}

		for name, want := range map[string]string{"a/kept": "kept\n", "a/changed": "before\n", "b/removed": "removed\n"} {
			got, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(name)))
			if err != nil || string(got) != want {
				t.Errorf("%s has %q (%v), want %q", name, got, err, want)
			}
		}
	})
}

// upstream is a repository for cloneShallow to clone: its branch has two
// commits, a branch "other" has a commit of its own, and the newest commit
// of the branch has two tags, a plain one and one with a message.
type upstream struct {
	*testRepo
	on                      string // the branch
	tip, onOther, annotated plumbing.Hash
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	up := &upstream{testRepo: newTestRepo(t)}
	up.on = up.branch()
	checkout := func(opts *git.CheckoutOptions) {
		t.Helper()
		repo, err := git.PlainOpen(up.dir)
		if err != nil {
			t.Fatal(err)
		}
		wt, err := repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if err := wt.Checkout(opts); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("other"), Create: true})
	up.write("a/kept", "on the other branch\n")
	if up.onOther, err = commitTrackedAt(up.dir, "other", false); err != nil {
		t.Fatal(err)
	}
	checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(up.on)})
	up.write("a/changed", "after\n")
	if up.tip, err = commitTrackedAt(up.dir, "more", false); err != nil {
		t.Fatal(err)
	}
	if _, err := up.repo.CreateTag("plain", up.tip, nil); err != nil {
		t.Fatal(err)
	}
	tag, err := up.repo.CreateTag("annotated", up.tip, &git.CreateTagOptions{
		Tagger:  &object.Signature{Name: "Bumper", Email: "bumper@example.com", When: time.Now()},
		Message: "annotated",
	})
	if err != nil {
		t.Fatal(err)
	}
	up.annotated = tag.Hash()
	return up
}

// allFilesIn returns the files below dir with their contents.
func allFilesIn(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		files[filepath.ToSlash(rel)] = string(content)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// filesIn returns the files below dir with their contents, those of .git
// left out.
func filesIn(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := allFilesIn(t, dir)
	maps.DeleteFunc(files, func(name, _ string) bool { return strings.HasPrefix(name, ".git/") })
	return files
}

func TestCloneShallow(t *testing.T) {
	if _, err := exec.LookPath("git-upload-pack"); err != nil {
		t.Skip("go-git reads a repository in a local directory with git-upload-pack")
	}
	notThere := func(err error) bool {
		return errors.Is(err, plumbing.ErrObjectNotFound) || errors.Is(err, plumbing.ErrReferenceNotFound)
	}

	transports := []struct {
		name string
		url  func(t *testing.T, origin *testRepo) string
	}{
		{"from a local directory", func(_ *testing.T, origin *testRepo) string { return origin.dir }},
		{"over http", serveHTTP},
	}
	for _, transport := range transports {
		t.Run(transport.name, func(t *testing.T) {
			// cloned returns an upstream and the directory that it was cloned into.
			cloned := func(t *testing.T) (*upstream, string) {
				t.Helper()
				up := newUpstream(t)
				dir := filepath.Join(t.TempDir(), "not", "there", "yet")
				if _, err := cloneShallow(transport.url(t, up.testRepo), up.on, dir); err != nil {
					t.Fatalf("cloneShallow: %v", err)
				}
				return up, dir
			}
			open := func(t *testing.T, dir string) *git.Repository {
				t.Helper()
				clone, err := git.PlainOpen(dir)
				if err != nil {
					t.Fatal(err)
				}
				return clone
			}

			t.Run("makes a checkout of the newest commit of the branch", func(t *testing.T) {
				up, dir := cloned(t)
				head, err := open(t, dir).Head()
				if err != nil {
					t.Fatal(err)
				}
				if head.Name() != plumbing.NewBranchReferenceName(up.on) || head.Hash() != up.tip {
					t.Errorf("HEAD is %s at %s, want %s at %s", head.Name(), head.Hash(), up.on, up.tip)
				}
				_, want := up.head()
				if got := filesIn(t, dir); !sameFiles(got, want) {
					t.Errorf("the files are %v, want %v", got, want)
				}
				if clean, err := worktreeCleanAt(dir); err != nil || !clean {
					t.Errorf("worktreeClean = %v, %v, want true", clean, err)
				}
			})

			t.Run("leaves the history behind", func(t *testing.T) {
				up, dir := cloned(t)
				clone := open(t, dir)
				if _, err := clone.CommitObject(up.base); !notThere(err) {
					t.Errorf("the commit before the newest one: %v, want it not to be there", err)
				}
				// what a push from this clone goes by
				shallow, err := clone.Storer.Shallow()
				if err != nil || !slices.Equal(shallow, []plumbing.Hash{up.tip}) {
					t.Errorf("the history is known to end at %v (%v), want at %s", shallow, err, up.tip)
				}
			})

			t.Run("leaves the other branches behind, in a later fetch too", func(t *testing.T) {
				up, dir := cloned(t)
				check := func(when string) {
					t.Helper()
					clone := open(t, dir)
					for _, name := range []plumbing.ReferenceName{
						plumbing.NewRemoteReferenceName("origin", "other"),
						plumbing.NewBranchReferenceName("other"),
					} {
						if _, err := clone.Reference(name, true); !notThere(err) {
							t.Errorf("%s: %s: %v, want it not to be there", when, name, err)
						}
					}
					if _, err := clone.CommitObject(up.onOther); !notThere(err) {
						t.Errorf("%s: the commit of the other branch: %v, want it not to be there", when, err)
					}
				}
				check("after the clone")
				if err := fetchOriginAt(dir); err != nil {
					t.Fatalf("fetchOrigin: %v", err)
				}
				check("after a fetch")
			})

			t.Run("leaves the tags behind", func(t *testing.T) {
				up, dir := cloned(t)
				clone := open(t, dir)
				tags, err := clone.Tags()
				if err != nil {
					t.Fatal(err)
				}
				var names []string
				err = tags.ForEach(func(tag *plumbing.Reference) error {
					names = append(names, tag.Name().Short())
					return nil
				})
				if err != nil || len(names) > 0 {
					t.Errorf("the tags are %v (%v), want none", names, err)
				}
				if _, err := clone.TagObject(up.annotated); !notThere(err) {
					t.Errorf("the tag with a message: %v, want it not to be there", err)
				}
			})

			t.Run("follows upstream with fetchOrigin and resetHardOriginMaster", func(t *testing.T) {
				up, dir := cloned(t)
				if up.on != "master" {
					t.Skipf("the test repository is on %s", up.on)
				}
				up.write("a/kept", "newer\n")
				newer, err := commitTrackedAt(up.dir, "newer", false)
				if err != nil {
					t.Fatal(err)
				}

				if err := fetchOriginAt(dir); err != nil {
					t.Fatalf("fetchOrigin: %v", err)
				}
				if err := resetHardOriginMasterAt(dir); err != nil {
					t.Fatalf("resetHardOriginMaster: %v", err)
				}

				if head, err := open(t, dir).Head(); err != nil || head.Hash() != newer {
					t.Errorf("HEAD is at %v (%v), want %s", head, err, newer)
				}
				_, want := up.head()
				if got := filesIn(t, dir); !sameFiles(got, want) {
					t.Errorf("the files are %v, want %v", got, want)
				}
				if clean, err := worktreeCleanAt(dir); err != nil || !clean {
					t.Errorf("worktreeClean = %v, %v, want true", clean, err)
				}
			})
		})
	}

	t.Run("takes the branch that it is given, not the one that upstream is on", func(t *testing.T) {
		up := newUpstream(t)
		dir := filepath.Join(t.TempDir(), "eve")
		if _, err := cloneShallow(up.dir, "other", dir); err != nil {
			t.Fatalf("cloneShallow: %v", err)
		}
		clone, err := git.PlainOpen(dir)
		if err != nil {
			t.Fatal(err)
		}
		head, err := clone.Head()
		if err != nil {
			t.Fatal(err)
		}
		if head.Name() != plumbing.NewBranchReferenceName("other") || head.Hash() != up.onOther {
			t.Errorf("HEAD is %s at %s, want other at %s", head.Name(), head.Hash(), up.onOther)
		}
		if got := filesIn(t, dir)["a/kept"]; got != "on the other branch\n" {
			t.Errorf("a/kept is %q, want that of the other branch", got)
		}
		if _, err := clone.CommitObject(up.tip); !notThere(err) {
			t.Errorf("the newest commit of the branch that upstream is on: %v, want it not to be there", err)
		}
	})

	t.Run("takes a directory that is there and empty", func(t *testing.T) {
		up := newUpstream(t)
		dir := t.TempDir()
		if _, err := cloneShallow(up.dir, up.on, dir); err != nil {
			t.Fatalf("cloneShallow: %v", err)
		}
		_, want := up.head()
		if got := filesIn(t, dir); !sameFiles(got, want) {
			t.Errorf("the files are %v, want %v", got, want)
		}
	})

	t.Run("refuses a directory that has something in it and leaves it as it is", func(t *testing.T) {
		for _, inTheWay := range []string{"mine", ".mine", "sub/mine", "a/kept"} {
			t.Run(inTheWay, func(t *testing.T) {
				up := newUpstream(t)
				dir := t.TempDir()
				(&testRepo{t: t, dir: dir}).write(inTheWay, "mine\n")

				if _, err := cloneShallow(up.dir, up.on, dir); err == nil {
					t.Error("cloneShallow gave no error")
				}

				want := map[string]string{inTheWay: "mine\n"}
				if got := allFilesIn(t, dir); !sameFiles(got, want) {
					t.Errorf("the directory has %v, want %v", slices.Sorted(maps.Keys(got)), want)
				}
			})
		}
	})

	t.Run("refuses a directory that is a checkout already and leaves it as it is", func(t *testing.T) {
		up := newUpstream(t)
		mine := newTestRepo(t)
		mine.write("a/changed", "not committed\n")
		want := allFilesIn(t, mine.dir)

		if _, err := cloneShallow(up.dir, up.on, mine.dir); err == nil {
			t.Error("cloneShallow gave no error")
		}

		if got := allFilesIn(t, mine.dir); !sameFiles(got, want) {
			t.Errorf("the checkout has %v, want %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
		}
	})

	t.Run("refuses a file and leaves it as it is", func(t *testing.T) {
		up := newUpstream(t)
		file := filepath.Join(t.TempDir(), "mine")
		if err := os.WriteFile(file, []byte("mine\n"), 0644); err != nil {
			t.Fatal(err)
		}

		if _, err := cloneShallow(up.dir, up.on, file); err == nil {
			t.Error("cloneShallow gave no error")
		}

		if got, err := os.ReadFile(file); err != nil || string(got) != "mine\n" {
			t.Errorf("the file has %q (%v), want it as it was", got, err)
		}
	})

	t.Run("returns the repository that it made", func(t *testing.T) {
		up := newUpstream(t)
		dir := filepath.Join(t.TempDir(), "eve")
		g, err := cloneShallow(up.dir, up.on, dir)
		if err != nil {
			t.Fatalf("cloneShallow: %v", err)
		}
		root, err := g.openRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if root.Name() != dir {
			t.Errorf("the repository is that of %s, want %s", root.Name(), dir)
		}
		if clean, err := g.worktreeClean(); err != nil || !clean {
			t.Errorf("worktreeClean = %v, %v, want true", clean, err)
		}
	})

	t.Run("fails and leaves nothing of a clone behind", func(t *testing.T) {
		up := newUpstream(t)
		nothing := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(nothing.Close)
		failing := []struct{ name, url, branch string }{
			{"where no repository is", nothing.URL + "/eve.git", up.on},
			{"for a branch that is not there", serveHTTP(t, up.testRepo), "nowhere"},
		}
		for _, f := range failing {
			t.Run(f.name, func(t *testing.T) {
				dirs := map[string]string{
					"in a directory that is not there": filepath.Join(t.TempDir(), "eve"),
					"in an empty directory":            t.TempDir(),
				}
				for name, dir := range dirs {
					t.Run(name, func(t *testing.T) {
						g, err := cloneShallow(f.url, f.branch, dir)

						if err == nil || g != nil {
							t.Fatalf("cloneShallow = %v, %v, want no repository and an error", g, err)
						}
						for _, what := range []string{f.url, f.branch, dir} {
							if !strings.Contains(err.Error(), what) {
								t.Errorf("the error %q does not name %s", err, what)
							}
						}
						// the directory itself may be there
						entries, err := os.ReadDir(dir)
						if !errors.Is(err, os.ErrNotExist) && (err != nil || len(entries) > 0) {
							t.Errorf("the directory has %v (%v), want nothing in it", entries, err)
						}
					})
				}
			})
		}
	})
}

func TestNewGitRepo(t *testing.T) {
	// rootOf returns the directory that openRoot opens for the repository.
	rootOf := func(t *testing.T, g *gitRepo) string {
		t.Helper()
		root, err := g.openRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		return root.Name()
	}

	t.Run("opens the repository that the directory is in", func(t *testing.T) {
		r := newTestRepo(t)
		for _, from := range []string{".", "a"} {
			g, err := newGitRepo(filepath.Join(r.dir, from))
			if err != nil {
				t.Fatalf("newGitRepo in %s: %v", from, err)
			}
			if got := rootOf(t, g); got != r.dir {
				t.Errorf("newGitRepo in %s: the repository is that of %s, want %s", from, got, r.dir)
			}
		}
	})

	t.Run("opens the repository of the current directory when it is given none", func(t *testing.T) {
		r := newTestRepo(t)
		t.Chdir(filepath.Join(r.dir, "a"))
		g, err := newGitRepo("")
		if err != nil {
			t.Fatalf("newGitRepo: %v", err)
		}
		if got := rootOf(t, g); got != r.dir {
			t.Errorf("the repository is that of %s, want %s", got, r.dir)
		}
	})

	t.Run("fails where no repository is, and says where", func(t *testing.T) {
		dir := t.TempDir()
		g, err := newGitRepo(dir)
		if err == nil || g != nil {
			t.Fatalf("newGitRepo = %v, %v, want no repository and an error", g, err)
		}
		if !strings.Contains(err.Error(), dir) {
			t.Errorf("the error %q does not name %s", err, dir)
		}
	})

	t.Run("stays with its directory when the current one changes", func(t *testing.T) {
		r := newTestRepo(t)
		r.write("a/untracked", "untracked\n")
		r.write("b/untracked", "untracked\n")
		elsewhere := newTestRepo(t)
		elsewhere.write("a/untracked", "untracked\n")
		t.Chdir(r.dir)
		g, err := newGitRepo("a")
		if err != nil {
			t.Fatalf("newGitRepo: %v", err)
		}

		t.Chdir(elsewhere.dir)
		if err := g.cleanWorktree(); err != nil {
			t.Fatalf("cleanWorktree: %v", err)
		}

		gone := func(dir, name string) bool {
			_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(name)))
			return errors.Is(err, os.ErrNotExist)
		}
		if !gone(r.dir, "a/untracked") {
			t.Error("a/untracked of the repository is still there")
		}
		if gone(r.dir, "b/untracked") {
			t.Error("b/untracked of the repository is gone, though the repository was opened in a")
		}
		if gone(elsewhere.dir, "a/untracked") {
			t.Error("a/untracked of the repository that became the current directory is gone")
		}
	})
}

// One gitRepo does all of a run, as blip has it: it has to see what it
// fetched and committed itself, though it opened the repository before.
func TestGitRepoThroughARun(t *testing.T) {
	gitCmd := func(t *testing.T, dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git is needed to serve a repository over http: %v", err)
	}
	up := newUpstream(t)
	if up.on != "master" {
		t.Skipf("the test repository is on %s", up.on)
	}
	// a fork as GitHub has them: behind upstream, and with upstream's objects
	// in reach
	forks := t.TempDir()
	forkDir := filepath.Join(forks, "fork.git")
	gitCmd(t, forks, "clone", "--quiet", "--bare", "--shared", up.dir, forkDir)
	gitCmd(t, forkDir, "config", "http.receivepack", "true")
	server := httptest.NewServer(&cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + forks, "GIT_HTTP_EXPORT_ALL=1"},
	})
	t.Cleanup(server.Close)
	forkURL := server.URL + "/fork.git"

	dir := filepath.Join(t.TempDir(), "eve")
	g, err := cloneShallow(serveHTTP(t, up.testRepo), up.on, dir)
	if err != nil {
		t.Fatalf("cloneShallow: %v", err)
	}
	cfg, err := g.repo.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.User.Name, cfg.User.Email = "Bumper", "bumper@example.com"
	if err := g.repo.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	clean := func(when string, want bool) {
		t.Helper()
		if got, err := g.worktreeClean(); err != nil || got != want {
			t.Errorf("worktreeClean %s = %v, %v, want %v", when, got, err, want)
		}
	}

	// upstream moves on after the clone
	up.write("a/kept", "newer\n")
	newer, err := commitTrackedAt(up.dir, "newer", false)
	if err != nil {
		t.Fatal(err)
	}

	if err := g.fetchOrigin(); err != nil {
		t.Fatalf("fetchOrigin: %v", err)
	}
	if err := g.checkoutNewBranch("blip-alpine"); err != nil {
		t.Fatalf("checkoutNewBranch: %v", err)
	}
	if err := g.resetHardOriginMaster(); err != nil {
		t.Fatalf("resetHardOriginMaster: %v", err)
	}
	_, want := up.head()
	if got := filesIn(t, dir); !sameFiles(got, want) {
		t.Errorf("after the reset the files are %v, want %v", got, want)
	}
	clean("after the reset", true)

	bumped := &testRepo{t: t, dir: dir}
	bumped.write("a/changed", "bumped\n")
	clean("with a changed file", false)
	first, err := g.commitTracked("bump", false)
	if err != nil {
		t.Fatalf("commitTracked: %v", err)
	}
	clean("after the commit", true)
	bumped.write("b/removed", "bumped as well\n")
	amended, err := g.commitTracked("", true)
	if err != nil {
		t.Fatalf("commitTracked to amend: %v", err)
	}
	clean("after the amended commit", true)
	if amended == first {
		t.Errorf("the amended commit is the first one, %s", first)
	}

	if err := g.pushTo(forkURL, nil, "blip-alpine", true); err != nil {
		t.Fatalf("pushTo: %v", err)
	}
	if got := gitCmd(t, forkDir, "rev-parse", "refs/heads/blip-alpine"); got != amended.String() {
		t.Errorf("the branch of the fork is at %s, want the amended commit %s", got, amended)
	}
	if got := gitCmd(t, forkDir, "rev-parse", "refs/heads/blip-alpine^"); got != newer.String() {
		t.Errorf("the commit of the fork is on top of %s, want upstream's newest commit %s", got, newer)
	}
	if got := gitCmd(t, forkDir, "rev-list", "--count", "refs/heads/blip-alpine"); got != "4" {
		t.Errorf("the branch of the fork has %s commits, want all 4", got)
	}
	if got := gitCmd(t, forkDir, "show", "refs/heads/blip-alpine:b/removed"); got != "bumped as well" {
		t.Errorf("b/removed is %q on the fork, want that of the amended commit", got)
	}
}
