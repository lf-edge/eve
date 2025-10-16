// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
)

type gitTmp struct {
	dir string

	currentDir string

	rev    uint64
	branch uint64
}

func createTmpGitDir() gitTmp {
	var err error
	var g gitTmp

	g.currentDir, err = os.Getwd()
	if err != nil {
		panic(err)
	}

	g.dir, err = os.MkdirTemp("", "gce-tempdir")

	cmd := exec.Command("git", "init", g.dir)
	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	os.Chdir(g.dir)

	return g
}

func (g *gitTmp) cleanup() {
	os.Chdir(g.currentDir)

	os.RemoveAll(g.dir)
}

func sanitizeFilename(name string) string {
	return url.QueryEscape(name)
}

func (g *gitTmp) writeFile(filename string, content string) {
	os.WriteFile(filename, []byte(content), 0600)
}

func (g *gitTmp) addFile(filename string) {
	cmd := exec.Command("git", "add", filename)
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
}

func (g *gitTmp) commit() uint64 {
	commitMessage := fmt.Sprintf("commit-%d", g.rev)
	g.rev++
	cmd := exec.Command("git", "commit", "-m", commitMessage)
	err := cmd.Run()
	if err != nil {
		panic(err)
	}

	return g.rev - 1
}

func (g *gitTmp) newBranch() uint64 {
	branchName := fmt.Sprintf("branch_%d", g.branch)
	g.branch++

	cmd := exec.Command("git", "checkout", "-b", branchName)
	err := cmd.Run()
	if err != nil {
		panic(err)
	}

	return g.branch - 1
}

type testAction struct {
	matchPathImpl func(path string) bool
	matchDiffImpl func(path string, ld LineDiff) bool
	doImpl        func() error
	t             *testing.T
}

func (ta *testAction) matchPath(path string) bool {
	if ta.t != nil {
		ta.t.Logf("matchPath %s", path)
	}

	if ta.matchPathImpl != nil {
		return ta.matchPathImpl(path)
	}
	return false
}
func (ta *testAction) matchDiff(path string, ld LineDiff) bool {
	if ta.t != nil {
		ta.t.Logf("matchPathDiff %s -> %+v | %+v", path, ld, ld.TypeOfLine)
	}

	if ta.matchDiffImpl != nil {
		return ta.matchDiffImpl(path, ld)
	}
	return false
}

func (ta *testAction) Do([]ActionToDo) error {
	return ta.doImpl()
}

func (ta *testAction) Close() {
}

func runGCE(t *testing.T, ta *testAction) GitChangeExec {
	var err error
	gce := NewGitChangeExec()
	gce.G, err = git.PlainOpenWithOptions("./", &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		t.Fatalf("open git path %s failed: %v", gce.GitPath, err)
	}
	gce.ActionsToCheck = append(gce.ActionsToCheck, ta)

	gce.CalculateBaseCommit()

	gce.CollectActionsGitTree()
	gce.CollectDirtyGitTree()

	gce.Diff()
	return gce
}

func TestPR(t *testing.T) {
	g := createTmpGitDir()
	defer g.cleanup()

	g.writeFile("foo", "foo")
	g.addFile("foo")

	g.commit()

	g.writeFile("baz", "")
	g.addFile("baz")

	g.commit()

	g.newBranch()
	g.writeFile("bar", "bar")
	g.addFile("bar")

	g.commit()

	g.writeFile("foo", "foo\nbar")

	ta := &testAction{
		matchPathImpl: func(path string) bool {
			if path != "foo" && path != "bar" {
				t.Fatalf("unexpected path %s", path)
			}
			return true
		},
		matchDiffImpl: func(path string, ld LineDiff) bool {
			if ld.IsComment() != Undecided {
				t.Fatalf("only undecided lines expected, got %+v", ld.TypeOfLine)
			}
			return true
		},
		doImpl: func() error {
			return nil
		},
	}

	gce := runGCE(t, ta)

	commitMessage := strings.TrimSpace(gce.baseCommit.Message)
	if commitMessage != "commit-1" {
		t.Fatalf("unexpected commit message '%s'", commitMessage)
	}
}

func TestPRGo(t *testing.T) {
	g := createTmpGitDir()
	defer g.cleanup()

	g.writeFile("main.go", `
			package main

			func main() {
				fmt.Println("hello world")
			}

		`)
	g.addFile("main.go")

	g.commit()

	g.newBranch()

	g.writeFile("main.go", `
			package main

			import "fmt"

			// this is the main func
			func main() {
				fmt.Println("hello world")
			}
		`)
	g.addFile("main.go")

	g.commit()

	ta := &testAction{
		matchPathImpl: func(path string) bool {
			if path != "main.go" {
				t.Fatalf("wrong file %s", path)
			}
			return true
		},
		matchDiffImpl: func(path string, ld LineDiff) bool {
			if path != "main.go" {
				t.Fatalf("wrong file %s", path)
			}

			if ld.Operation == LineDel && (ld.LineNumber != 6 || ld.Line != "") {
				t.Fatalf("wrong lineDiff: %+v", ld)
			} else if ld.LineNumber == 2 && (ld.Line != "" || ld.IsComment() != NotComment) {
				t.Fatalf("wrong lineDiff: %+v // %+v", ld, ld.TypeOfLine)
			} else if ld.LineNumber == 3 && (!strings.Contains(ld.Line, "import \"fmt\"") || ld.IsComment() == IsComment) {
				t.Fatalf("wrong lineDiff: %+v", ld)
			} else if ld.LineNumber == 5 && (!strings.Contains(ld.Line, "// this is the main func") || ld.IsComment() == NotComment) {
				t.Fatalf("wrong lineDiff: %+v", ld)
			}

			return true
		},
		doImpl: func() error {
			return nil
		},
		t: t,
	}
	runGCE(t, ta)

}
func TestPRGoMultilineComment(t *testing.T) {
	g := createTmpGitDir()
	defer g.cleanup()

	g.writeFile("main.go", `
			package main

			import "fmt"

			func main() {
				fmt.Println("hello world")
			}
		`)
	g.addFile("main.go")

	g.commit()

	g.newBranch()

	g.writeFile("main.go", `
			package main

			import "fmt"

			/* first line of the comment
			 * line 2 of the comment
			 * line 3 of the comment
			 */
			func main() {
				fmt.Println("hello world") // EOL comment

				fmt.Println(/* first arg */ "arg test")
			}
		`)
	g.addFile("main.go")

	g.commit()

	ta := &testAction{
		matchPathImpl: func(path string) bool {
			if path != "main.go" {
				t.Fatalf("wrong file %s", path)
			}
			return true
		},
		matchDiffImpl: func(path string, ld LineDiff) bool {
			if path != "main.go" {
				t.Fatalf("wrong file %s", path)
			}

			if ld.Operation == LineAdd && ld.LineNumber >= 5 && ld.LineNumber <= 8 {
				if ld.IsComment() != IsComment {
					t.Fatalf("wrong lineDiff: %+v // %+v", ld, ld.TypeOfLine)
				}
			} else if ld.Operation == LineDel && ld.Line != "" && ld.IsComment() != NotComment {
				t.Fatalf("wrong lineDiff: %+v // %+v | %+v", ld, ld.TypeOfLine, ld.IsComment())
			}
			return true
		},
	}
	runGCE(t, ta)
}
