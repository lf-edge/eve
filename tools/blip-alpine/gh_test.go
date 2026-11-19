// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/config"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// fakeGitHub answers every request with status and body and keeps what it
// was asked.
type fakeGitHub struct {
	status int
	body   string

	requests []*http.Request
	sent     map[string]any // the JSON of the last request
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r)
	raw, _ := io.ReadAll(r.Body)
	f.sent = nil
	_ = json.Unmarshal(raw, &f.sent)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, _ = io.WriteString(w, f.body)
}

// The tests ask one thing of a GitHub at a URL at a time.

func createPRAt(api, token string, pr pullRequest) (string, error) {
	g, err := newGitHubAt(api, token)
	if err != nil {
		return "", err
	}
	return g.createPR(pr)
}

func openPRAt(api, token, owner, repo, head string) (string, error) {
	g, err := newGitHubAt(api, token)
	if err != nil {
		return "", err
	}
	return g.openPR(owner, repo, head)
}

func closePRAt(api, token, url string) error {
	g, err := newGitHubAt(api, token)
	if err != nil {
		return err
	}
	return g.closePR(url)
}

func updatePRAt(api, token, url, body string) error {
	g, err := newGitHubAt(api, token)
	if err != nil {
		return err
	}
	return g.updatePR(url, body)
}

func currentUserAt(api, token string) (string, error) {
	g, err := newGitHubAt(api, token)
	if err != nil {
		return "", err
	}
	return g.currentUser()
}

func currentMailAt(api, token string) (string, error) {
	g, err := newGitHubAt(api, token)
	if err != nil {
		return "", err
	}
	return g.currentMail()
}

func TestCreatePR(t *testing.T) {
	pr := pullRequest{
		Owner: "lf-edge",
		Repo:  "eve",
		Head:  "christoph-zededa:blip-alpine",
		Base:  "master",
		Title: "Update all package hashes",
		Body:  "Bump after a change to pkg/alpine.\n",
	}

	t.Run("asks GitHub for the pull request and returns where it is", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusCreated, body: `{"number": 7, "html_url": "https://github.com/lf-edge/eve/pull/7"}`}
		server := httptest.NewServer(gh)
		defer server.Close()

		url, err := createPRAt(server.URL+"/", "s3cret", pr)
		if err != nil {
			t.Fatalf("createPRAt: %v", err)
		}

		if want := "https://github.com/lf-edge/eve/pull/7"; url != want {
			t.Errorf("got %q, want %q", url, want)
		}
		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		r := gh.requests[0]
		if r.Method != http.MethodPost || r.URL.Path != "/repos/lf-edge/eve/pulls" {
			t.Errorf("request %s %s, want POST /repos/lf-edge/eve/pulls", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization %q, want the token as a bearer", got)
		}
		want := map[string]any{
			"title": "Update all package hashes",
			"head":  "christoph-zededa:blip-alpine",
			"base":  "master",
			"body":  "Bump after a change to pkg/alpine.\n",
			"draft": false,
		}
		for key, value := range want {
			if gh.sent[key] != value {
				t.Errorf("sent %s = %v, want %v", key, gh.sent[key], value)
			}
		}
		if len(gh.sent) != len(want) {
			t.Errorf("sent %v, want only %v", gh.sent, want)
		}
	})

	t.Run("can ask for a draft", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusCreated, body: `{"html_url": "https://github.com/lf-edge/eve/pull/8"}`}
		server := httptest.NewServer(gh)
		defer server.Close()
		draft := pr
		draft.Draft = true

		if _, err := createPRAt(server.URL+"/", "s3cret", draft); err != nil {
			t.Fatalf("createPRAt: %v", err)
		}

		if gh.sent["draft"] != true {
			t.Errorf("sent draft = %v, want true", gh.sent["draft"])
		}
	})

	t.Run("passes on why GitHub refused", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusUnprocessableEntity, body: `{
			"message": "Validation Failed",
			"errors": [{"resource": "PullRequest", "code": "custom", "message": "A pull request already exists for christoph-zededa:blip-alpine."}]
		}`}
		server := httptest.NewServer(gh)
		defer server.Close()

		url, err := createPRAt(server.URL+"/", "s3cret", pr)

		if err == nil || !strings.Contains(err.Error(), "A pull request already exists") {
			t.Errorf("got %q and error %v, want the message of GitHub", url, err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("the error gives the token away: %v", err)
		}
	})

	t.Run("asks nothing without a token", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusCreated, body: `{}`}
		server := httptest.NewServer(gh)
		defer server.Close()

		if url, err := createPRAt(server.URL+"/", "", pr); err == nil {
			t.Errorf("createPRAt gave no error, but %q", url)
		}
		if len(gh.requests) != 0 {
			t.Errorf("%d requests, want none", len(gh.requests))
		}
	})
}

func TestOpenPR(t *testing.T) {
	const listed = `[
		{"number": 3, "state": "open", "html_url": "https://github.com/lf-edge/eve/pull/3",
		 "head": {"ref": "other-branch", "user": {"login": "christoph-zededa"}}},
		{"number": 7, "state": "open", "html_url": "https://github.com/lf-edge/eve/pull/7",
		 "head": {"ref": "blip-alpine", "user": {"login": "Christoph-Zededa"}}},
		{"number": 9, "state": "open", "html_url": "https://github.com/lf-edge/eve/pull/9",
		 "head": {"ref": "blip-alpine", "user": {"login": "someone-else"}}}
	]`
	serve := func(t *testing.T, status int, body string) (*fakeGitHub, string) {
		t.Helper()
		gh := &fakeGitHub{status: status, body: body}
		server := httptest.NewServer(gh)
		t.Cleanup(server.Close)
		return gh, server.URL + "/"
	}

	t.Run("asks for the open pull requests of the branch and returns where the one is", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, listed)

		url, err := openPRAt(api, "s3cret", "lf-edge", "eve", "christoph-zededa:blip-alpine")
		if err != nil {
			t.Fatalf("openPRAt: %v", err)
		}

		if want := "https://github.com/lf-edge/eve/pull/7"; url != want {
			t.Errorf("got %q, want %q", url, want)
		}
		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		r := gh.requests[0]
		if r.Method != http.MethodGet || r.URL.Path != "/repos/lf-edge/eve/pulls" {
			t.Errorf("request %s %s, want GET /repos/lf-edge/eve/pulls", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("state") != "open" || q.Get("head") != "christoph-zededa:blip-alpine" {
			t.Errorf("asked for state %q and head %q, want open and christoph-zededa:blip-alpine", q.Get("state"), q.Get("head"))
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization %q, want the token as a bearer", got)
		}
	})

	t.Run("takes a branch without a user for one of the repository itself", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, `[{"html_url": "https://github.com/lf-edge/eve/pull/11",
			"head": {"ref": "17.0-stable", "user": {"login": "lf-edge"}}}]`)

		url, err := openPRAt(api, "s3cret", "lf-edge", "eve", "17.0-stable")
		if err != nil {
			t.Fatalf("openPRAt: %v", err)
		}

		if want := "https://github.com/lf-edge/eve/pull/11"; url != want {
			t.Errorf("got %q, want %q", url, want)
		}
		if got := gh.requests[0].URL.Query().Get("head"); got != "lf-edge:17.0-stable" {
			t.Errorf("asked for head %q, want lf-edge:17.0-stable", got)
		}
	})

	t.Run("returns nothing when there is none", func(t *testing.T) {
		for _, body := range []string{`[]`, `[{"html_url": "https://github.com/lf-edge/eve/pull/3",
			"head": {"ref": "other-branch", "user": {"login": "christoph-zededa"}}}]`} {
			_, api := serve(t, http.StatusOK, body)

			url, err := openPRAt(api, "s3cret", "lf-edge", "eve", "christoph-zededa:blip-alpine")
			if err != nil || url != "" {
				t.Errorf("got %q and error %v for %s, want neither", url, err, body)
			}
		}
	})

	t.Run("fails when GitHub does", func(t *testing.T) {
		_, api := serve(t, http.StatusNotFound, `{"message": "Not Found"}`)

		if url, err := openPRAt(api, "s3cret", "lf-edge", "nonesuch", "christoph-zededa:blip-alpine"); err == nil {
			t.Errorf("openPRAt gave no error, but %q", url)
		}
	})
}

func TestClosePR(t *testing.T) {
	const closed = `{"number": 7, "state": "closed", "html_url": "https://github.com/lf-edge/eve/pull/7"}`
	serve := func(t *testing.T, status int, body string) (*fakeGitHub, string) {
		t.Helper()
		gh := &fakeGitHub{status: status, body: body}
		server := httptest.NewServer(gh)
		t.Cleanup(server.Close)
		return gh, server.URL + "/"
	}

	t.Run("asks GitHub to close the pull request, and to change nothing else of it", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, closed)

		if err := closePRAt(api, "s3cret", "https://github.com/lf-edge/eve/pull/7"); err != nil {
			t.Fatalf("closePRAt: %v", err)
		}

		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		r := gh.requests[0]
		if r.Method != http.MethodPatch || r.URL.Path != "/repos/lf-edge/eve/pulls/7" {
			t.Errorf("request %s %s, want PATCH /repos/lf-edge/eve/pulls/7", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization %q, want the token as a bearer", got)
		}
		if gh.sent["state"] != "closed" || len(gh.sent) != 1 {
			t.Errorf("sent %v, want only the state closed", gh.sent)
		}
	})

	t.Run("takes the repository and the number from the URL", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, `{"number": 6837, "state": "closed"}`)

		if err := closePRAt(api, "s3cret", "https://github.com/eve-bot/eve-fork/pull/6837"); err != nil {
			t.Fatalf("closePRAt: %v", err)
		}

		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		if r := gh.requests[0]; r.Method != http.MethodPatch || r.URL.Path != "/repos/eve-bot/eve-fork/pulls/6837" {
			t.Errorf("request %s %s, want PATCH /repos/eve-bot/eve-fork/pulls/6837", r.Method, r.URL.Path)
		}
	})

	t.Run("passes on why GitHub refused", func(t *testing.T) {
		_, api := serve(t, http.StatusForbidden, `{"message": "Resource not accessible by personal access token"}`)

		err := closePRAt(api, "s3cret", "https://github.com/lf-edge/eve/pull/7")

		if err == nil || !strings.Contains(err.Error(), "Resource not accessible") || !strings.Contains(err.Error(), "https://github.com/lf-edge/eve/pull/7") {
			t.Errorf("got error %v, want the message of GitHub and the pull request", err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("the error gives the token away: %v", err)
		}
	})

	t.Run("fails if GitHub answers with a pull request that is still open", func(t *testing.T) {
		_, api := serve(t, http.StatusOK, `{"number": 7, "state": "open", "html_url": "https://github.com/lf-edge/eve/pull/7"}`)

		if err := closePRAt(api, "s3cret", "https://github.com/lf-edge/eve/pull/7"); err == nil {
			t.Errorf("closePRAt gave no error")
		}
	})

	for what, url := range map[string]string{
		"no URL":                                     "",
		"a repository":                               "https://github.com/lf-edge/eve",
		"the pull requests of a repository":          "https://github.com/lf-edge/eve/pulls",
		"a pull request without a number":            "https://github.com/lf-edge/eve/pull/",
		"a pull request with a word for its number":  "https://github.com/lf-edge/eve/pull/seven",
		"the pull request zero":                      "https://github.com/lf-edge/eve/pull/0",
		"a number below zero":                        "https://github.com/lf-edge/eve/pull/-7",
		"a number with a sign":                       "https://github.com/lf-edge/eve/pull/+7",
		"an issue":                                   "https://github.com/lf-edge/eve/issues/7",
		"a page of a pull request":                   "https://github.com/lf-edge/eve/pull/7/files",
		"a pull request with a question":             "https://github.com/lf-edge/eve/pull/7?diff=split",
		"a pull request of a repository of nobody":   "https://github.com//eve/pull/7",
		"a pull request of nothing":                  "https://github.com/lf-edge//pull/7",
		"a pull request somewhere else":              "https://gitlab.com/lf-edge/eve/pull/7",
		"a site whose name starts like that of ours": "https://github.com.example.org/lf-edge/eve/pull/7",
		"what is no URL":                             "lf-edge/eve/pull/7",
	} {
		t.Run("asks nothing of GitHub for "+what, func(t *testing.T) {
			gh, api := serve(t, http.StatusOK, closed)

			if err := closePRAt(api, "s3cret", url); err == nil {
				t.Errorf("closePRAt gave no error for %q", url)
			}
			if len(gh.requests) != 0 {
				t.Errorf("%d requests, want none", len(gh.requests))
			}
		})
	}

	t.Run("asks nothing without a token", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, closed)

		if err := closePRAt(api, "", "https://github.com/lf-edge/eve/pull/7"); err == nil {
			t.Errorf("closePRAt gave no error")
		}
		if len(gh.requests) != 0 {
			t.Errorf("%d requests, want none", len(gh.requests))
		}
	})
}

func TestUpdatePR(t *testing.T) {
	const updated = `{"number": 7, "state": "open", "html_url": "https://github.com/lf-edge/eve/pull/7"}`
	serve := func(t *testing.T, status int, body string) (*fakeGitHub, string) {
		t.Helper()
		gh := &fakeGitHub{status: status, body: body}
		server := httptest.NewServer(gh)
		t.Cleanup(server.Close)
		return gh, server.URL + "/"
	}

	t.Run("asks GitHub to give the pull request the description, and to change nothing else of it", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, updated)

		err := updatePRAt(api, "s3cret", "https://github.com/lf-edge/eve/pull/7", "# Description\n\n- zstd\n")
		if err != nil {
			t.Fatalf("updatePRAt: %v", err)
		}

		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		r := gh.requests[0]
		if r.Method != http.MethodPatch || r.URL.Path != "/repos/lf-edge/eve/pulls/7" {
			t.Errorf("request %s %s, want PATCH /repos/lf-edge/eve/pulls/7", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization %q, want the token as a bearer", got)
		}
		if gh.sent["body"] != "# Description\n\n- zstd\n" || len(gh.sent) != 1 {
			t.Errorf("sent %v, want only the description", gh.sent)
		}
	})

	t.Run("takes the repository and the number from the URL", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, `{"number": 6837, "state": "open"}`)

		if err := updatePRAt(api, "s3cret", "https://github.com/eve-bot/eve-fork/pull/6837", "Bump."); err != nil {
			t.Fatalf("updatePRAt: %v", err)
		}

		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		if r := gh.requests[0]; r.Method != http.MethodPatch || r.URL.Path != "/repos/eve-bot/eve-fork/pulls/6837" {
			t.Errorf("request %s %s, want PATCH /repos/eve-bot/eve-fork/pulls/6837", r.Method, r.URL.Path)
		}
	})

	t.Run("sends a description that is empty too", func(t *testing.T) {
		gh, api := serve(t, http.StatusOK, updated)

		if err := updatePRAt(api, "s3cret", "https://github.com/lf-edge/eve/pull/7", ""); err != nil {
			t.Fatalf("updatePRAt: %v", err)
		}

		if body, sent := gh.sent["body"]; !sent || body != "" || len(gh.sent) != 1 {
			t.Errorf("sent %v, want only an empty description", gh.sent)
		}
	})

	t.Run("passes on why GitHub refused", func(t *testing.T) {
		_, api := serve(t, http.StatusForbidden, `{"message": "Resource not accessible by personal access token"}`)

		err := updatePRAt(api, "s3cret", "https://github.com/lf-edge/eve/pull/7", "Bump.")

		if err == nil || !strings.Contains(err.Error(), "Resource not accessible") || !strings.Contains(err.Error(), "https://github.com/lf-edge/eve/pull/7") {
			t.Errorf("got error %v, want the message of GitHub and the pull request", err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("the error gives the token away: %v", err)
		}
	})

	for what, url := range map[string]string{
		"no URL":                        "",
		"an issue":                      "https://github.com/lf-edge/eve/issues/7",
		"a page of a pull request":      "https://github.com/lf-edge/eve/pull/7/files",
		"a pull request somewhere else": "https://gitlab.com/lf-edge/eve/pull/7",
	} {
		t.Run("asks nothing of GitHub for "+what, func(t *testing.T) {
			gh, api := serve(t, http.StatusOK, updated)

			if err := updatePRAt(api, "s3cret", url, "Bump."); err == nil {
				t.Errorf("updatePRAt gave no error for %q", url)
			}
			if len(gh.requests) != 0 {
				t.Errorf("%d requests, want none", len(gh.requests))
			}
		})
	}
}

func TestCurrentUser(t *testing.T) {
	t.Run("asks GitHub whose token it is", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusOK, body: `{"login": "christoph-zededa", "id": 42, "name": "Somebody"}`}
		server := httptest.NewServer(gh)
		defer server.Close()

		user, err := currentUserAt(server.URL+"/", "s3cret")
		if err != nil {
			t.Fatalf("currentUserAt: %v", err)
		}

		if user != "christoph-zededa" {
			t.Errorf("got %q, want christoph-zededa", user)
		}
		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		r := gh.requests[0]
		if r.Method != http.MethodGet || r.URL.Path != "/user" {
			t.Errorf("request %s %s, want GET /user", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization %q, want the token as a bearer", got)
		}
	})

	t.Run("fails when GitHub does not know the token", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusUnauthorized, body: `{"message": "Bad credentials"}`}
		server := httptest.NewServer(gh)
		defer server.Close()

		if user, err := currentUserAt(server.URL+"/", "s3cret"); err == nil {
			t.Errorf("currentUserAt gave no error, but %q", user)
		}
	})

	t.Run("fails when the answer names nobody", func(t *testing.T) {
		gh := &fakeGitHub{status: http.StatusOK, body: `{}`}
		server := httptest.NewServer(gh)
		defer server.Close()

		if user, err := currentUserAt(server.URL+"/", "s3cret"); err == nil {
			t.Errorf("currentUserAt gave no error, but %q", user)
		}
	})
}

func TestGitHubPush(t *testing.T) {
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git is needed to serve a repository over http: %v", err)
	}
	// the repository someone/eve of a git server that wants the token s3cret
	root := t.TempDir()
	forkDir := filepath.Join(root, "someone", "eve.git")
	if _, err := git.PlainInit(forkDir, true); err != nil {
		t.Fatal(err)
	}
	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=tester"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, password, ok := req.BasicAuth(); !ok || password != "s3cret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, req)
	}))
	defer server.Close()
	at := func(branch string) plumbing.Hash {
		t.Helper()
		fork, err := git.PlainOpen(forkDir)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := fork.Reference(plumbing.NewBranchReferenceName(branch), true)
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return plumbing.ZeroHash
		}
		if err != nil {
			t.Fatal(err)
		}
		return ref.Hash()
	}
	// push runs gitHub.push with the token in the repository r.
	push := func(t *testing.T, r *testRepo, token, owner string, force bool) error {
		t.Helper()
		g, err := newGitHubAt(server.URL+"/", token)
		if err != nil {
			t.Fatal(err)
		}
		g.gitURL = server.URL
		return inErr(r.dir, func(from *gitRepo) error { return g.push(from, owner, "eve", "master", force) })
	}

	r := newTestRepo(t)
	if err := push(t, r, "wrong", "someone", false); err == nil {
		t.Error("push with a wrong token gave no error")
	}
	if err := push(t, r, "s3cret", "someone-else", false); err == nil {
		t.Error("push to the repository of another owner, which is not there, gave no error")
	}
	if got := at("master"); !got.IsZero() {
		t.Fatalf("master is on the remote already, at %s", got)
	}

	if err := push(t, r, "s3cret", "someone", false); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := at("master"); got != r.base {
		t.Errorf("master is at %s on the remote, want %s", got, r.base)
	}

	r.write("a/changed", "amended\n")
	amended, err := commitTrackedAt(r.dir, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := push(t, r, "s3cret", "someone", false); err == nil {
		t.Error("push of an amended commit without force gave no error")
	}
	if err := push(t, r, "s3cret", "someone", true); err != nil {
		t.Fatalf("push with force: %v", err)
	}
	if got := at("master"); got != amended {
		t.Errorf("master is at %s on the remote, want %s", got, amended)
	}
}

func TestGitHubRepoURL(t *testing.T) {
	g, err := newGitHubAt("", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := g.repoURL("christoph-zededa-bot", "eve"), "https://github.com/christoph-zededa-bot/eve.git"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCurrentMail(t *testing.T) {
	ask := func(t *testing.T, status int, body string) (*fakeGitHub, string, error) {
		t.Helper()
		gh := &fakeGitHub{status: status, body: body}
		server := httptest.NewServer(gh)
		t.Cleanup(server.Close)
		mail, err := currentMailAt(server.URL+"/", "s3cret")
		return gh, mail, err
	}

	t.Run("asks GitHub for the addresses of the user and returns the primary one", func(t *testing.T) {
		gh, mail, err := ask(t, http.StatusOK, `[
			{"email": "old@example.com", "primary": false, "verified": true, "visibility": null},
			{"email": "bot@example.com", "primary": true, "verified": true, "visibility": "private"},
			{"email": "1+bot@users.noreply.github.com", "primary": false, "verified": true, "visibility": null}
		]`)
		if err != nil {
			t.Fatalf("currentMail: %v", err)
		}

		if mail != "bot@example.com" {
			t.Errorf("got %q, want bot@example.com", mail)
		}
		if len(gh.requests) != 1 {
			t.Fatalf("%d requests, want 1", len(gh.requests))
		}
		r := gh.requests[0]
		if r.Method != http.MethodGet || r.URL.Path != "/user/emails" {
			t.Errorf("request %s %s, want GET /user/emails", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization %q, want the token as a bearer", got)
		}
	})

	t.Run("fails when there is no primary address that is verified", func(t *testing.T) {
		for _, body := range []string{
			`[]`,
			`[{"email": "other@example.com", "primary": false, "verified": true}]`,
			`[{"email": "new@example.com", "primary": true, "verified": false}]`,
		} {
			if _, mail, err := ask(t, http.StatusOK, body); err == nil {
				t.Errorf("for %s: currentMail gave no error, but %q", body, mail)
			}
		}
	})

	t.Run("says which scope the token lacks when GitHub hides the addresses", func(t *testing.T) {
		_, mail, err := ask(t, http.StatusNotFound, `{"message": "Not Found"}`)
		if err == nil || !strings.Contains(err.Error(), "user:email") {
			t.Errorf("got %q and error %v, want an error that names the scope user:email", mail, err)
		}
	})
}

func TestGitHubToken(t *testing.T) {
	// alone keeps the test away from the login of whoever runs it: a home
	// directory of its own, no token in the environment, no gh to ask, and a
	// configuration of gh that has nothing but the hosts.yml given.
	alone := func(t *testing.T, hosts string) {
		t.Helper()
		t.Setenv("HOME", t.TempDir())
		configDir := t.TempDir()
		for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GH_PATH"} {
			t.Setenv(name, "")
		}
		t.Setenv("GH_CONFIG_DIR", configDir)
		t.Setenv("PATH", t.TempDir())
		if hosts != "" {
			if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte(hosts), 0600); err != nil {
				t.Fatal(err)
			}
		}
		// the library reads the configuration once and keeps it
		if err := config.Reload(nil); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("takes the token of the environment", func(t *testing.T) {
		alone(t, "github.com:\n    oauth_token: from-the-file\n")
		t.Setenv("GH_TOKEN", "from-the-environment")

		got, err := githubToken()
		if err != nil || got != "from-the-environment" {
			t.Errorf("got a token of %d characters and error %v, want the one of GH_TOKEN", len(got), err)
		}
	})

	t.Run("takes the token that gh keeps in its hosts.yml", func(t *testing.T) {
		alone(t, "github.com:\n    user: someone\n    oauth_token: from-the-file\n    git_protocol: ssh\n")

		got, err := githubToken()
		if err != nil || got != "from-the-file" {
			t.Errorf("got a token of %d characters and error %v, want the one of hosts.yml", len(got), err)
		}
	})

	t.Run("fails when there is no login", func(t *testing.T) {
		alone(t, "")

		if got, err := githubToken(); err == nil {
			t.Errorf("githubToken gave no error, but a token of %d characters", len(got))
		}
	})

	// own writes ~/.config/blip-alpine.json of the home directory of the test.
	own := func(t *testing.T, content string) {
		t.Helper()
		dir := filepath.Join(os.Getenv("HOME"), ".config")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "blip-alpine.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("takes the token of ~/.config/blip-alpine.json before any other", func(t *testing.T) {
		alone(t, "github.com:\n    oauth_token: from-the-file\n")
		t.Setenv("GH_TOKEN", "from-the-environment")
		own(t, `{"token": "from-blip-alpine"}`)

		got, err := githubToken()
		if err != nil || got != "from-blip-alpine" {
			t.Errorf("got a token of %d characters and error %v, want the one of blip-alpine.json", len(got), err)
		}
	})

	t.Run("goes on to the login of gh when blip-alpine.json has no token", func(t *testing.T) {
		for _, content := range []string{`{}`, `{"token": ""}`, `{"other": "setting"}`} {
			alone(t, "github.com:\n    oauth_token: from-the-file\n")
			own(t, content)

			got, err := githubToken()
			if err != nil || got != "from-the-file" {
				t.Errorf("with %s: got a token of %d characters and error %v, want the one of hosts.yml", content, len(got), err)
			}
		}
	})

	t.Run("fails for a blip-alpine.json that it cannot make sense of", func(t *testing.T) {
		alone(t, "github.com:\n    oauth_token: from-the-file\n")
		own(t, `{"token": "cut off`)

		got, err := githubToken()
		if err == nil || !strings.Contains(err.Error(), "blip-alpine.json") {
			t.Errorf("got a token of %d characters and error %v, want an error that names the file", len(got), err)
		}
	})
}
