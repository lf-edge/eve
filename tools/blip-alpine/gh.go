// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/auth"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v93/github"
)

// pullRequest is a pull request to open on GitHub.
type pullRequest struct {
	// Owner and Repo name the repository that it is for: lf-edge and eve.
	Owner, Repo string
	// Head is the branch with the commits, which has to be on GitHub
	// already; user:branch if it is in the fork of a user.
	Head string
	// Base is the branch that the commits are to go into.
	Base        string
	Title, Body string
	Draft       bool
}

// gitHub is GitHub in the hands of one user: its API, and its repositories
// for git.
type gitHub struct {
	client *github.Client
	// token is what the user logs in with, and gitURL where git reaches
	// the repositories: https://github.com.
	token, gitURL string
}

// newGitHub returns the API of github.com for the user of the GitHub
// token, see githubToken.
func newGitHub() (*gitHub, error) {
	token, err := githubToken()
	if err != nil {
		return nil, err
	}
	return newGitHubAt("", token)
}

// newGitHubAt returns the GitHub API at the URL api, or that of github.com
// for "", for the user that the token is of.
func newGitHubAt(api, token string) (*gitHub, error) {
	if token == "" {
		return nil, errors.New("no GitHub token")
	}
	opts := []github.ClientOptionsFunc{
		github.WithAuthToken(token),
		github.WithEnvProxy(),
		github.WithTimeout(time.Minute),
	}
	if api != "" {
		opts = append(opts, github.WithURLs(&api, nil))
	}
	client, err := github.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &gitHub{client: client, token: token, gitURL: "https://github.com"}, nil
}

// push does what "git push https://github.com/owner/repo.git branch" does in
// the repository from: it gives that repository on GitHub the commits of
// the branch and puts its branch of that name on them. If GitHub would lose
// commits by that, it fails, or with force does it all the same, as "git
// push --force" does.
//
// It needs no remote and no ssh key: it goes over https as the user of the
// token, who has to be allowed to write to the repository.
func (g *gitHub) push(from *gitRepo, owner, repo, branch string, force bool) error {
	// the token is the password, and GitHub does not care for the name
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: g.token}
	return from.pushTo(g.repoURL(owner, repo), auth, branch, force)
}

// repoURL returns where git reaches the repository owner/repo over https.
func (g *gitHub) repoURL(owner, repo string) string {
	return g.gitURL + "/" + owner + "/" + repo + ".git"
}

// createPR opens a pull request and returns its URL.
func (g *gitHub) createPR(pr pullRequest) (string, error) {
	created, _, err := g.client.PullRequests.Create(context.Background(), pr.Owner, pr.Repo, github.CreatePullRequest{
		Title: &pr.Title,
		Head:  pr.Head,
		Base:  pr.Base,
		Body:  &pr.Body,
		Draft: &pr.Draft,
	})
	if err != nil {
		return "", fmt.Errorf("opening a pull request for %s/%s from %s: %w", pr.Owner, pr.Repo, pr.Head, err)
	}
	return created.GetHTMLURL(), nil
}

// githubToken returns the token for github.com. It takes the "token" of
// ~/.config/blip-alpine.json if that file has one. Else it takes it from
// where the gh command has it: the environment variable GH_TOKEN or
// GITHUB_TOKEN, else what "gh auth login" left in hosts.yml of gh's
// configuration, else the keyring of the system, which the gh command is
// asked for.
func githubToken() (string, error) {
	token, err := ownToken()
	if err != nil {
		return "", err
	}
	if token == "" {
		token, _ = auth.TokenForHost("github.com")
	}
	if token == "" {
		return "", errors.New("no GitHub token: put one into ~/.config/blip-alpine.json, log in with \"gh auth login\" or set GH_TOKEN")
	}
	return token, nil
}

// ownToken returns the token of ~/.config/blip-alpine.json, or "" if there
// is no such file or no token in it.
func ownToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	file := filepath.Join(home, ".config", "blip-alpine.json")
	content, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var settings struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(content, &settings); err != nil {
		return "", fmt.Errorf("%s: %w", file, err)
	}
	return settings.Token, nil
}

// openPR tells whether the repository owner/repo has an open pull request
// from the branch head, which is user:branch for a branch in the fork of a
// user, as in a pullRequest. It returns the URL of the pull request, or ""
// if there is none.
func (g *gitHub) openPR(owner, repo, head string) (string, error) {
	user, branch, found := strings.Cut(head, ":")
	if !found {
		user, branch = owner, head
	}
	prs, _, err := g.client.PullRequests.List(context.Background(), owner, repo, &github.PullRequestListOptions{
		State: "open",
		Head:  user + ":" + branch,
	})
	if err != nil {
		return "", fmt.Errorf("looking for a pull request for %s/%s from %s: %w", owner, repo, head, err)
	}
	for _, pr := range prs {
		// GitHub lists every open pull request when it cannot make sense
		// of the head that it is asked for
		if pr.GetHead().GetRef() == branch && strings.EqualFold(pr.GetHead().GetUser().GetLogin(), user) {
			return pr.GetHTMLURL(), nil
		}
	}
	return "", nil
}

// prAt takes the URL of a pull request apart, which createPR and openPR
// return: https://github.com/owner/repo/pull/number.
func (g *gitHub) prAt(url string) (owner, repo string, number int, err error) {
	notOne := fmt.Errorf("%q is not the URL of a pull request on %s", url, g.gitURL)
	path, isHere := strings.CutPrefix(url, g.gitURL+"/")
	// owner, repo, "pull" and the number
	parts := strings.Split(path, "/")
	if !isHere || len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] != "pull" {
		return "", "", 0, notOne
	}
	// a number as GitHub writes it, which leaves out +7 and 007
	number, err = strconv.Atoi(parts[3])
	if err != nil || number <= 0 || strconv.Itoa(number) != parts[3] {
		return "", "", 0, notOne
	}
	return parts[0], parts[1], number, nil
}

// closePR closes a pull request without merging it. url is where the pull
// request is, as createPR and openPR return it. A pull request that is
// closed already stays that.
func (g *gitHub) closePR(url string) error {
	owner, repo, number, err := g.prAt(url)
	if err != nil {
		return err
	}
	closed := "closed"
	pr, _, err := g.client.PullRequests.Edit(context.Background(), owner, repo, number, &github.PullRequest{State: &closed})
	if err != nil {
		return fmt.Errorf("closing the pull request %s: %w", url, err)
	}
	if pr.GetState() != "closed" {
		return fmt.Errorf("closing the pull request %s: GitHub says that it is %q", url, pr.GetState())
	}
	return nil
}

// updatePR gives a pull request another description, and leaves all else
// of it as it is. url is where the pull request is, as createPR and openPR
// return it.
func (g *gitHub) updatePR(url, body string) error {
	owner, repo, number, err := g.prAt(url)
	if err != nil {
		return err
	}
	_, _, err = g.client.PullRequests.Edit(context.Background(), owner, repo, number, &github.PullRequest{Body: &body})
	if err != nil {
		return fmt.Errorf("updating the pull request %s: %w", url, err)
	}
	return nil
}

// currentUser returns the login name of the user that the API is in the
// hands of.
func (g *gitHub) currentUser() (string, error) {
	// no name asks for the user that the token is of
	user, _, err := g.client.Users.Get(context.Background(), "")
	if err != nil {
		return "", fmt.Errorf("asking GitHub for the current user: %w", err)
	}
	if user.GetLogin() == "" {
		return "", errors.New("GitHub did not say who the current user is")
	}
	return user.GetLogin(), nil
}

// currentMail returns the primary e-mail address of the user that the API
// is in the hands of. The token needs the scope user:email for it: what
// GitHub tells of a user without it is only the address on the profile,
// which need not be there.
func (g *gitHub) currentMail() (string, error) {
	emails, resp, err := g.client.Users.ListEmails(context.Background(), nil)
	if err != nil {
		const what = "asking GitHub for the e-mail addresses of the current user"
		// GitHub hides what a token may not see behind "not found"
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("%s: the token lacks the scope user:email: %w", what, err)
		}
		return "", fmt.Errorf("%s: %w", what, err)
	}
	for _, email := range emails {
		if email.GetPrimary() && email.GetVerified() {
			return email.GetEmail(), nil
		}
	}
	return "", errors.New("the current user has no verified primary e-mail address on GitHub")
}
