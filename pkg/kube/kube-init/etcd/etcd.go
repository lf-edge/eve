// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package etcd reads and edits the membership of k3s's embedded etcd
// cluster. It shells out to etcdctl, which the image already ships and
// which clustermode/masterleases.go already drives the same way.
//
// The official Go client was measured as the alternative and rejected:
// for the two calls used here it vendored 246 files and added 3MB to
// the binary, pulling in a second logging framework and gogo/protobuf.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Paths and endpoints. Vars for test override.
var (
	caCert = "/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt"
	cert   = "/var/lib/rancher/k3s/server/tls/etcd/client.crt"
	key    = "/var/lib/rancher/k3s/server/tls/etcd/client.key"

	etcdctlPath = "/usr/bin/etcdctl"

	// endpoint is the local etcd server. Membership is replicated, so
	// the local view is the cluster view once this member has joined.
	endpoint = "https://127.0.0.1:2379"
)

// Member is one etcd cluster member.
type Member struct {
	// ID is etcd's member ID. See IDHex for why the format matters.
	ID uint64
	// Name is empty until the member has started and introduced
	// itself. k3s names members "<node-name>-<8 hex chars>".
	Name       string
	PeerURLs   []string
	ClientURLs []string
	IsLearner  bool
}

// Started reports whether the member has come up and joined. etcd
// leaves the name empty for a member that was added but has never
// contacted the cluster.
func (m Member) Started() bool { return m.Name != "" }

// Voting reports whether the member contributes a quorum vote. A
// learner replicates but does not vote until etcd promotes it.
func (m Member) Voting() bool { return m.Started() && !m.IsLearner }

// IDHex renders the member ID the way etcdctl's member subcommands
// expect it. `member list -w json` reports IDs in decimal while
// `member remove` takes hex, and passing the decimal form through
// silently addresses the wrong member or fails.
func (m Member) IDHex() string { return strconv.FormatUint(m.ID, 16) }

// memberListJSON mirrors the parts of `etcdctl member list -w json`
// that we use.
type memberListJSON struct {
	Members []struct {
		ID         uint64   `json:"ID"`
		Name       string   `json:"name"`
		PeerURLs   []string `json:"peerURLs"`
		ClientURLs []string `json:"clientURLs"`
		IsLearner  bool     `json:"isLearner"`
	} `json:"members"`
}

// Members returns the current etcd cluster membership.
func Members(ctx context.Context) ([]Member, error) {
	out, err := run(ctx, "member", "list", "-w", "json")
	if err != nil {
		return nil, err
	}
	return parseMembers(out)
}

func parseMembers(out []byte) ([]Member, error) {
	var parsed memberListJSON
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parse member list: %w", err)
	}
	members := make([]Member, 0, len(parsed.Members))
	for _, m := range parsed.Members {
		members = append(members, Member{
			ID:         m.ID,
			Name:       m.Name,
			PeerURLs:   m.PeerURLs,
			ClientURLs: m.ClientURLs,
			IsLearner:  m.IsLearner,
		})
	}
	return members, nil
}

// Status is what the local member reports about its place in the
// cluster, without going through raft.
type Status struct {
	// HasLeader is false when the member knows of no leader, which is
	// what it reports once it can no longer reach a majority.
	HasLeader bool
	// Errors are the member's own error strings, such as
	// "etcdserver: no leader".
	Errors []string
}

// statusJSON mirrors the parts of `etcdctl endpoint status -w json`
// that we use.
type statusJSON []struct {
	Status struct {
		Leader uint64   `json:"leader"`
		Errors []string `json:"errors"`
	} `json:"Status"`
}

// LocalStatus asks the local member for its status. Unlike
// `endpoint health` it proposes nothing through raft, so it answers at
// once even without quorum instead of waiting for a commit to time out.
// An error means the member could not be reached at all, not that it
// lacks quorum.
func LocalStatus(ctx context.Context) (Status, error) {
	out, err := run(ctx, "endpoint", "status", "-w", "json")
	if err != nil {
		return Status{}, err
	}
	return parseStatus(out)
}

func parseStatus(out []byte) (Status, error) {
	var parsed statusJSON
	if err := json.Unmarshal(out, &parsed); err != nil {
		return Status{}, fmt.Errorf("parse endpoint status: %w", err)
	}
	if len(parsed) != 1 {
		return Status{}, fmt.Errorf("endpoint status: got %d endpoints, want 1",
			len(parsed))
	}
	return Status{
		HasLeader: parsed[0].Status.Leader != 0,
		Errors:    parsed[0].Status.Errors,
	}, nil
}

// RemoveMember evicts a member from the cluster.
func RemoveMember(ctx context.Context, m Member) error {
	if _, err := run(ctx, "member", "remove", m.IDHex()); err != nil {
		return fmt.Errorf("remove etcd member %s (%s): %w", m.Name, m.IDHex(), err)
	}
	return nil
}

// FindByNamePrefix returns the members whose name starts with prefix.
// k3s appends a random suffix to the node name, so a witness named
// "eve-witness" appears as "eve-witness-<8 hex chars>".
func FindByNamePrefix(members []Member, prefix string) []Member {
	var found []Member
	for _, m := range members {
		if strings.HasPrefix(m.Name, prefix) {
			found = append(found, m)
		}
	}
	return found
}

func run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{
		"--endpoints=" + endpoint,
		"--cacert=" + caCert,
		"--cert=" + cert,
		"--key=" + key,
	}, args...)
	cmd := exec.CommandContext(ctx, etcdctlPath, full...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		return nil, fmt.Errorf("etcdctl %s: %w (%s)",
			strings.Join(args, " "), err, stderr)
	}
	return out, nil
}
