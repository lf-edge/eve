// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package etcd

import (
	"strings"
	"testing"
)

// TestMemberIDHex pins the decimal-to-hex conversion. `member list -w
// json` reports IDs in decimal while `member remove` takes hex, and
// passing the decimal form through addresses the wrong member or fails.
func TestMemberIDHex(t *testing.T) {
	cases := []struct {
		id   uint64
		want string
	}{
		{0, "0"},
		{10, "a"},
		{3279244937613851754, "2d8237e585f8bc6a"},
	}
	for _, c := range cases {
		if got := (Member{ID: c.id}).IDHex(); got != c.want {
			t.Errorf("Member{ID:%d}.IDHex() = %q, want %q", c.id, got, c.want)
		}
	}
}

// TestMemberState covers the two ways a member can be present without
// contributing a vote: added but never started (etcd leaves the name
// empty), and started but still a learner, which replicates without
// voting.
func TestMemberState(t *testing.T) {
	cases := []struct {
		name        string
		member      Member
		wantStarted bool
		wantVoting  bool
	}{
		{"unstarted", Member{ID: 1}, false, false},
		{"learner", Member{ID: 2, Name: "eve-witness-abc", IsLearner: true}, true, false},
		{"voter", Member{ID: 3, Name: "eve-witness-abc"}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.member.Started(); got != c.wantStarted {
				t.Errorf("Started() = %v, want %v", got, c.wantStarted)
			}
			if got := c.member.Voting(); got != c.wantVoting {
				t.Errorf("Voting() = %v, want %v", got, c.wantVoting)
			}
		})
	}
}

// TestFindByNamePrefix matches the way k3s names members: the node name
// plus a random suffix.
func TestFindByNamePrefix(t *testing.T) {
	members := []Member{
		{Name: "edge-dev1"},
		{Name: "eve-witness-c2aef981"},
		{Name: ""},
	}
	got := FindByNamePrefix(members, "eve-witness")
	if len(got) != 1 || got[0].Name != "eve-witness-c2aef981" {
		t.Errorf("FindByNamePrefix = %v, want the witness member", got)
	}
	if len(FindByNamePrefix(members, "nope")) != 0 {
		t.Error("unexpected match")
	}
}

// TestParseMembers covers the shape etcdctl actually emits: IDs in
// decimal, and no name at all for a member that was added but has never
// started.
func TestParseMembers(t *testing.T) {
	raw := []byte(`{"header":{"cluster_id":1},"members":[
	  {"ID":3279244937613851754,"name":"edge-dev1","peerURLs":["https://10.244.244.2:2380"],
	   "clientURLs":["https://10.244.244.2:2379"]},
	  {"ID":5,"peerURLs":["https://10.244.244.5:2380"],"clientURLs":[]},
	  {"ID":7,"name":"eve-witness-c2aef981","peerURLs":["https://10.244.244.5:2380"],
	   "clientURLs":["https://10.244.244.5:2379"],"isLearner":true}]}`)

	members, err := parseMembers(raw)
	if err != nil {
		t.Fatalf("parseMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}
	if members[0].IDHex() != "2d8237e585f8bc6a" {
		t.Errorf("IDHex = %q, want 2d8237e585f8bc6a", members[0].IDHex())
	}
	if members[1].Started() {
		t.Error("member with no name must not count as started")
	}
	if members[2].Voting() {
		t.Error("learner must not count as voting")
	}
}

// TestParseStatus pins how the local member's status is read: a leader
// ID of zero, with the member's own error, is how it reports having
// lost quorum.
func TestParseStatus(t *testing.T) {
	cases := []struct {
		name       string
		out        string
		want       Status
		wantErrStr bool
	}{
		{
			name: "healthy",
			out:  `[{"Endpoint":"https://127.0.0.1:2379","Status":{"leader":12345,"raftTerm":24}}]`,
			want: Status{HasLeader: true},
		},
		{
			name: "no leader",
			out:  `[{"Endpoint":"https://127.0.0.1:2379","Status":{"leader":0,"errors":["etcdserver: no leader"]}}]`,
			want: Status{Errors: []string{"etcdserver: no leader"}},
		},
		{name: "garbage", out: `not json`, wantErrStr: true},
		{name: "no endpoints", out: `[]`, wantErrStr: true},
	}
	for _, c := range cases {
		got, err := parseStatus([]byte(c.out))
		if (err != nil) != c.wantErrStr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErrStr)
			continue
		}
		if got.HasLeader != c.want.HasLeader ||
			strings.Join(got.Errors, ";") != strings.Join(c.want.Errors, ";") {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}
