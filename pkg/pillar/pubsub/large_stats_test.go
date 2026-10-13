// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

func TestLargeFileCounters(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	name := uniqueName("largestats/item")
	in := []byte(`{"Name":"x","pubsub-large-A":"aaaa","Sub":{"pubsub-large-B":[1,2,3]}}`)

	out, err := writeAndRemoveLarge(log, in, t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	pub := PublicationStats(name)
	if pub.LargeFilesWritten.Load() != 2 || pub.LargeBytesWritten.Load() == 0 {
		t.Fatalf("files written %d bytes %d, want 2 files",
			pub.LargeFilesWritten.Load(), pub.LargeBytesWritten.Load())
	}

	restored, err := readAddLarge(log, out, name)
	if err != nil {
		t.Fatal(err)
	}
	if got := SubscriptionStats(name).LargeFilesRead.Load(); got != 2 {
		t.Fatalf("files read %d, want 2", got)
	}
	var want, got interface{}
	_ = json.Unmarshal(in, &want)
	_ = json.Unmarshal(restored, &got)
	wantB, _ := json.Marshal(want)
	gotB, _ := json.Marshal(got)
	if !bytes.Equal(wantB, gotB) {
		t.Fatalf("restored %s, want %s", gotB, wantB)
	}
}
