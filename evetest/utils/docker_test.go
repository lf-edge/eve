// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

type nopCloser struct{ io.Reader }

func (nopCloser) Close() error { return nil }

type testHook struct{ messages []string }

func (h *testHook) Levels() []logrus.Level { return logrus.AllLevels }
func (h *testHook) Fire(e *logrus.Entry) error {
	h.messages = append(h.messages, e.Message)
	return nil
}

func runLogDockerResp(t *testing.T, lines []string) []string {
	var hook testHook
	log := logrus.New()
	log.SetLevel(logrus.TraceLevel)
	log.AddHook(&hook)
	entry := log.WithField("t", "x")

	r := nopCloser{strings.NewReader(strings.Join(lines, "\n") + "\n")}
	if err := logDockerResp(entry, r, "test-image"); err != nil {
		t.Fatalf("logDockerResp: %v", err)
	}
	return hook.messages
}

func TestLogDockerRespWaitsForAllLayers(t *testing.T) {
	lines := []string{
		`{"status":"Pulling from lfedge/eve","id":"0.0.0-master-abc"}`,
		`{"status":"Pulling fs layer","id":"layer1"}`,
		`{"status":"Pulling fs layer","id":"layer2"}`,
		`{"status":"Pulling fs layer","id":"layer3"}`,
		`{"status":"Pulling fs layer","id":"layer4"}`,
		`{"status":"Pulling fs layer","id":"layer5"}`,
		`{"status":"Pulling fs layer","id":"layer6"}`,
		`{"status":"Pulling fs layer","id":"layer7"}`,
		`{"status":"Pulling fs layer","id":"layer8"}`,
		`{"status":"Pulling fs layer","id":"layerBIG"}`,
		`{"status":"Downloading","id":"layer1","progressDetail":{"current":100,"total":100}}`,
		`{"status":"Downloading","id":"layer2","progressDetail":{"current":200,"total":200}}`,
		`{"status":"Downloading","id":"layer3","progressDetail":{"current":50,"total":50}}`,
		`{"status":"Downloading","id":"layer4","progressDetail":{"current":50,"total":50}}`,
		`{"status":"Downloading","id":"layer5","progressDetail":{"current":50,"total":50}}`,
		`{"status":"Downloading","id":"layer6","progressDetail":{"current":50,"total":50}}`,
		`{"status":"Downloading","id":"layer7","progressDetail":{"current":50,"total":50}}`,
		`{"status":"Downloading","id":"layer8","progressDetail":{"current":50,"total":50}}`,
		`{"status":"Downloading","id":"layerBIG","progressDetail":{"current":1000,"total":780000000}}`,
	}
	for _, msg := range runLogDockerResp(t, lines) {
		if strings.Contains(msg, "100.0%") {
			t.Errorf("premature 100%% progress logged before all layers known: %q", msg)
		}
	}
}

func TestLogDockerRespIgnoresAlreadyExists(t *testing.T) {
	lines := []string{
		`{"status":"Pulling from lfedge/eve","id":"0.0.0-master-abc"}`,
		`{"status":"Pulling fs layer","id":"cached1"}`,
		`{"status":"Pulling fs layer","id":"layerBIG"}`,
		`{"status":"Already exists","id":"cached1"}`,
		`{"status":"Downloading","id":"layerBIG","progressDetail":{"current":1000,"total":780000000}}`,
		`{"status":"Downloading","id":"layerBIG","progressDetail":{"current":390000000,"total":780000000}}`,
	}
	msgs := runLogDockerResp(t, lines)
	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "Pull progress") {
			found = true
			if !strings.Contains(msg, "780000000") {
				t.Errorf("progress line has wrong total (cached layer shouldn't block or skew it): %q", msg)
			}
		}
	}
	if !found {
		t.Errorf("expected at least one aggregate progress line, got none: %v", msgs)
	}
}

func TestLogDockerRespLogsFinalOnlyOnce(t *testing.T) {
	// Two layers both send their final "Downloading" tick (current==total)
	// within the same batch -- each independently computes an aggregate
	// current>=total, which must not produce two identical "100.0%" lines.
	lines := []string{
		`{"status":"Pulling from lfedge/eve","id":"0.0.0-master-abc"}`,
		`{"status":"Pulling fs layer","id":"layer1"}`,
		`{"status":"Pulling fs layer","id":"layer2"}`,
		`{"status":"Downloading","id":"layer1","progressDetail":{"current":50,"total":100}}`,
		`{"status":"Downloading","id":"layer2","progressDetail":{"current":50,"total":100}}`,
		`{"status":"Downloading","id":"layer1","progressDetail":{"current":100,"total":100}}`,
		`{"status":"Downloading","id":"layer2","progressDetail":{"current":100,"total":100}}`,
	}
	msgs := runLogDockerResp(t, lines)
	count := 0
	for _, msg := range msgs {
		if strings.Contains(msg, "100.0%") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one 100%% progress line, got %d: %v", count, msgs)
	}
}

func TestLogDockerRespIgnoresExtractingPhase(t *testing.T) {
	// A small layer finishes downloading and moves into Extracting (which
	// reports a completely different, uncompressed total) while the big
	// layer is still mid-download -- the aggregate must not be skewed by
	// the small layer's Extracting numbers.
	lines := []string{
		`{"status":"Pulling from lfedge/eve","id":"0.0.0-master-abc"}`,
		`{"status":"Pulling fs layer","id":"small"}`,
		`{"status":"Pulling fs layer","id":"layerBIG"}`,
		`{"status":"Downloading","id":"small","progressDetail":{"current":100,"total":100}}`,
		`{"status":"Downloading","id":"layerBIG","progressDetail":{"current":1000,"total":780000000}}`,
		`{"status":"Extracting","id":"small","progressDetail":{"current":50000000,"total":50000000}}`,
		`{"status":"Downloading","id":"layerBIG","progressDetail":{"current":390000000,"total":780000000}}`,
	}
	msgs := runLogDockerResp(t, lines)
	for _, msg := range msgs {
		if strings.Contains(msg, "Pull progress") && strings.Contains(msg, "50000000") {
			t.Errorf("Extracting-phase bytes leaked into the download aggregate: %q", msg)
		}
	}
}
