// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
	"time"

	"github.com/onsi/gomega"
)

const (
	testFullHash  = "full"
	testShortHash = "short"
	noDeviceBody  = "no device online\n+++Done+++"
)

// fakeProbe answers probes from a per-call script and records the hashes asked.
type fakeProbe struct {
	answers []map[string]string // one map per probe pair, keyed by hash
	asked   []string
}

func (f *fakeProbe) probe(hash string) string {
	f.asked = append(f.asked, hash)
	pair := (len(f.asked) - 1) / 2
	if pair >= len(f.answers) {
		pair = len(f.answers) - 1
	}
	return f.answers[pair][hash]
}

func noDevicePair() map[string]string {
	return map[string]string{testFullHash: noDeviceBody, testShortHash: noDeviceBody}
}

func TestProbeTokenHashFullHash(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{{testFullHash: serverConnectedMsg}}}
	hash, err := probeTokenHash(f.probe, testFullHash, testShortHash, 0, time.Millisecond, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(hash).To(gomega.Equal(testFullHash))
	g.Expect(f.asked).To(gomega.Equal([]string{testFullHash}))
}

func TestProbeTokenHashShortHash(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{
		{testFullHash: noDeviceBody, testShortHash: serverConnectedMsg}}}
	hash, err := probeTokenHash(f.probe, testFullHash, testShortHash, 0, time.Millisecond, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(hash).To(gomega.Equal(testShortHash))
}

func TestProbeTokenHashNoWait(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{noDevicePair()}}
	_, err := probeTokenHash(f.probe, testFullHash, testShortHash, 0, time.Millisecond, nil)
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("device is not connected to the dispatcher;")))
	g.Expect(err.Error()).To(gomega.ContainSubstring("-wait"))
	g.Expect(f.asked).To(gomega.HaveLen(2), "no retry without -wait")
}

func TestProbeTokenHashWaitThenConnect(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{
		noDevicePair(), noDevicePair(), {testFullHash: serverConnectedMsg}}}
	hash, err := probeTokenHash(f.probe, testFullHash, testShortHash,
		time.Minute, time.Millisecond, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(hash).To(gomega.Equal(testFullHash))
	g.Expect(f.asked).To(gomega.HaveLen(5))
}

func TestProbeTokenHashWaitTimeout(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{noDevicePair()}}
	_, err := probeTokenHash(f.probe, testFullHash, testShortHash,
		50*time.Millisecond, 10*time.Millisecond, nil)
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("after waiting 50ms")))
	g.Expect(len(f.asked)).To(gomega.BeNumerically(">", 2))
}

func TestProbeTokenHashInterrupted(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{noDevicePair()}}
	intSignal := make(chan os.Signal, 1)
	intSignal <- os.Interrupt
	_, err := probeTokenHash(f.probe, testFullHash, testShortHash,
		time.Minute, time.Minute, intSignal)
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("interrupted")))
}

func TestProbeTokenHashOtherResponse(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{{testFullHash: "token expired"}}}
	_, err := probeTokenHash(f.probe, testFullHash, testShortHash, time.Minute, time.Millisecond, nil)
	g.Expect(err).To(gomega.MatchError("probe response: token expired"))
	g.Expect(f.asked).To(gomega.HaveLen(1), "no retry on a non 'no device' answer")
}

func TestProbeTokenHashUnreachable(t *testing.T) {
	g := gomega.NewWithT(t)
	f := &fakeProbe{answers: []map[string]string{{}}}
	_, err := probeTokenHash(f.probe, testFullHash, testShortHash, time.Minute, time.Millisecond, nil)
	g.Expect(err).To(gomega.MatchError("could not reach the dispatcher"))
}
