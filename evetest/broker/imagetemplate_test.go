// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

func baseKeyParams() templateKeyParams {
	return templateKeyParams{
		DockerImageID: "sha256:aaaa",
		DiskBytes:     30 << 30,
		Installer:     false,
		Arch:          api.ArchType_ARCH_AMD64,
	}
}

func TestComputeTemplateKeyIsStable(t *testing.T) {
	if computeTemplateKey(baseKeyParams()) != computeTemplateKey(baseKeyParams()) {
		t.Fatal("same inputs produced different keys")
	}
}

// TestTemplateKeyParamsFields locks down the property the whole design depends
// on: device configuration must never reach the cache key, so that a test
// changing grub options, global.json, certificates or the soft serial still
// reuses the cached template. Those are not fields of templateKeyParams, and
// this asserts nobody adds one -- comparing two equal structs could not detect
// that, since a new field would be zero in both.
func TestTemplateKeyParamsFields(t *testing.T) {
	want := []string{"DockerImageID", "LiveImageSHA256", "DiskBytes", "Installer", "Arch"}
	typ := reflect.TypeOf(templateKeyParams{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("templateKeyParams fields = %v, want %v.\n"+
			"Device configuration must not enter the cache key: it is injected "+
			"into the CONFIG partition of the working copy instead. If this is a "+
			"genuinely image-wide input, add it here and bump templateFormatVersion.",
			got, want)
	}
}

// TestLiveTemplateKeyParamsIgnoresDiskSize pins the live path's sizing model:
// disk size is applied per device by resizing the overlay, so two devices
// asking for different sizes must resolve to the SAME template.
//
// Note this tests the params helper, not computeTemplateKey -- the hash does
// include DiskBytes, and it is the live path's job never to set it.
func TestLiveTemplateKeyParamsIgnoresDiskSize(t *testing.T) {
	small := liveTemplateKeyParams("abc", api.ArchType_ARCH_AMD64, 8<<30)
	large := liveTemplateKeyParams("abc", api.ArchType_ARCH_AMD64, 64<<30)
	if small.DiskBytes != 0 {
		t.Errorf("DiskBytes = %d, want 0: the live path sizes per device", small.DiskBytes)
	}
	if computeTemplateKey(small) != computeTemplateKey(large) {
		t.Error("two disk sizes produced two templates; they must share one")
	}
	other := liveTemplateKeyParams("def", api.ArchType_ARCH_AMD64, 8<<30)
	if computeTemplateKey(small) == computeTemplateKey(other) {
		t.Error("different live image hashes produced the same key")
	}
}

func TestComputeTemplateKeyVaries(t *testing.T) {
	base := computeTemplateKey(baseKeyParams())

	tests := []struct {
		name   string
		mutate func(*templateKeyParams)
	}{
		{"docker image ID", func(p *templateKeyParams) { p.DockerImageID = "sha256:bbbb" }},
		{"disk size", func(p *templateKeyParams) { p.DiskBytes = 40 << 30 }},
		{"installer flag", func(p *templateKeyParams) { p.Installer = true }},
		{"arch", func(p *templateKeyParams) { p.Arch = api.ArchType_ARCH_ARM64 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := baseKeyParams()
			tc.mutate(&p)
			if computeTemplateKey(p) == base {
				t.Errorf("changing %s did not change the key", tc.name)
			}
		})
	}
}

func TestTemplateMetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := templateMeta{
		FormatVersion:    templateFormatVersion,
		Key:              "abc123",
		DockerImageID:    "sha256:aaaa",
		DiskBytes:        30 << 30,
		Installer:        false,
		Arch:             api.ArchType_ARCH_AMD64.String(),
		ConfigOffset:     6291456,
		ConfigLength:     5 << 20,
		DiskVirtualBytes: 30 << 30,
		BuiltAt:          time.Now().UTC().Truncate(time.Second),
		LastUsed:         time.Now().UTC().Truncate(time.Second),
	}
	if err := want.save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadTemplateMeta(dir)
	if err != nil {
		t.Fatalf("loadTemplateMeta: %v", err)
	}
	if got.Key != want.Key || got.ConfigOffset != want.ConfigOffset ||
		got.ConfigLength != want.ConfigLength || got.DockerImageID != want.DockerImageID {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestLoadTemplateMetaRejectsOldFormatVersion(t *testing.T) {
	dir := t.TempDir()
	m := templateMeta{FormatVersion: templateFormatVersion - 1, Key: "abc123"}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, templateMetaFile), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadTemplateMeta(dir); err == nil {
		t.Fatal("expected an error for an older format version")
	}
}

func TestLoadTemplateMetaRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, templateMetaFile), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadTemplateMeta(dir); err == nil {
		t.Fatal("expected an error for a corrupt meta file")
	}
}

// TestLoadTemplateMetaMissingFile pins the error contract callers rely
// on to tell a cold cache apart from a corrupt one. Note errors.Is, not
// os.IsNotExist: the latter cannot see through loadTemplateMeta's %w wrap and
// would report false here.
func TestLoadTemplateMetaMissingFile(t *testing.T) {
	_, err := loadTemplateMeta(t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a missing meta file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) = false for a missing meta file; "+
			"callers cannot distinguish a cold cache from a corrupt one. err = %v", err)
	}
	if os.IsNotExist(err) {
		t.Error("os.IsNotExist unexpectedly matched the wrapped error; if this " +
			"starts passing, the %w wrap was removed and the doc comment on " +
			"loadTemplateMeta needs updating")
	}
}

// TestLoadTemplateMetaRejectsMissingDiskVirtualBytes covers a template written
// before the field existed: it must be a clean miss and get rebuilt, rather
// than loading with a zero baseline that silently defeats resizeDeviceDisk's
// shrink check.
func TestLoadTemplateMetaRejectsMissingDiskVirtualBytes(t *testing.T) {
	dir := t.TempDir()
	m := templateMeta{
		FormatVersion: templateFormatVersion,
		Key:           "k",
		ConfigOffset:  6291456,
		ConfigLength:  5 << 20,
	}
	if err := m.save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := loadTemplateMeta(dir); err == nil {
		t.Fatal("expected an error for a meta with no recorded disk virtual size")
	}
}

func newTestCache(t *testing.T) *templateCache {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	c := newTemplateCache(t.TempDir(), log)
	if err := c.tryLock(); err != nil {
		t.Fatalf("tryLock: %v", err)
	}
	t.Cleanup(c.unlock)
	return c
}

// stubBuilder writes the files a real template build produces, and records how
// many times it ran.
func stubBuilder(calls *int32, delay time.Duration) templateBuilder {
	return func(_ context.Context, _ *logrus.Entry, dstDir string) (gptPartition, error) {
		atomic.AddInt32(calls, 1)
		time.Sleep(delay)
		for _, name := range []string{templateDiskFile, templateConfigImgFile} {
			if err := os.WriteFile(filepath.Join(dstDir, name), []byte("x"), 0o600); err != nil {
				return gptPartition{}, err
			}
		}
		if err := os.MkdirAll(filepath.Join(dstDir, templateFirmwareDir), 0o755); err != nil {
			return gptPartition{}, err
		}
		return gptPartition{Offset: 6291456, Length: 5 << 20}, nil
	}
}

func TestEnsureTemplateBuildsOnceThenHits(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	first, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("first ensureTemplate: %v", err)
	}
	second, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("second ensureTemplate: %v", err)
	}
	if calls != 1 {
		t.Errorf("builder ran %d times, want 1", calls)
	}
	if first.Dir != second.Dir {
		t.Errorf("cache returned different dirs: %q vs %q", first.Dir, second.Dir)
	}
	if second.Meta.ConfigOffset != 6291456 || second.Meta.ConfigLength != 5<<20 {
		t.Errorf("CONFIG partition not persisted: %+v", second.Meta)
	}
	if _, err := os.Stat(second.diskPath()); err != nil {
		t.Errorf("template disk missing: %v", err)
	}
	if _, err := os.Stat(second.refsDir()); err != nil {
		t.Errorf("refs dir missing: %v", err)
	}
}

func TestEnsureTemplateSingleFlight(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	const concurrency = 5
	var wg sync.WaitGroup
	errs := make([]error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.ensureTemplate(context.Background(), log,
				baseKeyParams(), stubBuilder(&calls, 50*time.Millisecond))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Errorf("builder ran %d times under concurrency, want 1", calls)
	}
}

// TestEnsureTemplateWaiterRetriesAfterLeaderFailure covers the client that
// started a shared build failing or disconnecting: its error must not be
// reported to the other clients waiting on that build.
func TestEnsureTemplateWaiterRetriesAfterLeaderFailure(t *testing.T) {
	c := newTestCache(t)
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	leaderIn := make(chan struct{})
	var calls int32
	builder := func(_ context.Context, _ *logrus.Entry, dstDir string) (gptPartition, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(leaderIn)
			return gptPartition{}, errors.New("leader disconnected")
		}
		for _, name := range []string{templateDiskFile, templateConfigImgFile} {
			if err := os.WriteFile(filepath.Join(dstDir, name), []byte("x"), 0o600); err != nil {
				return gptPartition{}, err
			}
		}
		if err := os.MkdirAll(filepath.Join(dstDir, templateFirmwareDir), 0o755); err != nil {
			return gptPartition{}, err
		}
		return gptPartition{Offset: 6291456, Length: 5 << 20}, nil
	}

	var wg sync.WaitGroup
	var waiterRef *templateRef
	var waiterErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-leaderIn
		waiterRef, waiterErr = c.ensureTemplate(context.Background(), log, baseKeyParams(), builder)
	}()

	_, leaderErr := c.ensureTemplate(context.Background(), log, baseKeyParams(), builder)
	if leaderErr == nil {
		t.Fatal("the leader's build was supposed to fail")
	}
	wg.Wait()
	if waiterErr != nil {
		t.Fatalf("waiter inherited the leader's failure instead of retrying: %v", waiterErr)
	}
	if waiterRef == nil {
		t.Fatal("waiter got no template")
	}
}

func TestEnsureTemplateFailedBuildLeavesNothingBehind(t *testing.T) {
	c := newTestCache(t)
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	failing := func(_ context.Context, _ *logrus.Entry, dstDir string) (gptPartition, error) {
		_ = os.WriteFile(filepath.Join(dstDir, templateDiskFile), []byte("partial"), 0o600)
		return gptPartition{}, errors.New("boom")
	}
	if _, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), failing); err == nil {
		t.Fatal("expected the build error to propagate")
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read templates dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("failed build left %d entries behind: %v", len(entries), entries)
	}

	// A later successful build for the same key must still work.
	var calls int32
	if _, err := c.ensureTemplate(context.Background(), log,
		baseKeyParams(), stubBuilder(&calls, 0)); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
}

func TestEnsureTemplateRebuildsWhenMetaIsCorrupt(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ref.Dir, templateMetaFile), []byte("{bad"), 0o600); err != nil {
		t.Fatalf("corrupt meta: %v", err)
	}
	if _, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0)); err != nil {
		t.Fatalf("ensureTemplate after corruption: %v", err)
	}
	if calls != 2 {
		t.Errorf("builder ran %d times, want 2 (corrupt template must be rebuilt)", calls)
	}
}

func TestEnsureTemplateRebuildsWhenDiskIsMissing(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := os.Remove(ref.diskPath()); err != nil {
		t.Fatalf("remove disk: %v", err)
	}
	if _, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0)); err != nil {
		t.Fatalf("ensureTemplate after disk removal: %v", err)
	}
	if calls != 2 {
		t.Errorf("builder ran %d times, want 2", calls)
	}
}

func TestRemoveStaleTmpDirs(t *testing.T) {
	c := newTestCache(t)
	if err := os.MkdirAll(filepath.Join(c.dir, templateTmpPrefix+"abc-1"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(c.dir, "realkey"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := c.removeStaleTmpDirs(); err != nil {
		t.Fatalf("removeStaleTmpDirs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.dir, templateTmpPrefix+"abc-1")); !os.IsNotExist(err) {
		t.Error("stale tmp dir was not removed")
	}
	if _, err := os.Stat(filepath.Join(c.dir, "realkey")); err != nil {
		t.Errorf("real template dir was removed: %v", err)
	}
}

// TestNonOwnerDoesNotRemoveStaleTmpDirs covers a second broker starting on a
// shared image directory: the .tmp-* dirs it would sweep may be the owner's
// build in progress, so it must leave them alone.
func TestNonOwnerDoesNotRemoveStaleTmpDirs(t *testing.T) {
	imageDir := t.TempDir()
	log := logrus.New()
	log.SetOutput(io.Discard)

	owner := newTemplateCache(imageDir, log)
	if err := owner.tryLock(); err != nil {
		t.Fatalf("first tryLock must succeed: %v", err)
	}
	t.Cleanup(owner.unlock)

	second := newTemplateCache(imageDir, log)
	if err := second.tryLock(); err != nil {
		t.Fatalf("second tryLock must not error: %v", err)
	}
	if second.owner {
		t.Fatal("second cache claimed ownership while the first holds the lock")
	}

	inProgress := filepath.Join(second.dir, templateTmpPrefix+"somekey-1")
	if err := os.MkdirAll(inProgress, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := second.removeStaleTmpDirs(); err != nil {
		t.Fatalf("removeStaleTmpDirs: %v", err)
	}
	if _, err := os.Stat(inProgress); err != nil {
		t.Errorf("a non-owner removed an in-progress build directory: %v", err)
	}
	// The owner must still sweep it.
	if err := owner.removeStaleTmpDirs(); err != nil {
		t.Fatalf("owner removeStaleTmpDirs: %v", err)
	}
	if _, err := os.Stat(inProgress); !os.IsNotExist(err) {
		t.Errorf("the owner failed to sweep the stale dir: %v", err)
	}
}

// TestEnsureTemplateDifferentKeysDoNotBlock proves the cache does not simply
// serialise every call. Both builders wait for the other to start, so an
// implementation holding one lock across all of ensureTemplate -- which would
// still pass TestEnsureTemplateSingleFlight -- cannot get both in flight.
func TestEnsureTemplateDifferentKeysDoNotBlock(t *testing.T) {
	c := newTestCache(t)
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	builder := func(_ context.Context, _ *logrus.Entry, dstDir string) (gptPartition, error) {
		started <- struct{}{}
		<-release
		for _, name := range []string{templateDiskFile, templateConfigImgFile} {
			if err := os.WriteFile(filepath.Join(dstDir, name), []byte("x"), 0o600); err != nil {
				return gptPartition{}, err
			}
		}
		if err := os.MkdirAll(filepath.Join(dstDir, templateFirmwareDir), 0o755); err != nil {
			return gptPartition{}, err
		}
		return gptPartition{Offset: 6291456, Length: 5 << 20}, nil
	}

	paramsB := baseKeyParams()
	paramsB.DiskBytes = 40 << 30

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, p := range []templateKeyParams{baseKeyParams(), paramsB} {
		wg.Add(1)
		go func(i int, p templateKeyParams) {
			defer wg.Done()
			_, errs[i] = c.ensureTemplate(context.Background(), log, p, builder)
		}(i, p)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("only one build ran at a time: unrelated keys block each other")
		}
	}
	close(release)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

func TestTemplateRefsPinAndRelease(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if c.hasRefs(ref.Key) {
		t.Error("a fresh template must have no refs")
	}
	if err := c.addRef(ref.Key, "eve-abcd-node1"); err != nil {
		t.Fatalf("addRef: %v", err)
	}
	if err := c.addRef(ref.Key, "eve-abcd-node2"); err != nil {
		t.Fatalf("addRef: %v", err)
	}
	if !c.hasRefs(ref.Key) {
		t.Error("template with two refs reported as unreferenced")
	}
	if err := c.removeRef(ref.Key, "eve-abcd-node1"); err != nil {
		t.Fatalf("removeRef: %v", err)
	}
	if !c.hasRefs(ref.Key) {
		t.Error("template still has one ref but reported as unreferenced")
	}
	if err := c.removeRef(ref.Key, "eve-abcd-node2"); err != nil {
		t.Fatalf("removeRef: %v", err)
	}
	if c.hasRefs(ref.Key) {
		t.Error("template with all refs released reported as referenced")
	}
}

// TestRemoveRefIsIdempotent matters because teardown runs on paths where the
// working copy may never have been created.
func TestRemoveRefIsIdempotent(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := c.removeRef(ref.Key, "never-added"); err != nil {
		t.Errorf("removeRef on a missing ref should succeed, got %v", err)
	}
	if err := c.removeRef("no-such-template", "whatever"); err != nil {
		t.Errorf("removeRef on a missing template should succeed, got %v", err)
	}
}

// TestClearAllRefs covers broker restart: client sessions do not survive it, so
// every ref marker is stale and must be dropped, or the template stays pinned
// forever.
func TestClearAllRefs(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := c.addRef(ref.Key, "eve-abcd-node1"); err != nil {
		t.Fatalf("addRef: %v", err)
	}
	if err := c.clearAllRefs(); err != nil {
		t.Fatalf("clearAllRefs: %v", err)
	}
	if c.hasRefs(ref.Key) {
		t.Error("refs survived clearAllRefs")
	}
	if _, err := os.Stat(ref.diskPath()); err != nil {
		t.Errorf("clearAllRefs must not touch the template itself: %v", err)
	}
}

func TestCandidatesSkipsReferencedTemplates(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	pinnedParams := baseKeyParams()
	freeParams := baseKeyParams()
	freeParams.DiskBytes = 40 << 30

	pinned, err := c.ensureTemplate(context.Background(), log, pinnedParams, stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	free, err := c.ensureTemplate(context.Background(), log, freeParams, stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := c.addRef(pinned.Key, "eve-abcd-node1"); err != nil {
		t.Fatalf("addRef: %v", err)
	}

	got := c.candidates()
	if len(got) != 1 {
		t.Fatalf("candidates() returned %d entries, want 1: %+v", len(got), got)
	}
	if got[0].ID != free.Key {
		t.Errorf("candidates() returned %q, want the unreferenced %q", got[0].ID, free.Key)
	}
}

// TestNonOwnerCacheDoesNotHousekeep covers a second broker sharing an image
// directory: it must not clear the first broker's refs or evict its templates,
// or it can delete a backing file out from under a running VM.
func TestNonOwnerCacheDoesNotHousekeep(t *testing.T) {
	imageDir := t.TempDir()
	log := logrus.New()
	log.SetOutput(io.Discard)

	owner := newTemplateCache(imageDir, log)
	if err := owner.tryLock(); err != nil {
		t.Fatalf("first tryLock must succeed: %v", err)
	}
	t.Cleanup(owner.unlock)

	second := newTemplateCache(imageDir, log)
	if err := second.tryLock(); err != nil {
		t.Fatalf("second tryLock must not error, only decline ownership: %v", err)
	}
	if second.owner {
		t.Fatal("second cache claimed ownership while the first holds the lock")
	}

	var calls int32
	entry := logrus.NewEntry(log)
	ref, err := owner.ensureTemplate(context.Background(), entry, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := owner.addRef(ref.Key, "eve-abcd-node1"); err != nil {
		t.Fatalf("addRef: %v", err)
	}

	if err := second.clearAllRefs(); err != nil {
		t.Fatalf("clearAllRefs: %v", err)
	}
	if !owner.hasRefs(ref.Key) {
		t.Error("a non-owner cache cleared the owner's refs")
	}
	if got := second.candidates(); got != nil {
		t.Errorf("a non-owner cache offered %d eviction candidates, want none", len(got))
	}
}

func TestEvictRemovesTemplateDir(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if err := c.evict(ref.Key); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if _, err := os.Stat(ref.Dir); !os.IsNotExist(err) {
		t.Errorf("template dir still present after evict: %v", err)
	}
}

// TestEvictRefusesReferencedTemplate covers a reference acquired after
// candidates() snapshotted the list: evict must re-check rather than trust it.
func TestEvictRefusesReferencedTemplate(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	// Snapshot first, exactly as the sweep does, then acquire a reference.
	if got := c.candidates(); len(got) != 1 {
		t.Fatalf("candidates() = %d entries, want 1", len(got))
	}
	if err := c.addRef(ref.Key, "eve-abcd-node1"); err != nil {
		t.Fatalf("addRef: %v", err)
	}
	if err := c.evict(ref.Key); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if _, err := os.Stat(ref.diskPath()); err != nil {
		t.Errorf("evict deleted a template that gained a reference after the snapshot: %v", err)
	}
}

// TestEvictAddRefRace stresses the interleaving between evict's
// check-and-delete and a concurrent addRef: before refsMutex serialized them,
// evict could observe an empty refs dir, a concurrent addRef could then land
// its marker, and evict would still proceed to RemoveAll -- deleting a
// template the device had just taken a reference on. This is a stress loop,
// not a forced interleaving (the window is only a few instructions wide), so
// passing does not prove the race is impossible, only that it did not fire in
// these iterations; run with -race and a high -count for confidence.
func TestEvictAddRefRace(t *testing.T) {
	c := newTestCache(t)
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	const iterations = 200
	for i := 0; i < iterations; i++ {
		var calls int32
		params := baseKeyParams()
		params.DockerImageID = fmt.Sprintf("sha256:race-%d", i)
		ref, err := c.ensureTemplate(context.Background(), log, params, stubBuilder(&calls, 0))
		if err != nil {
			t.Fatalf("iteration %d: ensureTemplate: %v", i, err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var addErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			addErr = c.addRef(ref.Key, "eve-race-node")
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := c.evict(ref.Key); err != nil {
				t.Errorf("iteration %d: evict: %v", i, err)
			}
		}()
		close(start)
		wg.Wait()

		if addErr == nil {
			if _, err := os.Stat(ref.Dir); err != nil {
				t.Fatalf("iteration %d: addRef returned nil but the template dir is gone: %v", i, err)
			}
		}
	}
}

// TestRefNameRejectsPathTraversal covers a client-supplied device name that
// tries to escape the refs directory: both addRef and removeRef must reject
// it outright rather than joining it into a path.
func TestRefNameRejectsPathTraversal(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	ref, err := c.ensureTemplate(context.Background(), log, baseKeyParams(), stubBuilder(&calls, 0))
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}

	for _, bad := range []string{"../../escape", "", "a/b"} {
		if err := c.addRef(ref.Key, bad); err == nil {
			t.Errorf("addRef(%q) should have been rejected", bad)
		}
		if err := c.removeRef(ref.Key, bad); err == nil {
			t.Errorf("removeRef(%q) should have been rejected", bad)
		}
	}

	// Nothing must have escaped the refs directory or the image dir itself.
	if _, err := os.Stat(filepath.Join(c.imageDir, "escape")); !os.IsNotExist(err) {
		t.Errorf("a file escaped the refs directory: %v", err)
	}
	entries, err := os.ReadDir(ref.refsDir())
	if err != nil {
		t.Fatalf("read refs dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("refs dir has %d unexpected entries: %v", len(entries), entries)
	}
}

// TestValidLiveImageSHA256RejectsBadInput covers the client-supplied sha256
// that liveUploadPath joins straight into a path: a path-traversal payload, an
// empty string, an uppercase digest (hex.EncodeToString never produces one, so
// this rejects a hand-crafted request) and one hex character short of 64 must
// all be rejected before they reach filepath.Join.
func TestValidLiveImageSHA256RejectsBadInput(t *testing.T) {
	valid64 := strings.Repeat("a", 64)
	bad := []string{
		"../../escape",
		"",
		strings.ToUpper(valid64),
		valid64[:63],
	}
	for _, sha := range bad {
		if err := validLiveImageSHA256(sha); err == nil {
			t.Errorf("validLiveImageSHA256(%q) should have been rejected", sha)
		}
	}
	if err := validLiveImageSHA256(valid64); err != nil {
		t.Errorf("validLiveImageSHA256(%q) rejected a valid digest: %v", valid64, err)
	}
}
