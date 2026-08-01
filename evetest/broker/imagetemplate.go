// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

const (
	// templateFormatVersion is bumped whenever the template directory layout
	// changes, or the way the template disk itself is built changes. It is part
	// of the cache key, so bumping it makes every existing template a miss
	// rather than a subtly wrong hit.
	templateFormatVersion = 1

	// templatesSubdir is where templates live under the broker's image dir.
	// Deliberately a sibling of the per-device directories, which teardown
	// removes wholesale.
	templatesSubdir = "templates"

	// templateMetaFile records what a template is and where its CONFIG
	// partition sits.
	templateMetaFile = "meta.json"
	// templateDiskFile is the config-independent EVE disk image.
	templateDiskFile = "disk.qcow2"
	// templateConfigImgFile is the pristine /bits/config.img extracted from the
	// EVE container: the 5 MiB FAT image that per-device config is overlaid on.
	templateConfigImgFile = "config.img"
	// templateFirmwareDir holds the UEFI firmware extracted from /bits/firmware.
	templateFirmwareDir = "firmware"
	// templateRefsDir holds one empty marker file per live working copy backed
	// by this template; a template with any refs is never evicted.
	templateRefsDir = "refs"
	// templateTmpPrefix marks an in-progress build, renamed into place on
	// success. Leftovers are swept at broker startup.
	templateTmpPrefix = ".tmp-"
)

// templateKeyParams is everything that makes two template disks differ.
//
// Device configuration is deliberately absent: grub options, global.json,
// certificates and the soft serial all live in the CONFIG partition, which is
// written into the per-device working copy after the fact. Adding any of them
// here would defeat the cache. Platform is absent because the broker never
// passes -p to the EVE container; if that changes, it must be added here.
type templateKeyParams struct {
	DockerImageID string
	DiskBytes     uint64
	Installer     bool
	Arch          api.ArchType
}

// computeTemplateKey derives the cache key. The hash is truncated to 32 hex
// characters: it names a directory, and collisions are not adversarial here.
func computeTemplateKey(p templateKeyParams) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d\n%s\n%d\n%t\n%s\n",
		templateFormatVersion, p.DockerImageID, p.DiskBytes, p.Installer, p.Arch)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// templateMeta is the on-disk description of a built template.
type templateMeta struct {
	FormatVersion int       `json:"formatVersion"`
	Key           string    `json:"key"`
	DockerImageID string    `json:"dockerImageId"`
	DiskBytes     uint64    `json:"diskBytes"`
	Installer     bool      `json:"installer"`
	Arch          string    `json:"arch"`
	ConfigOffset  int64     `json:"configOffset"`
	ConfigLength  int64     `json:"configLength"`
	BuiltAt       time.Time `json:"builtAt"`
	LastUsed      time.Time `json:"lastUsed"`
}

// save writes the metadata into a template directory.
func (m templateMeta) save(dir string) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal template metadata: %w", err)
	}
	path := filepath.Join(dir, templateMetaFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write %q: %w", path, err)
	}
	return nil
}

// loadTemplateMeta reads and validates a template's metadata. Anything
// unreadable, malformed or produced by an older broker is an error, so that
// callers rebuild rather than trust it.
//
// Callers distinguishing "no template yet" from "corrupt template" must use
// errors.Is(err, fs.ErrNotExist), NOT os.IsNotExist: the latter only unwraps
// *PathError/*LinkError/*SyscallError and so cannot see through the %w wrap
// below.
func loadTemplateMeta(dir string) (templateMeta, error) {
	var m templateMeta
	path := filepath.Join(dir, templateMetaFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return m, fmt.Errorf("failed to read %q: %w", path, err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("failed to parse %q: %w", path, err)
	}
	if m.FormatVersion != templateFormatVersion {
		return m, fmt.Errorf("template %q has format version %d, want %d",
			dir, m.FormatVersion, templateFormatVersion)
	}
	if m.ConfigLength <= 0 {
		return m, fmt.Errorf("template %q records a non-positive CONFIG length %d",
			dir, m.ConfigLength)
	}
	return m, nil
}

// templateRef points at an installed template directory.
type templateRef struct {
	Key  string
	Dir  string
	Meta templateMeta
}

func (t *templateRef) diskPath() string      { return filepath.Join(t.Dir, templateDiskFile) }
func (t *templateRef) configImgPath() string { return filepath.Join(t.Dir, templateConfigImgFile) }
func (t *templateRef) firmwareDir() string   { return filepath.Join(t.Dir, templateFirmwareDir) }
func (t *templateRef) refsDir() string       { return filepath.Join(t.Dir, templateRefsDir) }

// configPartition returns where the CONFIG partition sits inside the template
// disk, as recorded at build time.
func (t *templateRef) configPartition() gptPartition {
	return gptPartition{Offset: t.Meta.ConfigOffset, Length: t.Meta.ConfigLength}
}

// templateBuilder populates dstDir with templateDiskFile, templateConfigImgFile
// and templateFirmwareDir, and returns where the CONFIG partition sits inside
// the disk it produced.
type templateBuilder func(
	ctx context.Context, log *logrus.Entry, dstDir string) (gptPartition, error)

// templateCache stores config-independent EVE disk images, keyed by
// computeTemplateKey, so the expensive EVE container build runs once per
// distinct image rather than once per device.
type templateCache struct {
	dir string
	log *logrus.Logger

	// imageDir is the parent of dir; the ownership lock lives there because
	// dir may not exist yet.
	imageDir string
	// owner is true when this process holds the exclusive lock on imageDir and
	// may therefore do housekeeping (clearing stale refs, evicting templates).
	// A second broker sharing the directory runs with owner false: it still
	// reads and creates templates, but must never delete anything, or it can
	// pull a backing file out from under the owner's running VMs. tryLock is
	// only ever attempted once (from newBroker), so if the owning broker exits,
	// a non-owner never becomes owner and housekeeping stays off for the
	// lifetime of this process.
	owner    bool
	lockFile *os.File

	// mutex protects inFlight and serializes cache lookups. It is never held
	// while a build runs.
	mutex    sync.Mutex
	inFlight map[string]*templateBuildState
}

// templateBuildState lets concurrent callers wanting the same template wait on
// one build instead of each starting their own.
type templateBuildState struct {
	done chan struct{}
	ref  *templateRef
	err  error
}

func newTemplateCache(imageDir string, log *logrus.Logger) *templateCache {
	return &templateCache{
		dir:      filepath.Join(imageDir, templatesSubdir),
		log:      log,
		imageDir: imageDir,
		inFlight: make(map[string]*templateBuildState),
	}
}

// templateDir is where the template for a key lives once installed.
func (c *templateCache) templateDir(key string) string {
	return filepath.Join(c.dir, key)
}

// waiterLogInterval is how often a caller waiting on someone else's in-flight
// template build logs, so a long wait (builds can take most of
// brokerBuildImageTimeout) is not mistaken for a hang.
const waiterLogInterval = 30 * time.Second

// ensureTemplate returns the template for params, building it with build if it
// is not already cached. Concurrent callers for the same key share one build.
func (c *templateCache) ensureTemplate(ctx context.Context, log *logrus.Entry,
	params templateKeyParams, build templateBuilder) (*templateRef, error) {
	return c.ensureTemplateAttempt(ctx, log, params, build, 0)
}

// ensureTemplateAttempt is ensureTemplate's body. attempt distinguishes a
// waiter's one allowed retry (see below) from the original call, and is
// always 0 from ensureTemplate; it must never be threaded any further so the
// retry cannot recurse more than once.
func (c *templateCache) ensureTemplateAttempt(ctx context.Context, log *logrus.Entry,
	params templateKeyParams, build templateBuilder, attempt int) (*templateRef, error) {

	key := computeTemplateKey(params)

	c.mutex.Lock()
	if ref, ok := c.loadInstalled(log, key); ok {
		c.mutex.Unlock()
		log.Infof("Reusing cached EVE image template %q", key)
		return ref, nil
	}
	if state, building := c.inFlight[key]; building {
		c.mutex.Unlock()
		log.Infof("Waiting for an in-progress build of EVE image template %q", key)
		ticker := time.NewTicker(waiterLogInterval)
		defer ticker.Stop()
		for {
			select {
			case <-state.done:
				if state.err != nil && attempt == 0 {
					// The client that started this build failed or disconnected; that
					// is not this caller's failure. Retry once as a fresh caller rather
					// than propagating an error that has nothing to do with this request.
					log.Warnf("The in-progress build of EVE image template %q this call was "+
						"waiting on failed for the client that started it (%v); retrying once",
						key, state.err)
					return c.ensureTemplateAttempt(ctx, log, params, build, attempt+1)
				}
				return state.ref, state.err
			case <-ticker.C:
				log.Infof("Still waiting for an in-progress build of EVE image template %q", key)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	state := &templateBuildState{done: make(chan struct{})}
	c.inFlight[key] = state
	c.mutex.Unlock()

	if !c.owner {
		log.Warnf("This broker does not own the image directory %q and will not clear "+
			"stale references or evict templates; building without housekeeping", c.imageDir)
	}
	log.Infof("Building EVE image template %q", key)
	state.ref, state.err = c.buildAndInstall(ctx, log, key, params, build)

	c.mutex.Lock()
	delete(c.inFlight, key)
	c.mutex.Unlock()
	close(state.done)

	return state.ref, state.err
}

// loadInstalled returns an already-installed template, or false if it is
// absent, incomplete or unreadable. Callers must hold c.mutex.
func (c *templateCache) loadInstalled(log *logrus.Entry, key string) (*templateRef, bool) {
	dir := c.templateDir(key)
	meta, err := loadTemplateMeta(dir)
	if err != nil {
		// errors.Is, not os.IsNotExist: loadTemplateMeta wraps os.ReadFile's
		// error with %w, which os.IsNotExist cannot see through.
		if !errors.Is(err, fs.ErrNotExist) {
			c.discardUnusable(log, key, err.Error())
		}
		return nil, false
	}
	ref := &templateRef{Key: key, Dir: dir, Meta: meta}
	for _, p := range []string{ref.diskPath(), ref.configImgPath(), ref.firmwareDir()} {
		if _, err := os.Stat(p); err != nil {
			c.discardUnusable(log, key, fmt.Sprintf("incomplete: %v", err))
			return nil, false
		}
	}
	meta.LastUsed = time.Now()
	if err := meta.save(dir); err != nil {
		log.Warnf("Failed to record last-used time for template %q: %v", key, err)
	}
	ref.Meta = meta
	return ref, true
}

// discardUnusable removes a template that cannot be used, unless doing so would
// be unsafe: a template with live references may still back a running VM, and a
// non-owner broker must never delete anything. In those cases it is left in
// place and the caller rebuilds instead.
func (c *templateCache) discardUnusable(log *logrus.Entry, key, reason string) {
	if !c.owner {
		log.Warnf("EVE image template %q is unusable (%s) but this broker does not own "+
			"the image directory; leaving it in place", key, reason)
		return
	}
	if c.hasRefs(key) {
		log.Warnf("EVE image template %q is unusable (%s) but is still referenced by a "+
			"working copy; leaving it in place", key, reason)
		return
	}
	dir := c.templateDir(key)
	if err := os.RemoveAll(dir); err != nil {
		log.Warnf("Failed to remove unusable template %q: %v", dir, err)
		return
	}
	log.Infof("Removed unusable EVE image template %q (%s)", key, reason)
}

// buildAndInstall builds into a temporary directory and renames it into place,
// so a partially built template is never visible to another caller or to a
// later broker run.
func (c *templateCache) buildAndInstall(ctx context.Context, log *logrus.Entry,
	key string, params templateKeyParams, build templateBuilder) (*templateRef, error) {

	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create template dir %q: %w", c.dir, err)
	}
	tmpDir := filepath.Join(c.dir, fmt.Sprintf("%s%s-%d", templateTmpPrefix, key, rand.Uint32()))
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create temp template dir %q: %w", tmpDir, err)
	}
	installed := false
	defer func() {
		if !installed {
			if err := os.RemoveAll(tmpDir); err != nil {
				log.Warnf("Failed to remove temp template dir %q: %v", tmpDir, err)
			}
		}
	}()

	configPart, err := build(ctx, log, tmpDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, templateRefsDir), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create refs dir: %w", err)
	}
	now := time.Now()
	meta := templateMeta{
		FormatVersion: templateFormatVersion,
		Key:           key,
		DockerImageID: params.DockerImageID,
		DiskBytes:     params.DiskBytes,
		Installer:     params.Installer,
		Arch:          params.Arch.String(),
		ConfigOffset:  configPart.Offset,
		ConfigLength:  configPart.Length,
		BuiltAt:       now,
		LastUsed:      now,
	}
	if err := meta.save(tmpDir); err != nil {
		return nil, err
	}

	dstDir := c.templateDir(key)
	if err := os.Rename(tmpDir, dstDir); err != nil {
		// A non-empty destination means another broker sharing this image
		// directory installed this key first. Its template is complete and may
		// already back a running VM, so adopt it and let the deferred cleanup
		// discard ours. Never RemoveAll the destination to make room: that
		// would delete a template out from under the other broker.
		if !errors.Is(err, fs.ErrExist) && !errors.Is(err, syscall.ENOTEMPTY) {
			return nil, fmt.Errorf("failed to install template into %q: %w", dstDir, err)
		}
		c.mutex.Lock()
		ref, ok := c.loadInstalled(log, key)
		c.mutex.Unlock()
		if !ok {
			return nil, fmt.Errorf(
				"template %q already exists but is unusable and cannot be replaced "+
					"(it may still back a running VM)", key)
		}
		log.Infof("Adopted concurrently installed EVE image template %q", key)
		return ref, nil
	}
	installed = true
	log.Infof("Built EVE image template %q at %q", key, dstDir)
	return &templateRef{Key: key, Dir: dstDir, Meta: meta}, nil
}

// removeStaleTmpDirs deletes in-progress template builds left behind by a
// killed broker. Called once at startup. A non-owner broker must skip this:
// the .tmp-* directories it would sweep may belong to another broker's build
// currently in progress, not to a killed one.
func (c *templateCache) removeStaleTmpDirs() error {
	if !c.owner {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read template dir %q: %w", c.dir, err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), templateTmpPrefix) {
			continue
		}
		path := filepath.Join(c.dir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			c.log.Warnf("Failed to remove stale temp template dir %q: %v", path, err)
			continue
		}
		c.log.Infof("Removed stale temp template dir %q", path)
	}
	return nil
}

// templateLockFile is the per-image-directory ownership lock. Exactly one
// broker may do template housekeeping for a given image directory.
const templateLockFile = "broker.lock"

// tryLock attempts to claim exclusive ownership of the image directory. Failing
// to acquire the lock is not an error: the broker runs on without housekeeping.
// The returned error covers only failures to attempt the lock at all.
func (c *templateCache) tryLock() error {
	if err := os.MkdirAll(c.imageDir, 0o755); err != nil {
		return fmt.Errorf("failed to create image dir %q: %w", c.imageDir, err)
	}
	path := filepath.Join(c.imageDir, templateLockFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		c.log.Warnf("Another broker owns the image directory %q: this broker will "+
			"use templates but will not clear stale references or evict them. "+
			"To run brokers in parallel, give each its own %s.",
			c.imageDir, constants.BrokerImageDirEnv)
		return nil
	}
	c.lockFile = f
	c.owner = true
	return nil
}

// unlock releases the ownership lock.
func (c *templateCache) unlock() {
	if c.lockFile == nil {
		return
	}
	if err := c.lockFile.Close(); err != nil {
		c.log.Warnf("Failed to release the image directory lock: %v", err)
	}
	c.lockFile = nil
	c.owner = false
}

// validRefName rejects names that are not a single path element, so a
// client-supplied device name cannot escape the refs directory.
func validRefName(refName string) error {
	if refName == "" || refName != filepath.Base(refName) || refName == "." || refName == ".." {
		return fmt.Errorf("invalid template ref name %q", refName)
	}
	return nil
}

// addRef records that a live working copy is backed by this template. A
// template with any refs is never evicted. The template must already exist:
// otherwise this would create a bare refs directory that no template ever
// occupies, which candidates() would then skip forever as a permanent leak.
func (c *templateCache) addRef(key, refName string) error {
	if err := validRefName(refName); err != nil {
		return err
	}
	templateDir := c.templateDir(key)
	if _, err := os.Stat(templateDir); err != nil {
		return fmt.Errorf("failed to add ref: template %q: %w", key, err)
	}
	dir := filepath.Join(templateDir, templateRefsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create refs dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, refName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return fmt.Errorf("failed to write template ref %q: %w", path, err)
	}
	return nil
}

// removeRef releases a working copy's hold on a template. It is idempotent:
// teardown runs on paths where the working copy may never have been created.
func (c *templateCache) removeRef(key, refName string) error {
	if err := validRefName(refName); err != nil {
		return err
	}
	path := filepath.Join(c.templateDir(key), templateRefsDir, refName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove template ref %q: %w", path, err)
	}
	return nil
}

// hasRefs reports whether any working copy still depends on this template. An
// unreadable refs dir is reported as referenced, so an I/O problem can never
// cause a template to be deleted out from under a running VM.
func (c *templateCache) hasRefs(key string) bool {
	dir := filepath.Join(c.templateDir(key), templateRefsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return !os.IsNotExist(err)
	}
	return len(entries) > 0
}

// clearAllRefs drops every ref marker. Called once at broker startup: client
// sessions do not survive a restart, so all markers are stale and would
// otherwise pin their templates forever. A non-owner broker must skip this:
// the refs it would clear belong to the owner's live VMs.
//
// This guarantees no *harness-managed* VM ever loses its backing file, not an
// absolute one: libvirt domains do survive a broker restart, and the provider
// does no startup reconciliation against them, so an orphaned domain (e.g. one
// left behind by a failed teardown) can have its template evicted out from
// under it after a restart. That domain is already unmanaged by this point,
// so this is not a regression to fix here.
func (c *templateCache) clearAllRefs() error {
	if !c.owner {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read template dir %q: %w", c.dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), templateTmpPrefix) {
			continue
		}
		refsDir := filepath.Join(c.dir, e.Name(), templateRefsDir)
		refs, err := os.ReadDir(refsDir)
		if err != nil {
			continue
		}
		for _, r := range refs {
			path := filepath.Join(refsDir, r.Name())
			if err := os.Remove(path); err != nil {
				c.log.Warnf("Failed to clear stale template ref %q: %v", path, err)
				continue
			}
			c.log.Infof("Cleared stale template ref %q", path)
		}
	}
	return nil
}

// candidates lists templates eligible for eviction: installed, readable and
// unreferenced. imageCandidate is reused so the age and disk-pressure
// selection helpers in imagecleanup.go serve both docker images and templates.
// A non-owner broker never offers candidates: only the owner evicts.
func (c *templateCache) candidates() []imageCandidate {
	if !c.owner {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			c.log.Warnf("Template cleanup: failed to read %q: %v", c.dir, err)
		}
		return nil
	}
	var out []imageCandidate
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), templateTmpPrefix) {
			continue
		}
		key := e.Name()
		if c.hasRefs(key) {
			continue
		}
		meta, err := loadTemplateMeta(c.templateDir(key))
		if err != nil {
			continue
		}
		out = append(out, imageCandidate{ID: key, Name: key, LastUsed: meta.LastUsed})
	}
	return out
}

// evict deletes a template directory.
//
// It re-checks the reference count rather than trusting the caller: candidates()
// returns a snapshot, and a client can acquire a reference after that snapshot
// while the sweep is still running. It also re-checks ownership so the
// non-owner guarantee does not depend on candidates() being the only entry point.
func (c *templateCache) evict(key string) error {
	if !c.owner {
		return nil
	}
	if c.hasRefs(key) {
		c.log.Infof("Template cleanup: %q acquired a reference during the sweep; keeping it", key)
		return nil
	}
	dir := c.templateDir(key)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove template %q: %w", dir, err)
	}
	return nil
}
