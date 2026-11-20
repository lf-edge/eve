// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/moby/moby/client"
)

const (
	// imageCleanupInterval is how often the broker checks for old/unused
	// Docker images to remove. Not user-configurable, unlike the age and
	// disk-usage thresholds below.
	imageCleanupInterval = 30 * time.Minute

	// imageUsageStateFile is the name of the JSON file (stored under the
	// broker's image directory) persisting per-image last-used timestamps
	// across broker/VM restarts.
	imageUsageStateFile = "docker-image-usage.json"
)

// imageUsageTracker persists a last-used timestamp per Docker image name, so
// the periodic cleanup below can tell how long an image has been unused even
// across broker restarts (the broker VM reboots, or the container itself is
// restarted).
type imageUsageTracker struct {
	mutex    sync.Mutex
	path     string
	lastUsed map[string]time.Time
}

// newImageUsageTracker loads any previously persisted usage state from
// imageDir. A missing or corrupt file just starts empty -- this is a
// best-effort optimization, not critical state.
func newImageUsageTracker(imageDir string) *imageUsageTracker {
	t := &imageUsageTracker{
		path:     filepath.Join(imageDir, imageUsageStateFile),
		lastUsed: make(map[string]time.Time),
	}
	if data, err := os.ReadFile(t.path); err == nil {
		_ = json.Unmarshal(data, &t.lastUsed)
	}
	return t
}

// touch records that imageName was just used (pulled, or confirmed already
// present), resetting its age for the purposes of the retention-based
// cleanup below.
func (t *imageUsageTracker) touch(imageName string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.lastUsed[imageName] = time.Now()
	t.saveLocked()
}

func (t *imageUsageTracker) get(imageName string) (time.Time, bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	ts, ok := t.lastUsed[imageName]
	return ts, ok
}

// remove drops imageName's usage record, e.g. once the image itself has been
// evicted -- otherwise the persisted state grows indefinitely, since image
// names normally include a version tag and a new one appears for every EVE/SDN
// version ever pulled.
func (t *imageUsageTracker) remove(imageName string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	delete(t.lastUsed, imageName)
	t.saveLocked()
}

// prune drops the usage records, last updated before listedAt, of images not
// in present (the local image store as listed at listedAt): images removed
// outside the broker, or whose removal failed to drop the record. Records
// updated since then may belong to images loaded after the listing.
func (t *imageUsageTracker) prune(present map[string]struct{}, listedAt time.Time) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	changed := false
	for name, ts := range t.lastUsed {
		if _, ok := present[name]; !ok && ts.Before(listedAt) {
			delete(t.lastUsed, name)
			changed = true
		}
	}
	if changed {
		t.saveLocked()
	}
}

func (t *imageUsageTracker) saveLocked() {
	data, err := json.Marshal(t.lastUsed)
	if err != nil {
		return
	}
	_ = os.WriteFile(t.path, data, 0o600)
}

// imageCandidate is a local Docker image not currently referenced by any
// container (running or stopped) and with a recorded usage entry (i.e. this
// broker itself pulled/built/confirmed it at some point), and therefore
// eligible for cleanup. An image the broker never touched is never a
// candidate, no matter how old or unused it looks -- see cleanupDockerImages.
type imageCandidate struct {
	// ID is the image's content-addressable ID.
	ID string
	// Refs are the references the image is removed by: all its tags, or just
	// its ID if it has none. Removing by ID fails while more than one tag
	// points at the image, whereas removing each tag in turn untags it and
	// deletes it with the last one.
	Refs []string
	// Name is a human-readable reference (first RepoTag, or the ID) for logging.
	Name string
	// LastUsed is the latest usage recorded for any of Refs.
	LastUsed time.Time
}

// newImageCandidate returns the cleanup candidate for an unused local image,
// or false if the broker never recorded a use of any of its references.
// Every tag of a candidate is removed with it, including tags the broker did
// not record itself: they are only other names for an image the broker
// pulled, built or loaded (a loaded image brings along all of its tags).
func newImageCandidate(id string, repoTags []string,
	lastUsed func(name string) (time.Time, bool)) (imageCandidate, bool) {
	c := imageCandidate{ID: id, Refs: repoTags, Name: id}
	if len(repoTags) == 0 {
		c.Refs = []string{id}
	} else {
		c.Name = repoTags[0]
	}
	tracked := false
	for _, ref := range c.Refs {
		if ts, ok := lastUsed(ref); ok {
			tracked = true
			if ts.After(c.LastUsed) {
				c.LastUsed = ts
			}
		}
	}
	return c, tracked
}

// selectAgeExpiredImages returns the IDs of candidates whose LastUsed is
// older than retention -- the normal, always-on age-based sweep.
func selectAgeExpiredImages(candidates []imageCandidate, now time.Time,
	retention time.Duration) []string {
	var ids []string
	for _, c := range candidates {
		if now.Sub(c.LastUsed) >= retention {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// orderImagesOldestFirst returns every candidate's ID sorted by LastUsed,
// oldest first. Used by the disk-pressure sweep, which needs to remove more
// than just the age-expired images: the caller removes them one at a time
// and re-checks real disk usage after each removal, stopping as soon as it's
// no longer needed (removing images has a real, sometimes slow, side effect,
// so that loop lives in the caller, not here).
func orderImagesOldestFirst(candidates []imageCandidate) []string {
	sorted := make([]imageCandidate, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].LastUsed.Before(sorted[j].LastUsed)
	})
	ids := make([]string, len(sorted))
	for i, c := range sorted {
		ids[i] = c.ID
	}
	return ids
}

// runImageCleanupLoop periodically removes old, unused Docker images so the
// broker VM's disk doesn't fill up with EVE/SDN image versions pulled over
// the lifetime of the broker. Started once from newBroker; runs until the
// broker process exits.
func (b *broker) runImageCleanupLoop() {
	ticker := time.NewTicker(imageCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		b.cleanupDockerImages(context.Background())
		b.cleanupTemplates(context.Background())
	}
}

// cleanupDockerImages runs one cleanup pass: an age-based sweep (always),
// followed by a disk-pressure sweep (only if usage is at or above
// b.diskThresholdPct AND free space is below b.dockerMinFreeGiB, see
// shouldEvict), which keeps removing the oldest remaining unused images,
// rechecking after each one, until either condition stops holding or nothing
// more can be removed.
func (b *broker) cleanupDockerImages(ctx context.Context) {
	log := b.globalLog
	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Warnf("Image cleanup: failed to create docker client: %v", err)
		return
	}

	// An image is "in use" if any container (running or stopped) references
	// it -- this is exactly what protects the broker's own image and the
	// running registry:2 mirror containers' image without any special-casing.
	containers, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		log.Warnf("Image cleanup: failed to list containers: %v", err)
		return
	}
	inUse := make(map[string]struct{}, len(containers.Items))
	for _, c := range containers.Items {
		inUse[c.ImageID] = struct{}{}
	}

	listedAt := time.Now()
	images, err := cli.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		log.Warnf("Image cleanup: failed to list images: %v", err)
		return
	}

	present := make(map[string]struct{})
	byID := make(map[string]imageCandidate, len(images.Items))
	var candidates []imageCandidate
	for _, img := range images.Items {
		present[img.ID] = struct{}{}
		for _, tag := range img.RepoTags {
			present[tag] = struct{}{}
		}
		if _, used := inUse[img.ID]; used {
			continue
		}
		// Only images this broker itself pulled/built/confirmed via
		// BuildImage/PushEVEContainerImage/SetupDevices are ever eligible for
		// cleanup. An image that was never touched by the broker must never be removed,
		// regardless of age or disk pressure.
		c, ok := newImageCandidate(img.ID, img.RepoTags, b.imageUsage.get)
		if !ok {
			continue
		}
		byID[img.ID] = c
		candidates = append(candidates, c)
	}
	b.imageUsage.prune(present, listedAt)

	evict := func(id, reason string) bool {
		c := byID[id]
		for _, ref := range c.Refs {
			if _, err := cli.ImageRemove(ctx, ref, client.ImageRemoveOptions{}); err != nil {
				log.Warnf("Image cleanup: failed to remove image %q: %v", ref, err)
				return false
			}
			b.imageUsage.remove(ref)
		}
		log.Infof("Image cleanup: removed unused image %q (%s)", c.Name, reason)
		return true
	}

	ageExpired := selectAgeExpiredImages(candidates, time.Now(), b.imgRetention)
	evicted := make(map[string]struct{}, len(ageExpired))
	for _, id := range ageExpired {
		if evict(id, "age") {
			evicted[id] = struct{}{}
		}
	}

	usage, dockerRoot, err := b.dockerDiskUsage(ctx, cli)
	if err != nil {
		log.Warnf("Image cleanup: failed to check disk usage: %v", err)
		return
	}
	if !shouldEvict(usage, b.diskThresholdPct, b.dockerMinFreeGiB) {
		return
	}
	log.Warnf("Image cleanup: disk usage at %d%% on %s (threshold %d%%) and "+
		"available space %.1f GiB (floor %d GiB), evicting oldest unused images",
		usage.UsedPct, dockerRoot, b.diskThresholdPct,
		usage.freeGiB(), b.dockerMinFreeGiB)

	var remaining []imageCandidate
	for _, c := range candidates {
		if _, done := evicted[c.ID]; !done {
			remaining = append(remaining, c)
		}
	}
	err = evictWhilePressured(orderImagesOldestFirst(remaining),
		func(id string) { evict(id, "disk pressure") },
		func() (diskUsage, error) {
			u, _, err := b.dockerDiskUsage(ctx, cli)
			return u, err
		},
		func(u diskUsage) bool {
			return shouldEvict(u, b.diskThresholdPct, b.dockerMinFreeGiB)
		})
	if err != nil {
		log.Warnf("Image cleanup: failed to re-check disk usage: %v", err)
	}
}

// dockerDiskUsage returns the current disk usage of the
// filesystem backing Docker's actual storage directory. It asks Docker
// itself for that directory (DockerRootDir, from `docker info`) rather than
// assuming a fixed path like /var/lib/docker, since it can be customized via
// the daemon's data-root setting.
func (b *broker) dockerDiskUsage(ctx context.Context, cli *client.Client) (
	usage diskUsage, dockerRoot string, err error) {
	info, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		err = fmt.Errorf("failed to query docker info: %w", err)
		return diskUsage{}, "", err
	}
	dockerRoot = info.Info.DockerRootDir
	if dockerRoot == "" {
		err = fmt.Errorf("docker did not report its root directory")
		return diskUsage{}, "", err
	}
	usage, err = statDiskUsage(dockerRoot)
	return usage, dockerRoot, err
}

// diskUsage is the result of one statfs call on a filesystem.
type diskUsage struct {
	// UsedPct is the used-space percentage, 0-100.
	UsedPct int
	// FreeBytes is the space available to unprivileged users, in bytes.
	FreeBytes uint64
	// TotalBytes is the total size of the filesystem, in bytes.
	TotalBytes uint64
}

const bytesPerGiB = 1 << 30

func (u diskUsage) freeGiB() float64 {
	return float64(u.FreeBytes) / bytesPerGiB
}

// shouldEvict reports whether disk pressure justifies evicting images or
// templates: usage must be at or above thresholdPct AND free space must be
// below minFreeGiB. A big disk can sit above a percentage threshold while
// still having hundreds of GiB free, which is no reason to evict. A
// non-positive minFreeGiB disables the free-space floor, leaving the
// percentage as the only trigger.
func shouldEvict(u diskUsage, thresholdPct, minFreeGiB int) bool {
	if u.UsedPct < thresholdPct {
		return false
	}
	if minFreeGiB <= 0 {
		return true
	}
	return u.FreeBytes < uint64(minFreeGiB)*bytesPerGiB
}

// evictWhilePressured evicts ids in order, re-reading disk usage after each
// eviction, and stops as soon as pressured reports false (either the
// percentage or the free-space condition cleared), when ids run out, or when
// usage cannot be read (the error is returned).
func evictWhilePressured(ids []string, evict func(id string),
	usage func() (diskUsage, error), pressured func(diskUsage) bool) error {
	for _, id := range ids {
		evict(id)
		u, err := usage()
		if err != nil {
			return err
		}
		if !pressured(u) {
			return nil
		}
	}
	return nil
}

// statDiskUsage returns the used percentage and free bytes of the filesystem
// backing path, from a single statfs call.
func statDiskUsage(path string) (diskUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskUsage{}, fmt.Errorf("failed to stat %q: %w", path, err)
	}
	// Block counts are in units of f_frsize per POSIX; older filesystems
	// may leave it 0, in which case f_bsize is the best available unit.
	bsize := uint64(stat.Frsize) //nolint:unconvert
	if bsize == 0 {
		bsize = uint64(stat.Bsize) //nolint:unconvert
	}
	total := stat.Blocks * bsize
	if total == 0 {
		return diskUsage{}, fmt.Errorf("statfs reported zero total blocks for %q", path)
	}
	// Percentage is computed from Bfree (like df's used column); the free
	// space reported is Bavail, what an unprivileged writer can really use.
	used := total - stat.Bfree*bsize
	return diskUsage{
		UsedPct:    int(used * 100 / total),
		FreeBytes:  stat.Bavail * bsize,
		TotalBytes: total,
	}, nil
}

// cleanupTemplates runs one template cleanup pass, mirroring
// cleanupDockerImages: an age-based sweep (skipped when b.tmplRetention is
// non-positive, an explicit "disable age-based eviction"), then a
// disk-pressure sweep that removes the oldest remaining templates until usage
// is back under the threshold or free space is back above the floor (see
// shouldEvict) -- run regardless of b.tmplRetention, since a
// disabled age sweep must not also disable the broker's only protection
// against filling the disk. Templates still referenced by a live working copy
// are never candidates.
func (b *broker) cleanupTemplates(_ context.Context) {
	log := b.globalLog
	if b.templates == nil {
		return
	}
	candidates := b.templates.candidates()
	if len(candidates) == 0 {
		return
	}

	evict := func(key, reason string) bool {
		if err := b.templates.evict(key); err != nil {
			log.Warnf("Template cleanup: %v", err)
			return false
		}
		log.Infof("Template cleanup: removed unused template %q (%s)", key, reason)
		return true
	}

	evicted := make(map[string]struct{})
	if b.tmplRetention > 0 {
		ageExpired := selectAgeExpiredImages(candidates, time.Now(), b.tmplRetention)
		for _, key := range ageExpired {
			if evict(key, "age") {
				evicted[key] = struct{}{}
			}
		}
	}

	usage, err := b.imageDirUsage()
	if err != nil {
		log.Warnf("Template cleanup: failed to check disk usage: %v", err)
		return
	}
	if !shouldEvict(usage, b.tmplDiskThresholdPct, b.tmplMinFreeGiB) {
		return
	}
	log.Warnf("Template cleanup: disk usage at %d%% on %s (threshold %d%%) and "+
		"available space %.1f GiB (floor %d GiB), evicting oldest unused templates",
		usage.UsedPct, b.imageDir, b.tmplDiskThresholdPct,
		usage.freeGiB(), b.tmplMinFreeGiB)

	var remaining []imageCandidate
	for _, c := range candidates {
		if _, done := evicted[c.ID]; !done {
			remaining = append(remaining, c)
		}
	}
	err = evictWhilePressured(orderImagesOldestFirst(remaining),
		func(key string) { evict(key, "disk pressure") },
		b.imageDirUsage,
		func(u diskUsage) bool {
			return shouldEvict(u, b.tmplDiskThresholdPct, b.tmplMinFreeGiB)
		})
	if err != nil {
		log.Warnf("Template cleanup: failed to re-check disk usage: %v", err)
	}
}

// imageDirUsage returns the disk usage of the filesystem
// backing the broker's image directory, which is where templates and working
// copies live -- not necessarily the same filesystem as Docker's storage.
func (b *broker) imageDirUsage() (diskUsage, error) {
	return statDiskUsage(b.imageDir)
}
