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
	data, err := json.Marshal(t.lastUsed)
	if err != nil {
		return
	}
	_ = os.WriteFile(t.path, data, 0o600)
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
	// ID is the image's content-addressable ID, used to actually remove it.
	ID string
	// Name is a human-readable reference (first RepoTag, or the ID) for logging.
	Name     string
	LastUsed time.Time
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
	}
}

// cleanupDockerImages runs one cleanup pass: an age-based sweep (always),
// followed by a disk-pressure sweep (only if usage is at or above
// b.diskThresholdPct), which keeps removing the oldest
// remaining unused images, rechecking usage after each one, until back under
// the threshold or nothing more can be removed.
func (b *broker) cleanupDockerImages(ctx context.Context) {
	log := b.globalLog
	cli, err := client.NewClientWithOpts(client.FromEnv)
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

	images, err := cli.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		log.Warnf("Image cleanup: failed to list images: %v", err)
		return
	}

	names := make(map[string]string, len(images.Items)) // image ID -> display name
	var candidates []imageCandidate
	for _, img := range images.Items {
		if _, used := inUse[img.ID]; used {
			continue
		}
		name := img.ID
		if len(img.RepoTags) > 0 {
			name = img.RepoTags[0]
		}
		// Only images this broker itself pulled/built/confirmed via
		// BuildImage/PushEVEContainerImage/SetupDevices are ever eligible for
		// cleanup. An image that was never touched by the broker must never be removed,
		// regardless of age or disk pressure.
		lastUsed, ok := b.imageUsage.get(name)
		if !ok {
			continue
		}
		names[img.ID] = name
		candidates = append(candidates,
			imageCandidate{ID: img.ID, Name: name, LastUsed: lastUsed})
	}

	evict := func(id, reason string) bool {
		if _, err := cli.ImageRemove(ctx, id, client.ImageRemoveOptions{}); err != nil {
			log.Warnf("Image cleanup: failed to remove image %q: %v", names[id], err)
			return false
		}
		log.Infof("Image cleanup: removed unused image %q (%s)", names[id], reason)
		b.imageUsage.remove(names[id])
		return true
	}

	ageExpired := selectAgeExpiredImages(candidates, time.Now(), b.imgRetention)
	evicted := make(map[string]struct{}, len(ageExpired))
	for _, id := range ageExpired {
		if evict(id, "age") {
			evicted[id] = struct{}{}
		}
	}

	usagePercent, dockerRoot, err := b.dockerDiskUsagePercent(ctx, cli)
	if err != nil {
		log.Warnf("Image cleanup: failed to check disk usage: %v", err)
		return
	}
	if usagePercent < b.diskThresholdPct {
		return
	}
	log.Warnf("Image cleanup: disk usage at %d%% on %s (threshold %d%%), "+
		"evicting oldest unused images",
		usagePercent, dockerRoot, b.diskThresholdPct)

	var remaining []imageCandidate
	for _, c := range candidates {
		if _, done := evicted[c.ID]; !done {
			remaining = append(remaining, c)
		}
	}
	for _, id := range orderImagesOldestFirst(remaining) {
		evict(id, "disk pressure")
		usagePercent, _, err = b.dockerDiskUsagePercent(ctx, cli)
		if err != nil {
			log.Warnf("Image cleanup: failed to re-check disk usage: %v", err)
			return
		}
		if usagePercent < b.diskThresholdPct {
			return
		}
	}
}

// dockerDiskUsagePercent returns the current disk usage percentage of the
// filesystem backing Docker's actual storage directory. It asks Docker
// itself for that directory (DockerRootDir, from `docker info`) rather than
// assuming a fixed path like /var/lib/docker, since it can be customized via
// the daemon's data-root setting.
func (b *broker) dockerDiskUsagePercent(ctx context.Context, cli *client.Client) (
	percent int, dockerRoot string, err error) {
	info, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		err = fmt.Errorf("failed to query docker info: %w", err)
		return 0, "", err
	}
	dockerRoot = info.Info.DockerRootDir
	if dockerRoot == "" {
		err = fmt.Errorf("docker did not report its root directory")
		return 0, "", err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dockerRoot, &stat); err != nil {
		err = fmt.Errorf("failed to stat %q: %w", dockerRoot, err)
		return 0, dockerRoot, err
	}
	total := stat.Blocks * uint64(stat.Bsize) //nolint:unconvert
	free := stat.Bfree * uint64(stat.Bsize)   //nolint:unconvert
	if total == 0 {
		err = fmt.Errorf("statfs reported zero total blocks for %q", dockerRoot)
		return 0, dockerRoot, err
	}
	used := total - free
	return int(used * 100 / total), dockerRoot, nil
}
