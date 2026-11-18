// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	appsv1 "k8s.io/api/apps/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const (
	longhornManagerDaemonSet   = "longhorn-manager"
	longhornCSIPluginDaemonSet = "longhorn-csi-plugin"
	longhornEngineImagePrefix  = "engine-image-"
	longhornCRDGroup           = "longhorn.io"
	longhornRemovedAPIVersion  = "v1beta1"
	longhornVersionCheckArg    = "--upgrade-version-check"
)

// longhornUpgradeStep is one upgrade wider than a single minor version
// that longhorn-manager refuses on its own.
type longhornUpgradeStep struct {
	from, to string
}

// validatedLonghornLargeSteps lists the large steps this build may take.
// Longhorn only supports and tests upgrades of one minor version, so each
// entry needs its own validation, recorded in the commit that adds it.
// Source and destination are exact versions, never ranges.
var validatedLonghornLargeSteps = []longhornUpgradeStep{}

// longhornUpgradeAllowed decides whether Longhorn may be upgraded from
// sourceVer to destVer. It mirrors longhorn-manager's own rule (same major
// version, at most one minor version up, no downgrade) and additionally
// accepts the validated large steps, for which it returns largeStep true.
func longhornUpgradeAllowed(sourceVer, destVer string,
	largeSteps []longhornUpgradeStep) (largeStep bool, err error) {
	src, err := semver.NewVersion(sourceVer)
	if err != nil {
		return false, fmt.Errorf("installed version %q: %w", sourceVer, err)
	}
	dst, err := semver.NewVersion(destVer)
	if err != nil {
		return false, fmt.Errorf("target version %q: %w", destVer, err)
	}
	if dst.LessThan(src) {
		return false, fmt.Errorf("downgrade %s -> %s is not supported",
			sourceVer, destVer)
	}
	if src.Major() == dst.Major() && dst.Minor()-src.Minor() <= 1 {
		return false, nil
	}
	for _, step := range largeSteps {
		if step.from == sourceVer && step.to == destVer {
			return true, nil
		}
	}
	return false, fmt.Errorf("no supported upgrade path %s -> %s: Longhorn "+
		"upgrades one minor version at a time and this pair is not a "+
		"validated large step", sourceVer, destVer)
}

// longhornLeavesRemovedAPI reports whether the upgrade crosses v1.10, the
// release that stops serving the v1beta1 API.
func longhornLeavesRemovedAPI(sourceVer, destVer string) bool {
	src, err := semver.NewVersion(sourceVer)
	if err != nil {
		return false
	}
	dst, err := semver.NewVersion(destVer)
	if err != nil {
		return false
	}
	firstWithout := semver.MustParse("v1.10.0")
	return src.LessThan(firstWithout) && !dst.LessThan(firstWithout)
}

// checkLonghornStoredVersions fails if any Longhorn CRD still lists the
// removed API version among its stored versions. The API server rejects a
// CRD update that drops such a version, which would leave Longhorn half
// upgraded.
func checkLonghornStoredVersions(crds []apiextensionsv1.CustomResourceDefinition) error {
	var stale []string
	for _, crd := range crds {
		if crd.Spec.Group != longhornCRDGroup {
			continue
		}
		for _, v := range crd.Status.StoredVersions {
			if v == longhornRemovedAPIVersion {
				stale = append(stale, crd.Name)
			}
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("CRDs still store %s objects: %s",
			longhornRemovedAPIVersion, strings.Join(stale, ", "))
	}
	return nil
}

// checkLonghornVolumesNotFaulted fails if any volume is faulted. Longhorn
// documents this as a precondition of every upgrade.
func checkLonghornVolumesNotFaulted(volumes []v1beta2.Volume) error {
	var faulted []string
	for _, vol := range volumes {
		if vol.Status.Robustness == v1beta2.VolumeRobustnessFaulted {
			faulted = append(faulted, vol.Name)
		}
	}
	if len(faulted) > 0 {
		return fmt.Errorf("faulted volumes: %s", strings.Join(faulted, ", "))
	}
	return nil
}

// checkLonghornEngineImagesAt fails if an engine image still in use is not
// at version. A large step disables longhorn-manager's own engine
// compatibility check, so this takes its place.
func checkLonghornEngineImagesAt(images []v1beta2.EngineImage, version string) error {
	var other []string
	for _, ei := range images {
		if ei.Status.RefCount > 0 && !strings.HasSuffix(ei.Spec.Image, ":"+version) {
			other = append(other, ei.Spec.Image)
		}
	}
	if len(other) > 0 {
		return fmt.Errorf("engine images in use are not at %s: %s",
			version, strings.Join(other, ", "))
	}
	return nil
}

// longhornServerTooOld reports whether a Kubernetes server at major.minor
// is older than the minimum the target Longhorn version documents.
// Longhorn does not enforce that minimum itself.
func longhornServerTooOld(destVer, serverMajor, serverMinor string) (bool, string) {
	dst, err := semver.NewVersion(destVer)
	if err != nil || dst.LessThan(semver.MustParse("v1.13.0")) {
		return false, ""
	}
	const minimum = "v1.34.0"
	server, err := semver.NewVersion(fmt.Sprintf("v%s.%s.0", serverMajor,
		strings.TrimRight(serverMinor, "+")))
	if err != nil {
		return false, ""
	}
	return server.LessThan(semver.MustParse(minimum)), minimum
}

// checkLonghornDaemonSetsReady verifies the DaemonSets Longhorn needs at
// version: the manager at that version, the CSI plugin, and the engine
// image of that version. Other engine-image DaemonSets are ignored: during
// an upgrade the previous engine image keeps its own until Longhorn expires
// it, an hour after its last use.
func checkLonghornDaemonSetsReady(daemonSets []appsv1.DaemonSet, version string) error {
	ready := func(ds *appsv1.DaemonSet) bool {
		return ds.Status.DesiredNumberScheduled > 0 &&
			ds.Status.NumberReady == ds.Status.DesiredNumberScheduled
	}
	var manager, csiPlugin, engineImage *appsv1.DaemonSet
	for i := range daemonSets {
		ds := &daemonSets[i]
		switch {
		case ds.Name == longhornManagerDaemonSet:
			manager = ds
		case ds.Name == longhornCSIPluginDaemonSet:
			csiPlugin = ds
		case strings.HasPrefix(ds.Name, longhornEngineImagePrefix):
			for _, c := range ds.Spec.Template.Spec.Containers {
				if strings.HasSuffix(c.Image, ":"+version) {
					engineImage = ds
				}
			}
		}
	}
	switch {
	case manager == nil:
		return errors.New("longhorn-manager daemonset not found")
	case manager.Spec.Template.GetLabels()["app.kubernetes.io/version"] != version:
		return fmt.Errorf("longhorn-manager daemonset version mismatch, running:%s",
			manager.Spec.Template.GetLabels()["app.kubernetes.io/version"])
	case !ready(manager):
		return errors.New("longhorn-manager daemonset is not ready")
	case csiPlugin == nil:
		return errors.New("longhorn-csi-plugin daemonset not found")
	case !ready(csiPlugin):
		return errors.New("longhorn-csi-plugin daemonset is not ready")
	case engineImage == nil:
		return fmt.Errorf("no engine image daemonset for %s", version)
	case !ready(engineImage):
		return fmt.Errorf("engine image daemonset %s is not ready", engineImage.Name)
	}
	return nil
}

var (
	yamlDocSeparator         = regexp.MustCompile(`(?m)^---\s*$`)
	longhornManagerDSKind    = regexp.MustCompile(`(?m)^kind:\s*DaemonSet\s*$`)
	longhornManagerDSName    = regexp.MustCompile(`(?m)^  name:\s*longhorn-manager\s*$`)
	longhornVersionCheckLine = regexp.MustCompile(`(?m)^\s*-\s*` +
		regexp.QuoteMeta(longhornVersionCheckArg) + `\s*\n`)
)

// longhornManagerDocument returns the bounds of the longhorn-manager
// DaemonSet document inside a multi-document manifest.
func longhornManagerDocument(manifest []byte) (start, end int, err error) {
	bounds := []int{0}
	for _, loc := range yamlDocSeparator.FindAllIndex(manifest, -1) {
		bounds = append(bounds, loc[1])
	}
	bounds = append(bounds, len(manifest))
	found := false
	for i := 0; i+1 < len(bounds); i++ {
		doc := manifest[bounds[i]:bounds[i+1]]
		if !longhornManagerDSKind.Match(doc) || !longhornManagerDSName.Match(doc) {
			continue
		}
		if found {
			return 0, 0, errors.New("more than one longhorn-manager daemonset in manifest")
		}
		found = true
		start, end = bounds[i], bounds[i+1]
	}
	if !found {
		return 0, 0, errors.New("no longhorn-manager daemonset in manifest")
	}
	return start, end, nil
}

// longhornManifestHasVersionCheck reports whether the manifest starts
// longhorn-manager with its upgrade version check enabled.
func longhornManifestHasVersionCheck(manifest []byte) (bool, error) {
	start, end, err := longhornManagerDocument(manifest)
	if err != nil {
		return false, err
	}
	return longhornVersionCheckLine.Match(manifest[start:end]), nil
}

// longhornManifestWithoutVersionCheck returns the manifest with the
// upgrade version check argument removed from the longhorn-manager
// DaemonSet and everything else byte for byte unchanged. It fails if the
// argument is not there exactly once, so an upstream change to the
// manifest cannot go unnoticed.
func longhornManifestWithoutVersionCheck(manifest []byte) ([]byte, error) {
	start, end, err := longhornManagerDocument(manifest)
	if err != nil {
		return nil, err
	}
	doc := manifest[start:end]
	locs := longhornVersionCheckLine.FindAllIndex(doc, -1)
	if len(locs) != 1 {
		return nil, fmt.Errorf("expected %s once in the longhorn-manager "+
			"daemonset, found it %d times", longhornVersionCheckArg, len(locs))
	}
	var out bytes.Buffer
	out.Write(manifest[:start+locs[0][0]])
	out.Write(manifest[start+locs[0][1]:])
	return out.Bytes(), nil
}

// longhornVolumesBehind returns the volumes whose engine is not yet running
// the engine image of version.
func longhornVolumesBehind(volumes []v1beta2.Volume, version string) []string {
	var behind []string
	for _, vol := range volumes {
		if !strings.HasSuffix(vol.Spec.Image, ":"+version) ||
			vol.Status.CurrentImage != vol.Spec.Image {
			behind = append(behind, vol.Name)
		}
	}
	return behind
}

// longhornDaemonSetHasVersionCheck reports whether a longhorn-manager
// DaemonSet starts the manager with its upgrade version check enabled.
func longhornDaemonSetHasVersionCheck(ds *appsv1.DaemonSet) bool {
	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, arg := range append(append([]string{}, c.Command...), c.Args...) {
			if arg == longhornVersionCheckArg {
				return true
			}
		}
	}
	return false
}
