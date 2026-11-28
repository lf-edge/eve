// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLonghornUpgradeAllowed(t *testing.T) {
	steps := []longhornUpgradeStep{{from: "v1.9.1", to: "v1.13.0"}}
	cases := []struct {
		name      string
		from, to  string
		steps     []longhornUpgradeStep
		wantLarge bool
		wantErr   bool
	}{
		{name: "same version", from: "v1.9.1", to: "v1.9.1"},
		{name: "patch up", from: "v1.9.1", to: "v1.9.2"},
		{name: "one minor up", from: "v1.9.1", to: "v1.10.2"},
		{name: "two minors up", from: "v1.9.1", to: "v1.11.3", wantErr: true},
		{name: "two minors up, other pair validated", from: "v1.9.1", to: "v1.11.3",
			steps: steps, wantErr: true},
		{name: "validated large step", from: "v1.9.1", to: "v1.13.0",
			steps: steps, wantLarge: true},
		{name: "large step needs the exact source", from: "v1.9.2", to: "v1.13.0",
			steps: steps, wantErr: true},
		{name: "large step needs the exact destination", from: "v1.9.1", to: "v1.13.1",
			steps: steps, wantErr: true},
		{name: "large step without a table", from: "v1.9.1", to: "v1.13.0", wantErr: true},
		{name: "patch down", from: "v1.9.2", to: "v1.9.1", wantErr: true},
		{name: "minor down", from: "v1.10.2", to: "v1.9.1", wantErr: true},
		{name: "major up", from: "v1.13.0", to: "v2.0.0", wantErr: true},
		{name: "unparsable source", from: "", to: "v1.9.1", wantErr: true},
		{name: "unparsable destination", from: "v1.9.1", to: "latest", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			large, err := longhornUpgradeAllowed(tc.from, tc.to, tc.steps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if large != tc.wantLarge {
				t.Fatalf("largeStep = %v, want %v", large, tc.wantLarge)
			}
		})
	}
}

// TestValidatedLonghornLargeSteps keeps the table to what it is for: exact
// pairs that the one-minor rule would refuse.
func TestValidatedLonghornLargeSteps(t *testing.T) {
	for _, step := range validatedLonghornLargeSteps {
		if large, err := longhornUpgradeAllowed(step.from, step.to, nil); err == nil {
			t.Errorf("%s -> %s is allowed without the table (large=%v)",
				step.from, step.to, large)
		}
		if large, err := longhornUpgradeAllowed(step.from, step.to,
			validatedLonghornLargeSteps); err != nil || !large {
			t.Errorf("%s -> %s: large=%v err=%v", step.from, step.to, large, err)
		}
	}
}

func TestLonghornLeavesRemovedAPI(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"v1.9.1", "v1.9.2", false},
		{"v1.9.1", "v1.10.2", true},
		{"v1.9.1", "v1.13.0", true},
		{"v1.10.2", "v1.11.3", false},
	}
	for _, tc := range cases {
		if got := longhornLeavesRemovedAPI(tc.from, tc.to); got != tc.want {
			t.Errorf("%s -> %s: got %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func crd(name, group string, stored ...string) apiextensionsv1.CustomResourceDefinition {
	return apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       apiextensionsv1.CustomResourceDefinitionSpec{Group: group},
		Status:     apiextensionsv1.CustomResourceDefinitionStatus{StoredVersions: stored},
	}
}

func TestCheckLonghornStoredVersions(t *testing.T) {
	clean := []apiextensionsv1.CustomResourceDefinition{
		crd("volumes.longhorn.io", "longhorn.io", "v1beta2"),
		crd("others.example.io", "example.io", "v1beta1"),
	}
	if err := checkLonghornStoredVersions(clean); err != nil {
		t.Fatalf("clean CRDs: %v", err)
	}
	stale := append(clean,
		crd("engines.longhorn.io", "longhorn.io", "v1beta1", "v1beta2"))
	err := checkLonghornStoredVersions(stale)
	if err == nil || !strings.Contains(err.Error(), "engines.longhorn.io") {
		t.Fatalf("stale CRD: err = %v, want it named", err)
	}
	if strings.Contains(err.Error(), "others.example.io") {
		t.Fatalf("a CRD of another group was reported: %v", err)
	}
}

func TestCheckLonghornVolumesNotFaulted(t *testing.T) {
	vol := func(name string, r v1beta2.VolumeRobustness) v1beta2.Volume {
		return v1beta2.Volume{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Status:     v1beta2.VolumeStatus{Robustness: r},
		}
	}
	ok := []v1beta2.Volume{
		vol("a", v1beta2.VolumeRobustnessHealthy),
		vol("b", v1beta2.VolumeRobustnessDegraded),
	}
	if err := checkLonghornVolumesNotFaulted(ok); err != nil {
		t.Fatalf("no faulted volume: %v", err)
	}
	err := checkLonghornVolumesNotFaulted(append(ok, vol("c", v1beta2.VolumeRobustnessFaulted)))
	if err == nil || !strings.Contains(err.Error(), "c") {
		t.Fatalf("faulted volume: err = %v, want it named", err)
	}
}

func TestCheckLonghornEngineImagesAt(t *testing.T) {
	ei := func(image string, refs int) v1beta2.EngineImage {
		return v1beta2.EngineImage{
			Spec:   v1beta2.EngineImageSpec{Image: image},
			Status: v1beta2.EngineImageStatus{RefCount: refs},
		}
	}
	images := []v1beta2.EngineImage{
		ei("longhornio/longhorn-engine:v1.9.1", 3),
		ei("longhornio/longhorn-engine:v1.6.3", 0),
	}
	if err := checkLonghornEngineImagesAt(images, "v1.9.1"); err != nil {
		t.Fatalf("unused old engine image must not block: %v", err)
	}
	images[1].Status.RefCount = 1
	err := checkLonghornEngineImagesAt(images, "v1.9.1")
	if err == nil || !strings.Contains(err.Error(), "v1.6.3") {
		t.Fatalf("engine image in use at another version: err = %v", err)
	}
}

func TestLonghornServerTooOld(t *testing.T) {
	cases := []struct {
		dest, major, minor string
		want               bool
	}{
		{"v1.13.0", "1", "34", false},
		{"v1.13.0", "1", "34+", false},
		{"v1.13.0", "1", "33", true},
		{"v1.13.1", "1", "32+", true},
		{"v1.12.2", "1", "30", false},
		{"v1.13.0", "", "", false},
	}
	for _, tc := range cases {
		if got, _ := longhornServerTooOld(tc.dest, tc.major, tc.minor); got != tc.want {
			t.Errorf("longhorn %s on kubernetes %s.%s: got %v, want %v",
				tc.dest, tc.major, tc.minor, got, tc.want)
		}
	}
}

func daemonSet(name, image, versionLabel string, desired, ready int32) appsv1.DaemonSet {
	ds := appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: desired,
			NumberReady:            ready,
		},
	}
	ds.Spec.Template.Spec.Containers = []corev1.Container{{Image: image}}
	if versionLabel != "" {
		ds.Spec.Template.Labels = map[string]string{
			"app.kubernetes.io/version": versionLabel,
		}
	}
	return ds
}

func TestCheckLonghornDaemonSetsReady(t *testing.T) {
	const old, target = "v1.9.1", "v1.13.0"
	manager := daemonSet("longhorn-manager", "longhornio/longhorn-manager:"+target, target, 3, 3)
	csi := daemonSet("longhorn-csi-plugin", "longhornio/longhorn-manager:"+target, "", 3, 3)
	newEngine := daemonSet("engine-image-ei-new", "longhornio/longhorn-engine:"+target, "", 3, 3)
	oldEngine := daemonSet("engine-image-ei-old", "longhornio/longhorn-engine:"+old, "", 3, 3)

	cases := []struct {
		name    string
		sets    []appsv1.DaemonSet
		wantErr string
	}{
		{name: "converged", sets: []appsv1.DaemonSet{manager, csi, newEngine}},
		{name: "previous engine image still present",
			sets: []appsv1.DaemonSet{manager, csi, oldEngine, newEngine}},
		{name: "previous engine image not ready does not matter",
			sets: []appsv1.DaemonSet{manager, csi, newEngine,
				daemonSet("engine-image-ei-old", "longhornio/longhorn-engine:"+old, "", 3, 1)}},
		{name: "unrelated daemonset does not matter",
			sets: []appsv1.DaemonSet{manager, csi, newEngine,
				daemonSet("something-else", "example/image:1", "", 3, 0)}},
		{name: "target engine image missing",
			sets:    []appsv1.DaemonSet{manager, csi, oldEngine},
			wantErr: "no engine image daemonset"},
		{name: "target engine image not ready",
			sets: []appsv1.DaemonSet{manager, csi,
				daemonSet("engine-image-ei-new", "longhornio/longhorn-engine:"+target, "", 3, 2)},
			wantErr: "engine image daemonset"},
		{name: "manager at the old version",
			sets: []appsv1.DaemonSet{
				daemonSet("longhorn-manager", "longhornio/longhorn-manager:"+old, old, 3, 3),
				csi, newEngine},
			wantErr: "version mismatch"},
		{name: "manager not ready",
			sets: []appsv1.DaemonSet{
				daemonSet("longhorn-manager", "longhornio/longhorn-manager:"+target, target, 3, 2),
				csi, newEngine},
			wantErr: "longhorn-manager daemonset is not ready"},
		{name: "csi plugin missing",
			sets:    []appsv1.DaemonSet{manager, newEngine},
			wantErr: "longhorn-csi-plugin daemonset not found"},
		{name: "nothing scheduled is not ready",
			sets: []appsv1.DaemonSet{manager,
				daemonSet("longhorn-csi-plugin", "x:"+target, "", 0, 0), newEngine},
			wantErr: "longhorn-csi-plugin daemonset is not ready"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLonghornDaemonSetsReady(tc.sets, target)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLonghornVolumesBehind(t *testing.T) {
	vol := func(name, spec, current string) v1beta2.Volume {
		return v1beta2.Volume{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       v1beta2.VolumeSpec{Image: spec},
			Status:     v1beta2.VolumeStatus{CurrentImage: current},
		}
	}
	const oldImg, newImg = "longhornio/longhorn-engine:v1.9.1", "longhornio/longhorn-engine:v1.13.0"
	behind := longhornVolumesBehind([]v1beta2.Volume{
		vol("done", newImg, newImg),
		vol("upgrading", newImg, oldImg),
		vol("untouched", oldImg, oldImg),
	}, "v1.13.0")
	if strings.Join(behind, ",") != "upgrading,untouched" {
		t.Fatalf("behind = %v", behind)
	}
}

// shippedLonghornManifests returns the Longhorn manifests in the kube
// package that the versions file can point the helper at.
func shippedLonghornManifests(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../lh-cfg-*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no Longhorn manifests found: %v", err)
	}
	return paths
}

// TestShippedLonghornManifestsKeepVersionCheck fails if a manifest is
// shipped with longhorn-manager's upgrade version check already removed.
// The check is only ever dropped at apply time, for a validated large step.
func TestShippedLonghornManifestsKeepVersionCheck(t *testing.T) {
	for _, path := range shippedLonghornManifests(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		has, err := longhornManifestHasVersionCheck(data)
		if err != nil {
			t.Errorf("%s: %v", path, err)
		} else if !has {
			t.Errorf("%s: longhorn-manager lacks %s", path, longhornVersionCheckArg)
		}
	}
}

// managerCommand decodes the longhorn-manager DaemonSet of a manifest and
// returns its container command.
func managerCommand(t *testing.T, manifest []byte) []string {
	t.Helper()
	start, end, err := longhornManagerDocument(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var ds struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name    string   `yaml:"name"`
						Command []string `yaml:"command"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifest[start:end], &ds); err != nil {
		t.Fatal(err)
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == longhornManagerDaemonSet {
			return c.Command
		}
	}
	t.Fatal("longhorn-manager daemonset has no longhorn-manager container")
	return nil
}

func TestLonghornManifestWithoutVersionCheck(t *testing.T) {
	for _, path := range shippedLonghornManifests(t) {
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		stripped, err := longhornManifestWithoutVersionCheck(original)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}

		// Exactly one line went, and it was the argument.
		removed := bytes.Count(original, []byte("\n")) - bytes.Count(stripped, []byte("\n"))
		if removed != 1 {
			t.Errorf("%s: %d lines removed, want 1", path, removed)
		}
		if len(original)-len(stripped) > len(longhornVersionCheckArg)+16 {
			t.Errorf("%s: %d bytes removed", path, len(original)-len(stripped))
		}

		before, after := managerCommand(t, original), managerCommand(t, stripped)
		var want []string
		for _, arg := range before {
			if arg != longhornVersionCheckArg {
				want = append(want, arg)
			}
		}
		if len(want) != len(before)-1 {
			t.Fatalf("%s: argument appears %d times in the command", path, len(before)-len(want))
		}
		if strings.Join(after, " ") != strings.Join(want, " ") {
			t.Errorf("%s: command after removal = %v, want %v", path, after, want)
		}

		if has, _ := longhornManifestHasVersionCheck(stripped); has {
			t.Errorf("%s: argument still present after removal", path)
		}
		if _, err := longhornManifestWithoutVersionCheck(stripped); err == nil {
			t.Errorf("%s: removing the argument twice must fail", path)
		}
	}
}

func TestLonghornManifestWithoutManager(t *testing.T) {
	manifest := []byte("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")
	if _, err := longhornManifestWithoutVersionCheck(manifest); err == nil {
		t.Fatal("a manifest without longhorn-manager must be refused")
	}
}

func TestLonghornDaemonSetHasVersionCheck(t *testing.T) {
	ds := appsv1.DaemonSet{}
	ds.Spec.Template.Spec.Containers = []corev1.Container{
		{Command: []string{"longhorn-manager", "-d", "daemon", longhornVersionCheckArg}},
	}
	if !longhornDaemonSetHasVersionCheck(&ds) {
		t.Fatal("argument in command not found")
	}
	ds.Spec.Template.Spec.Containers[0].Command = []string{"longhorn-manager", "-d", "daemon"}
	if longhornDaemonSetHasVersionCheck(&ds) {
		t.Fatal("argument reported although absent")
	}
}
