// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	longhornNamespace        = "longhorn-system"
	compLonghornDeployment   = "longhorn-driver-deployer"
	longhornSettingsYamlPath = "/etc/settings_longhorn.yaml"
	// longhornVersionSetting is Longhorn's own record of the installed
	// version. It only advances once longhorn-manager has completed an
	// upgrade, unlike the image tags, which change as soon as a manifest
	// is applied.
	longhornVersionSetting = "current-longhorn-version"
	// longhornManifestPathFmt is where the kube container ships the
	// Longhorn manifest of the version it targets.
	longhornManifestPathFmt = "/etc/lh-cfg-%s.yaml"
	// longhornFinalizeTimeout bounds the manager rollout that restores the
	// upgrade version check.
	longhornFinalizeTimeout = 10 * time.Minute
)

type longhornComponent struct {
	commonComponent
}

func longhornClient() (*versioned.Clientset, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, err
	}
	return versioned.NewForConfig(config)
}

func (ctx *longhornComponent) GetVersion() (string, error) {
	lhClient, err := longhornClient()
	if err != nil {
		return "", err
	}
	setting, err := lhClient.LonghornV1beta2().Settings(longhornNamespace).
		Get(context.Background(), longhornVersionSetting, metav1.GetOptions{})
	switch {
	case err == nil && setting.Value != "":
		return setting.Value, nil
	case err != nil && !apierrors.IsNotFound(err):
		return "", fmt.Errorf("failed to get longhorn setting %s: %v",
			longhornVersionSetting, err)
	}
	// longhorn-manager has not recorded a version yet.
	return ctx.deployerVersion()
}

// deployerVersion returns the image tag of the driver deployer.
func (ctx *longhornComponent) deployerVersion() (string, error) {
	cs := ctx.cs
	lhDriverDeployer, err := cs.AppsV1().Deployments(longhornNamespace).Get(context.Background(), compLonghornDeployment, metav1.GetOptions{})
	if lhDriverDeployer == nil || err != nil {
		return "", fmt.Errorf("failed to list longhorn deployment/%s: %v", compLonghornDeployment, err)
	}
	lhImage := lhDriverDeployer.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(lhImage, ":")
	if len(imageParts) < 2 {
		return "", fmt.Errorf("failed to parse longhorn image: %v", lhImage)
	}
	return imageParts[1], nil
}

func (ctx *longhornComponent) UpgradeSupported(sourceVer string, destVer string) error {
	_, err := longhornUpgradeAllowed(sourceVer, destVer, validatedLonghornLargeSteps)
	return err
}
func (ctx *longhornComponent) Uptime(version string) (time.Time, error) {
	// Return lowest ready condition time of all nodes found
	lowestRdyTime := time.Time{}

	config, err := GetKubeConfig()
	if err != nil {
		return lowestRdyTime, err
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return lowestRdyTime, err
	}
	lhNodes, err := lhClient.LonghornV1beta2().Nodes(longhornNamespace).List(context.Background(), metav1.ListOptions{})
	if lhNodes == nil || err != nil {
		return lowestRdyTime, fmt.Errorf("failed to list longhorn nodes: %v", err)
	}

	for _, node := range lhNodes.Items {
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == v1beta2.ConditionStatusTrue {
				lhNodeRdyTime, err := time.Parse(time.RFC3339, condition.LastTransitionTime)
				if err != nil {
					log.Printf("longhorn node timestamp:%s parse err:%v", condition.LastTransitionTime, err)
					continue
				}
				if lhNodeRdyTime.Compare(lowestRdyTime) == 1 {
					lowestRdyTime = lhNodeRdyTime
				}
			}
		}
	}
	if time.Time.IsZero(lowestRdyTime) {
		return lowestRdyTime, fmt.Errorf("failed to get uptime for longhorn nodes")
	}
	return lowestRdyTime, nil
}
func (ctx *longhornComponent) Ready(version string) error {
	cs := ctx.cs

	lhDaemonsets, err := cs.AppsV1().DaemonSets(longhornNamespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list longhorn daemonsets: %v", err)
	}
	if err := checkLonghornDaemonSetsReady(lhDaemonsets.Items, version); err != nil {
		return err
	}

	installed, err := ctx.GetVersion()
	if err != nil {
		return err
	}
	if installed != version {
		return fmt.Errorf("longhorn reports installed version %s", installed)
	}

	lhClient, err := longhornClient()
	if err != nil {
		return err
	}
	lhVols, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).List(context.Background(), metav1.ListOptions{})
	if lhVols == nil || err != nil {
		return fmt.Errorf("failed to list longhorn volumes: %v", err)
	}
	if behind := longhornVolumesBehind(lhVols.Items, version); len(behind) > 0 {
		return fmt.Errorf("longhorn volumes not yet on engine %s: %s",
			version, strings.Join(behind, ", "))
	}

	return nil
}

func getLonghornDefaultEngineImage() (string, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return "", err
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return "", err
	}
	lhSetting, err := lhClient.LonghornV1beta2().Settings(longhornNamespace).Get(context.Background(), "default-engine-image", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get longhorn settings: %v", err)
	}
	return lhSetting.Value, nil
}

// preUpgradeChecks runs the guards that must hold before a Longhorn
// manifest is applied. Errors that can clear up on their own, an API
// error, a faulted volume or an engine upgrade still under way, wrap
// errNotStarted; CRD versions left stored in a removed API do not.
func (ctx *longhornComponent) preUpgradeChecks(sourceVer, destVer string,
	largeStep bool) error {
	lhClient, err := longhornClient()
	if err != nil {
		return fmt.Errorf("%w: %w", errNotStarted, err)
	}
	lhVols, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("%w: failed to list longhorn volumes: %v", errNotStarted, err)
	}
	if err := checkLonghornVolumesNotFaulted(lhVols.Items); err != nil {
		return fmt.Errorf("%w: %w", errNotStarted, err)
	}

	if longhornLeavesRemovedAPI(sourceVer, destVer) {
		config, err := GetKubeConfig()
		if err != nil {
			return fmt.Errorf("%w: %w", errNotStarted, err)
		}
		extClient, err := apiextensionsclient.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("%w: %w", errNotStarted, err)
		}
		crds, err := extClient.ApiextensionsV1().CustomResourceDefinitions().
			List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("%w: failed to list CRDs: %v", errNotStarted, err)
		}
		if err := checkLonghornStoredVersions(crds.Items); err != nil {
			return err
		}
	}

	if largeStep {
		images, err := lhClient.LonghornV1beta2().EngineImages(longhornNamespace).
			List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("%w: failed to list longhorn engine images: %v", errNotStarted, err)
		}
		if err := checkLonghornEngineImagesAt(images.Items, sourceVer); err != nil {
			return fmt.Errorf("%w: %w", errNotStarted, err)
		}
	}

	if server, err := ctx.cs.Discovery().ServerVersion(); err != nil {
		log.Printf("longhorn pre-upgrade: kubernetes version unknown: %v", err)
	} else if old, minimum := longhornServerTooOld(destVer, server.Major, server.Minor); old {
		log.Printf("WARNING: longhorn %s requires kubernetes %s or later, server is %s",
			destVer, minimum, server.GitVersion)
	}
	return nil
}

// Applied reports whether longhorn-manager already runs version, that is
// an earlier run applied its manifest before Longhorn moved its version.
func (ctx *longhornComponent) Applied(version string) (bool, error) {
	ds, err := ctx.cs.AppsV1().DaemonSets(longhornNamespace).
		Get(context.Background(), longhornManagerDaemonSet, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	return ds.Spec.Template.GetLabels()["app.kubernetes.io/version"] == version, nil
}

func (ctx *longhornComponent) UpgradeStart(version string) error {
	sourceVer, err := ctx.GetVersion()
	if err != nil {
		return fmt.Errorf("%w: %w", errNotStarted, err)
	}
	largeStep, err := longhornUpgradeAllowed(sourceVer, version, validatedLonghornLargeSteps)
	if err != nil && !ForceUpgrade {
		return err
	}
	// The checks describe the cluster before the upgrade. An interrupted
	// run passed them and changed the cluster since, so a resumed run
	// only applies again.
	if resumed, _ := ctx.Applied(version); !resumed {
		if err := ctx.preUpgradeChecks(sourceVer, version, largeStep); err != nil {
			return fmt.Errorf("longhorn pre-upgrade check: %w", err)
		}
	}

	if _, err := os.Stat(longhornSettingsYamlPath); err == nil {
		err := ctx.KubectlApply(longhornSettingsYamlPath)
		if err != nil {
			return fmt.Errorf("unable to apply longhorn pre-upgrade settings: %v", err)
		}
	}

	manifestPath := fmt.Sprintf(longhornManifestPathFmt, version)
	if !largeStep {
		return ctx.KubectlApply(manifestPath)
	}
	// longhorn-manager refuses a large step on its own. Start it without
	// its upgrade version check; Finalize puts the check back.
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	manifest, err = longhornManifestWithoutVersionCheck(manifest)
	if err != nil {
		return fmt.Errorf("%s: %w", manifestPath, err)
	}
	log.Printf("longhorn large step %s -> %s: applying %s without %s",
		sourceVer, version, manifestPath, longhornVersionCheckArg)
	return ctx.KubectlApplyData(manifestPath, manifest)
}

// Finalize restores the upgrade version check on longhorn-manager if a
// large step left it off. It is a no-op when the check is in place. It
// refuses until Longhorn is ready at version, every volume on its engine:
// applying the manifest restarts every manager, which must not happen in
// the middle of the engine upgrades.
func (ctx *longhornComponent) Finalize(version string) error {
	hasCheck, err := ctx.managerHasVersionCheck()
	if err != nil {
		return err
	}
	if hasCheck {
		return nil
	}
	if err := ctx.Ready(version); err != nil {
		return fmt.Errorf("%w: longhorn not ready at %s, not restoring %s yet: %v",
			errNotStarted, version, longhornVersionCheckArg, err)
	}
	manifestPath := fmt.Sprintf(longhornManifestPathFmt, version)
	log.Printf("longhorn finalize: restoring %s from %s",
		longhornVersionCheckArg, manifestPath)
	if err := ctx.KubectlApply(manifestPath); err != nil {
		return err
	}
	deadline := time.Now().Add(longhornFinalizeTimeout)
	for {
		err := ctx.managerRolledOut()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("longhorn-manager not ready within %s after "+
				"restoring %s: %w", longhornFinalizeTimeout, longhornVersionCheckArg, err)
		}
		time.Sleep(upgradePollWaitSeconds * time.Second)
	}
}

func (ctx *longhornComponent) managerHasVersionCheck() (bool, error) {
	ds, err := ctx.cs.AppsV1().DaemonSets(longhornNamespace).
		Get(context.Background(), longhornManagerDaemonSet, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get longhorn-manager daemonset: %v", err)
	}
	return longhornDaemonSetHasVersionCheck(ds), nil
}

// managerRolledOut reports whether every longhorn-manager pod runs the
// current DaemonSet template, with the upgrade version check, and is ready.
func (ctx *longhornComponent) managerRolledOut() error {
	ds, err := ctx.cs.AppsV1().DaemonSets(longhornNamespace).
		Get(context.Background(), longhornManagerDaemonSet, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if !longhornDaemonSetHasVersionCheck(ds) {
		return errors.New("longhorn-manager daemonset still lacks " + longhornVersionCheckArg)
	}
	st := ds.Status
	if st.ObservedGeneration != ds.Generation ||
		st.UpdatedNumberScheduled != st.DesiredNumberScheduled ||
		st.NumberReady != st.DesiredNumberScheduled {
		return fmt.Errorf("longhorn-manager rollout in progress: %d/%d updated, %d ready",
			st.UpdatedNumberScheduled, st.DesiredNumberScheduled, st.NumberReady)
	}
	return nil
}
