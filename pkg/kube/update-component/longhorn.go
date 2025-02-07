// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	longhornNamespace        = "longhorn-system"
	compLonghornDeployment   = "longhorn-driver-deployer"
	longhornSettingsYamlPath = "/etc/settings_longhorn.yaml"
)

type longhornComponent struct {
	commonComponent
}

func (ctx *longhornComponent) GetVersion() (string, error) {
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
	destV, err := semver.NewVersion(destVer)
	if err != nil {
		return err
	}
	c, err := semver.NewConstraint(">=" + sourceVer)
	if err != nil {
		return err
	}
	if !c.Check(destV) {
		return fmt.Errorf("version constraints deny %s->%s", sourceVer, destVer)
	}
	return nil
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

	//
	// 1. Check for longhorn-manager daemonset at correct version
	//
	lhMgrDs, err := cs.AppsV1().DaemonSets(longhornNamespace).Get(context.Background(), "longhorn-manager", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get longhorn-manager daemonsets: %v", err)
	}
	if lhMgrDs.Status.NumberReady != lhMgrDs.Status.DesiredNumberScheduled {
		return fmt.Errorf("longhorn-manager daemonset is not ready")
	}
	if lhMgrDs.Spec.Template.GetLabels()["app.kubernetes.io/version"] != version {
		return fmt.Errorf("longhorn-manager daemonset version mismatch, running:%s", lhMgrDs.Spec.Template.GetLabels()["app.kubernetes.io/version"])
	}

	//
	// 2. Check for all three longhorn daemonsets ready
	//
	lhDaemonsets, err := cs.AppsV1().DaemonSets(longhornNamespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list longhorn daemonsets: %v", err)
	}
	if len(lhDaemonsets.Items) != 3 {
		return fmt.Errorf("expected 3 longhorn daemonsets, got %d", len(lhDaemonsets.Items))
	}
	for _, lhDaemonset := range lhDaemonsets.Items {
		if lhDaemonset.Status.NumberReady != lhDaemonset.Status.DesiredNumberScheduled {
			return fmt.Errorf("longhorn daemonset %s is not ready", lhDaemonset.Name)
		}
	}

	//
	// 3. check if all longhorn volumes are using new engine image
	//
	config, err := GetKubeConfig()
	if err != nil {
		return err
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return err
	}
	lhVols, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).List(context.Background(), metav1.ListOptions{})
	if lhVols == nil || err != nil {
		return fmt.Errorf("failed to list longhorn volumes: %v", err)
	}
	for _, lhVol := range lhVols.Items {
		if !strings.HasSuffix(lhVol.Spec.Image, version) {
			return fmt.Errorf("longhorn volume %s still on engine:%s", lhVol.Name, lhVol.Spec.Image)
		}
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

func (ctx *longhornComponent) UpgradeStart(version string) error {
	if _, err := os.Stat(longhornSettingsYamlPath); err == nil {
		err := ctx.KubectlApply(longhornSettingsYamlPath)
		if err != nil {
			return fmt.Errorf("unable to apply longhorn pre-upgrade settings: %v", err)
		}
	}
	yamlPath := "https://raw.githubusercontent.com/longhorn/longhorn/" + version + "/deploy/longhorn.yaml"
	return ctx.KubectlApply(yamlPath)
}
