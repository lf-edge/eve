// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	multusNamespace     = "kube-system"
	compMultusDaemonset = "kube-multus-ds-amd64"
)

type multusComponent struct {
	commonComponent
}

func (ctx *multusComponent) GetVersion() (string, error) {
	cs := ctx.cs
	multusDaemonset, err := cs.AppsV1().DaemonSets(multusNamespace).Get(context.Background(), compMultusDaemonset, metav1.GetOptions{})
	if multusDaemonset == nil || err != nil {
		return "", fmt.Errorf("failed to get daemonset/%s: %v", compMultusDaemonset, err)
	}
	image := multusDaemonset.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) < 2 {
		return "", fmt.Errorf("failed to parse multus image: %v", image)
	}
	return imageParts[1], nil
}

func (ctx *multusComponent) UpgradeSupported(sourceVer string, destVer string) error {
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

func (ctx *multusComponent) Uptime(version string) (time.Time, error) {
	cs := ctx.cs
	lowestRdyTime := time.Time{}
	pods, err := cs.CoreV1().Pods(multusNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=multus",
	})
	if pods == nil || err != nil {
		return lowestRdyTime, fmt.Errorf("failed to get pods by selector %s: %v", "app=multus", err)
	}

	for _, pod := range pods.Items {
		for _, condition := range pod.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				if condition.LastTransitionTime.Time.After(lowestRdyTime) {
					lowestRdyTime = condition.LastTransitionTime.Time
				}
			}
		}
	}
	if time.Time.IsZero(lowestRdyTime) {
		return lowestRdyTime, fmt.Errorf("failed to get uptime for app=multus pods")
	}
	return lowestRdyTime, nil
}

func (ctx *multusComponent) Ready(version string) error {
	cs := ctx.cs
	multusDaemonset, err := cs.AppsV1().DaemonSets(multusNamespace).Get(context.Background(), compMultusDaemonset, metav1.GetOptions{})
	if multusDaemonset == nil || err != nil {
		return fmt.Errorf("failed to get daemonset/%s: %v", compMultusDaemonset, err)
	}
	if multusDaemonset.Status.NumberReady != multusDaemonset.Status.DesiredNumberScheduled {
		return fmt.Errorf("insufficient multus readiness for daemonset %s", compMultusDaemonset)
	}
	return nil
}

func (ctx *multusComponent) UpgradeStart(version string) error {
	// Lookup table for custom multus yaml from version string to absolute file path in kube service container
	var multusInstallYamlTable = map[string]string{
		"v3.9.3": " /etc/multus-daemonset-new.yaml",
	}
	return ctx.KubectlApply(multusInstallYamlTable[version])
}
