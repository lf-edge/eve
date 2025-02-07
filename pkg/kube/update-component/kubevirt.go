// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/semver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
)

const (
	kubevirtNamespace                = "kubevirt"
	compKubevirtDeploymentOperator   = "virt-operator"
	compKubevirtDeploymentController = "virt-controller"
)

type kubevirtComponent struct {
	commonComponent
}

func (ctx *kubevirtComponent) GetVersion() (string, error) {
	kubeConfig, err := GetKubeConfig()
	if err != nil {
		return "", fmt.Errorf("can't get kubeconfig %v", err)
	}
	kvClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeConfig)
	if err != nil {
		return "", fmt.Errorf("can't get kubevirt client %v", err)
	}
	kubeVirt, err := kvClient.KubeVirt(kubevirtNamespace).Get("kubevirt", &metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("can't fetch kubevirt version %v", err)
	}
	return kubeVirt.Status.OperatorVersion, nil
}

func (ctx *kubevirtComponent) UpgradeSupported(sourceVer string, destVer string) error {
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

func (ctx *kubevirtComponent) Uptime(version string) (time.Time, error) {
	cs := ctx.cs
	lowestRdyTime := time.Time{}
	selector := "kubevirt.io=" + compKubevirtDeploymentController
	pods, err := cs.CoreV1().Pods(kubevirtNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: selector,
	})
	if pods == nil || err != nil {
		return lowestRdyTime, fmt.Errorf("failed to get pods by selector %s: %v", selector, err)
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
		return lowestRdyTime, fmt.Errorf("failed to get uptime for kubevirt deployment/%s", compKubevirtDeploymentController)
	}

	return lowestRdyTime, nil
}

func (ctx *kubevirtComponent) Ready(version string) error {
	cs := ctx.cs
	kvDeployment, err := cs.AppsV1().Deployments(kubevirtNamespace).Get(context.Background(), compKubevirtDeploymentController, metav1.GetOptions{})
	if kvDeployment == nil || err != nil {
		return fmt.Errorf("failed to list kubevirt deployment for version %s: %v", version, err)
	}
	if kvDeployment.Status.ReadyReplicas != kvDeployment.Status.Replicas {
		return fmt.Errorf("insufficient kubevirt readiness for deployment: %s", compKubevirtDeploymentController)
	}
	return nil
}

func (ctx *kubevirtComponent) UpgradeStart(version string) error {
	yamlPath := "https://github.com/kubevirt/kubevirt/releases/download/" + version + "/kubevirt-operator.yaml"
	return ctx.KubectlApply(yamlPath)
}
