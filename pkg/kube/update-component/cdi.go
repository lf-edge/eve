// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cdiNamespace              = "cdi"
	compCdiDeploymentOperator = "cdi-operator"
)

type cdiComponent struct {
	commonComponent
}

func (ctx *cdiComponent) GetVersion() (string, error) {
	cs := ctx.cs
	cdiDeployment, err := cs.AppsV1().Deployments(cdiNamespace).Get(context.Background(), compCdiDeploymentOperator, metav1.GetOptions{})
	if cdiDeployment == nil || err != nil {
		return "", fmt.Errorf("failed to get cdi deployment/%s: %v", compCdiDeploymentOperator, err)
	}
	env := cdiDeployment.Spec.Template.Spec.Containers[0].Env
	for _, e := range env {
		if e.Name == "OPERATOR_VERSION" {
			return e.Value, nil
		}
	}
	return "", nil
}

func (ctx *cdiComponent) UpgradeSupported(sourceVer string, destVer string) error {
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

func (ctx *cdiComponent) Uptime(version string) (time.Time, error) {
	cs := ctx.cs
	cdiDeployment, err := cs.AppsV1().Deployments(cdiNamespace).Get(context.Background(), compCdiDeploymentOperator, metav1.GetOptions{})
	if cdiDeployment == nil || err != nil {
		return time.Time{}, fmt.Errorf("failed to get cdi deployment/%s: %v", compCdiDeploymentOperator, err)
	}
	for _, condition := range cdiDeployment.Status.Conditions {
		if condition.Reason == "MinimumReplicasAvailable" && condition.Status == v1.ConditionTrue {
			return condition.LastTransitionTime.Time, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to get uptime for cdi deployment/%s", compCdiDeploymentOperator)
}

func (ctx *cdiComponent) Ready(version string) error {
	cs := ctx.cs
	cdiDeployment, err := cs.AppsV1().Deployments(cdiNamespace).Get(context.Background(), compCdiDeploymentOperator, metav1.GetOptions{})
	if cdiDeployment == nil || err != nil {
		return fmt.Errorf("failed to get deployment/%s: %v", compCdiDeploymentOperator, err)
	}
	for _, cdiContainer := range cdiDeployment.Spec.Template.Spec.Containers {
		imageTagParts := strings.Split(cdiContainer.Image, ":")
		imageVersion := imageTagParts[len(imageTagParts)-1]
		if version != imageVersion {
			return fmt.Errorf("CDI not yet online at version: %s", version)
		}
	}
	if cdiDeployment.Status.ReadyReplicas != cdiDeployment.Status.Replicas {
		return fmt.Errorf("insufficient cdi readiness for deployment: %s", compCdiDeploymentOperator)
	}
	return nil
}

func (ctx *cdiComponent) UpgradeStart(version string) error {
	yamlPath := "https://github.com/kubevirt/containerized-data-importer/releases/download/" + version + "/cdi-operator.yaml"
	return ctx.KubectlApply(yamlPath)
}
