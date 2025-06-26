// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

//
// Interface for Registration manifest
// Registration manifest contains a deployment definition to
// join the kubernetes cluster into a controller.

const (
	registrationFileName string = "registration.yaml"
)

var (
	// PillarPersistManifestPath is the path used in running eve to save manifests to apply
	// Each Registration*() function should be passed this (or a test dir for go tests)
	PillarPersistManifestPath = filepath.Join(types.SealedDirName, "manifests")
)

// RegistrationAdd is blocking for inflation and fs writes. Caller should run in goroutine.
func RegistrationAdd(rootPath string, gzipYamlBody []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(gzipYamlBody))
	if err != nil {
		return err
	}
	defer gz.Close()
	yamlBody, err := io.ReadAll(gz)
	if err != nil {
		return err
	}
	if _, err := os.Stat(rootPath); err != nil {
		os.MkdirAll(rootPath, 0700)
	}
	exists, err := RegistrationExists(rootPath)
	if exists {
		os.Remove(filepath.Join(rootPath, registrationFileName))
	}
	//return WriteAndRename(registrationFileName, rootPath, yamlBody)
	return utils.WriteRename(filepath.Join(rootPath, registrationFileName), yamlBody)
}

// RegistrationExists returns nil if it exists
func RegistrationExists(rootPath string) (bool, error) {
	_, err := os.Stat(filepath.Join(rootPath, registrationFileName))
	if err == nil {
		return true, nil
	}
	return false, err
}

// registrationAppliedToCluster returns nil if the AddOn has been applied
// to the cluster
func registrationAppliedToCluster() error {
	config, err := GetKubeConfig()
	if err != nil {
		return fmt.Errorf("Failed to create dynamic client: %v", err)
	}

	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create dynamic client: %v", err)
	}

	addonGVR := schema.GroupVersionResource{
		Group:    "k3s.cattle.io",
		Version:  "v1",
		Resource: "addons",
	}

	addon, err := dyn.Resource(addonGVR).Get(context.TODO(), "persist-registration", metav1.GetOptions{})
	if (err != nil) || (addon == nil) {
		return fmt.Errorf("Failed to get AddOn/persist-registration: %v", err)
	}
	return nil
}
