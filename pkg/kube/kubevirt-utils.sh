#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

KUBEVIRT_VERSION=v1.1.0
CDI_VERSION=v1.57.1

Kubevirt_install() {
    # This patched version will be removed once the following PR https://github.com/kubevirt/kubevirt/pull/9668 is merged
    logmsg "Installing patched Kubevirt"
    kubectl apply -f /etc/kubevirt-operator.yaml
    logmsg "Updating replica to 1 for virt-operator and virt-controller"
    kubectl patch deployment virt-operator -n kubevirt --patch '{"spec":{"replicas": 1 }}'
    kubectl apply -f https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml
    kubectl patch KubeVirt kubevirt -n kubevirt --patch '{"spec": {"infra": {"replicas": 1}}}' --type='merge'
    #Add kubevirt feature gates
    kubectl apply -f /etc/kubevirt-features.yaml
}

Kubevirt_uninstall() {
    logmsg "Removing patched Kubevirt"
    kubectl delete -f /etc/kubevirt-features.yaml
    kubectl delete -f /etc/kubevirt-operator.yaml

    # Kubevirt applies a large amount of labels to nodes detailing available cpu flags, remove them
    for n in $(kubectl get node -o NAME); do
        logmsg "removing kubevirt.io labels from node: $n"
        labelsToRemove=$(kubectl get "$n" -o json | jq -r '.metadata.labels | to_entries[] | select(.key | contains("kubevirt.io")) | .key' | awk '{printf "%s- ", $0}')
        # shellcheck disable=SC2086
        kubectl label $n $labelsToRemove
    done
    rm /var/lib/kubevirt_initialized
}

Cdi_install() {
    #CDI (containerzed data importer) is need to convert qcow2/raw formats to Persistent Volumes and Data volumes
    logmsg "Installing CDI version $CDI_VERSION"
    kubectl create -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-operator.yaml
    kubectl create -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-cr.yaml
}

Cdi_uninstall() {
    #CDI (containerzed data importer) is need to convert qcow2/raw formats to Persistent Volumes and Data volumes
    logmsg "Removing CDI version $CDI_VERSION"
    kubectl delete -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-cr.yaml
    kubectl delete -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-operator.yaml
}