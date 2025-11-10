#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

KUBEVIRT_VERSION=v1.6.0
CDI_VERSION=v1.57.1

Kubevirt_install() {
    # Though PR https://github.com/kubevirt/kubevirt/pull/9668 is merged to upstream kubevirt
    # we need to pass in env KV_IO_EXTRA_ENV_VIRT_IN_CONTAINER = "true" for our environment.
    # so we download kubevirt-operator.yaml and patch it
    logmsg "Installing patched Kubevirt"
    kubectl apply -f /etc/kubevirt-operator.yaml
    kubectl apply -f https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml
    Kubevirt_config 3
    #Add kubevirt feature gates
    kubectl apply -f /etc/kubevirt-features.yaml
}

Kubevirt_config() {
    replica_count=$1
    logmsg "Updating replica count to ${replica_count} for virt-operator and virt-controller"
    kubectl patch deployment virt-operator -n kubevirt --patch "{'spec':{'replicas': ${replica_count} }}"
    kubectl patch KubeVirt kubevirt -n kubevirt --patch "{'spec': {'infra': {'replicas': ${replica_count} }}}" --type='merge'
}

Kubevirt_tie_breaker_config_apply() {
    dsList=$(kubectl -n kubevirt get daemonset -o json | jq -r .items[].metadata.name)
    for ds in $dsList; do
            logmsg "setting node selector for ds:$ds"
            kubectl patch daemonset "$ds" -n kubevirt -p '{"spec":{"template":{"spec":{"nodeSelector":{"tie-breaker-node":"false"}}}}}'
    done
}

Kubevirt_uninstall() {
    logmsg "Removing patched Kubevirt"
    {
        kubectl delete -n kubevirt kubevirt kubevirt --wait=true
        kubectl delete apiservices v1.subresources.kubevirt.io
        kubectl delete mutatingwebhookconfigurations virt-api-mutator
        kubectl delete validatingwebhookconfigurations virt-operator-validator
        kubectl delete validatingwebhookconfigurations virt-api-validator
        kubectl delete -f /etc/kubevirt-operator.yaml --wait=false
    } >> "$INSTALL_LOG" 2>&1

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

Cdi_config() {
    depList=$(kubectl -n cdi get deployment -o json | jq -r .items[].metadata.name)
    for dep in $depList; do
            logmsg "setting node selector for dep:$dep"
            kubectl patch deployment "$dep" -n cdi -p '{"spec":{"template":{"spec":{"nodeSelector":{"tie-breaker-node":"false"}}}}}'
    done
}
