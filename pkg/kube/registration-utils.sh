#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Dir which pillar service container has access to
PERSIST_MANIFESTS_DIR=/persist/vault/manifests
# Dir which kube service container has access to and k3s monitors
KUBE_MANIFESTS_DIR=/var/lib/rancher/k3s/server/manifests

YAML_EXT="yaml"
# The source yaml, which pillar inflates.
registrationYamlName="registration"
registrationYamlFileName="${registrationYamlName}.${YAML_EXT}"
registrationYamlFilePath="${PERSIST_MANIFESTS_DIR}/${registrationYamlFileName}"

# The dest yaml, where k3s can auto-apply
appliedRegistrationYamlName="persist-${registrationYamlName}"
appliedRegistrationYamlFileName="${appliedRegistrationYamlName}.${YAML_EXT}"
appliedRegistrationYamlFilePath="${KUBE_MANIFESTS_DIR}/${appliedRegistrationYamlFileName}"

# Pillar may download a yaml for registration, copy it in so that k3s handles applying it
# This should be called in a very infrequently called cluster-config-change path
Registration_CheckApply() {
    if [ ! -d "${PERSIST_MANIFESTS_DIR}" ]; then
        return
    fi

    if [ ! -e "${registrationYamlFilePath}" ]; then
        return
    fi

    # Copy to the dir monitored by k3s, it will handle application
    cp "${registrationYamlFilePath}" "${appliedRegistrationYamlFilePath}"
    logmsg "${appliedRegistrationYamlFilePath} awaiting application by k3s"
    return
}

Registration_Cleanup() {
    cleanup_persist_manifest_registration
    return 0
}

# Registration_Exists checks if the local eve fs contains
# a registration file, this will only exist on one node.
Registration_Exists() {
    if [ -e "${appliedRegistrationYamlFilePath}" ]; then
        return 0
    fi
    return 1
}

# Registration_Applied checks if the cluster contains the pointer
# marking that a registration manifest has been applied by k3s.
# This marker allows an agnostic check that the manifest has been applied
# regardless of the manifest's specific object contents
Registration_Applied() {
    kubectl -n kube-system get AddOn/${appliedRegistrationYamlName} > /dev/null 2>&1
    return $?
}

# delete the files from persist so that we don't re-apply them
# when node converts to single node it also reverts /var/lib/ back to
# sqlite from before registration existed, no need to
# manually manage deletion of those objects
cleanup_persist_manifest_registration() {
    rm "${appliedRegistrationYamlFilePath}"
    rm "${registrationYamlFilePath}"
    logmsg "registration manifests deleted"
}
