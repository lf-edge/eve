#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

DESCHEDULER_VERSION="v0.29.0"

descheduler_install()
{
    logmsg "Applying Descheduler ${DESCHEDULER_VERSION}"
    if ! kubectl apply -f /etc/descheduler_rbac.yaml; then
            logmsg "descheduler rbac not yet applied"
            return 1
    fi
    if ! kubectl apply -f /etc/descheduler-policy-configmap.yaml; then
            logmsg "descheduler configmap not yet applied"
            return 1
    fi
    return 0
}