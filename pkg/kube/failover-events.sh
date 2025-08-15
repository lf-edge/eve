#!/bin/bash
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: ./failover-events.sh <vmi-replicaset-prefix>

PREFIX="$1"
NAMESPACE="eve-kube-app"

if [ -z "$PREFIX" ]; then
  echo "Usage: $0 <vmi-replicaset-prefix>"
  exit 1
fi

VMIRS_NAMES=$(kubectl get vmirs -n "$NAMESPACE" --no-headers | awk '{print $1}' | grep "^$PREFIX")
for vmirs in $VMIRS_NAMES; do
  appDomainNameSelector=$(kubectl -n "$NAMESPACE" get "vmirs/${vmirs}" -o json | jq -r .status.labelSelector)

  # Find all VMI names matching the prefix
  VMI_NAMES=$(kubectl get vmi -n "$NAMESPACE" -l "$appDomainNameSelector" --no-headers | awk '{print $1}')

  # Find all virt-launcher pods associated with those VMIs
  POD_NAMES=""
  PVC_NAMES=""
  LH_VOL_NAMES=""
  LH_VOL_REPS=""

  pods=$(kubectl get pods -n "$NAMESPACE" -l "$appDomainNameSelector" --no-headers | awk '{print $1}')
  POD_NAMES="$POD_NAMES $pods"

  # All PVCs for this pod
  pvcs=$(kubectl get pod -n "$NAMESPACE" -l "$appDomainNameSelector" -o json | jq -r '.items[].spec.volumes[] | select(.persistentVolumeClaim) | .persistentVolumeClaim.claimName')
  PVC_NAMES="$PVC_NAMES $pvcs"
  for pvc in $pvcs; do
    volname=$(kubectl -n "$NAMESPACE" get "pvc/${pvc}" -o json | jq -r .spec.volumeName)
    LH_VOL_NAMES="$LH_VOL_NAMES $volname"

    reps=$(kubectl -n longhorn-system get replicas -l "longhornvolume=$volname" --no-headers | awk '{print $1}')
    LH_VOL_REPS="$LH_VOL_REPS $reps"
  done

  # Collect all relevant object names
  OBJECTS="$vmirs $VMI_NAMES $POD_NAMES $PVC_NAMES"
  LHOBJECTS="$LH_VOL_NAMES $LH_VOL_REPS"

  # Get events for each object and print them with creationTimestamp
  for obj in $OBJECTS; do
    kubectl get events -n "$NAMESPACE" --field-selector involvedObject.name="$obj" -o json \
      | jq -r '.items[] | [.metadata.creationTimestamp, .involvedObject.kind, .involvedObject.name, .reason, .message] | @tsv'
  done | sort
  for obj in $LHOBJECTS; do
    kubectl get events -n longhorn-system --field-selector involvedObject.name="$obj" -o json \
      | jq -r '.items[] | [.metadata.creationTimestamp, .involvedObject.kind, .involvedObject.name, .reason, .message] | @tsv'
  done | sort
done
