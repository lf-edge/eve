#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# kubevip-apply.sh
# This script creates a Kube-VIP ConfigMap with the specified interface and CIDR range
# and applies the necessary Kubernetes resources.

# Function to display usage information
show_usage() {
    echo "Usage: $0 <interface-name> <ip-prefix>"
    echo "Example: $0 eth1 192.168.86.200/29"
    echo ""
    echo "This script creates a Kube-VIP ConfigMap with the specified interface and CIDR range"
    echo "and applies the necessary Kubernetes resources."
}

# Check if we have two arguments
if [ $# -ne 2 ]; then
    echo "Error: Missing required parameters"
    show_usage
    exit 1
fi

# Assign arguments to variables
INTERFACE=$1
CIDR=$2

# Validate interface name (simple check)
if ! echo "$INTERFACE" | grep -qE '^[a-zA-Z0-9_-]+$'; then
    echo "Error: Invalid interface name format. Allowed characters: letters, numbers, underscores (_), dots (.), and hyphens (-)"
    show_usage
    exit 1
fi

# Validate CIDR format (simple check)
if ! echo "$CIDR" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
    echo "Error: Invalid CIDR format. Expected format: x.x.x.x/y"
    show_usage
    exit 1
fi

# Create ConfigMap file
# see https://github.com/kube-vip/kube-vip-cloud-provider for config examples
cat > /etc/kubevip-cm.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubevip
  namespace: kube-system
data:
  # Global settings for all LoadBalancer services
  cidr-global: "${CIDR}"
  interface-global: "${INTERFACE}"
EOF

echo "Created Kube-VIP ConfigMap with interface ${INTERFACE} and CIDR ${CIDR}"
echo "Applying Kube-VIP resources..."

# Apply Kubernetes resources
if kubectl apply -f /etc/kubevip-sa.yaml && \
   kubectl apply -f /etc/kubevip-cm.yaml && \
   kubectl apply -f /etc/kubevip-ds.yaml; then
    echo "Kube-VIP resources successfully applied"
else
    echo "Error applying Kube-VIP resources"
    exit 1
fi

echo "Kube-VIP configuration complete"