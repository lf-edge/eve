#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# vm-create.sh — Create a KVM/libvirt Ubuntu VM pre-configured as a GitHub
#                self-hosted runner with EVETEST_BROKER_ADDRESS pointing at
#                the host via the libvirt default network gateway.
#
# Usage:
#   ./vm-create.sh --user <github-username> --pat <pat> [OPTIONS]
#
# Options:
#   --user    <username>     GitHub username (required). The repository is
#                            always "<username>/eve".
#   --pat     <pat>          GitHub PAT with Read & Write Administration
#                            permission (required). Used to generate a runner
#                            registration token automatically.
#   --name    <name>         VM and runner name (default: evetest-runner)
#   --cpus    <n>            vCPUs (default: 2)
#   --ram     <MB>           RAM in MB (default: 4096)
#   --disk    <GB>           Disk size in GB (default: 20)
#   --password <password>    SSH password for the in-VM user (default: password123).
#                            The SSH username is the GitHub username (--user).
#   --broker-addr <ip>       EVETEST_BROKER_ADDRESS value
#                            (default: gateway IP of the libvirt default network)
#   --image-dir <dir>        Directory for VM disks and the cached base image
#                            (default: /var/lib/libvirt/images)

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
VM_NAME="evetest-runner"
VCPUS=2
RAM_MB=4096
DISK_GB=20
BROKER_ADDR=""   # resolved after arg parsing from the libvirt default network
GH_USER=""
GH_PAT=""
SSH_PASSWORD="password123"
IMAGE_DIR="/var/lib/libvirt/images"

BASE_IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
BASE_IMAGE_NAME="noble-server-cloudimg-amd64.img"

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)         GH_USER="$2";       shift 2 ;;
        --pat)          GH_PAT="$2";        shift 2 ;;
        --name)         VM_NAME="$2";       shift 2 ;;
        --cpus)         VCPUS="$2";         shift 2 ;;
        --ram)          RAM_MB="$2";        shift 2 ;;
        --disk)         DISK_GB="$2";       shift 2 ;;
        --password)     SSH_PASSWORD="$2";  shift 2 ;;
        --broker-addr)  BROKER_ADDR="$2";   shift 2 ;;
        --image-dir)    IMAGE_DIR="$2";     shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ -z "$GH_USER" ]] && { echo "Error: --user is required"; exit 1; }
[[ -z "$GH_PAT"  ]] && { echo "Error: --pat is required";  exit 1; }

GH_REPO="${GH_USER}/eve"
SSH_PASSWORD_HASH=$(openssl passwd -6 "$SSH_PASSWORD")

# ── Generate runner registration token ───────────────────────────────────────
echo "Generating runner registration token..."
GH_TOKEN=$(curl -sf -X POST -H "Authorization: Bearer ${GH_PAT}" \
    "https://api.github.com/repos/${GH_REPO}/actions/runners/registration-token" \
    | jq -r .token)
[[ -z "$GH_TOKEN" || "$GH_TOKEN" == "null" ]] && {
    echo "Error: failed to generate registration token. Check --user and --pat."; exit 1;
}

# ── Resolve broker address ───────────────────────────────────────────────────
if [[ -z "$BROKER_ADDR" ]]; then
    BROKER_ADDR=$(virsh net-dumpxml default 2>/dev/null \
        | grep -oP "(?<=<ip address=')[^']*" | head -1)
    if [[ -z "$BROKER_ADDR" ]]; then
        echo "Error: could not discover gateway IP of the libvirt default network."
        echo "       Is libvirt running and is the 'default' network active?"
        echo "       You can specify the address manually with --broker-addr."
        exit 1
    fi
    echo "Discovered broker address: $BROKER_ADDR"
fi

# ── Check for existing VM ────────────────────────────────────────────────────
if virsh domstate "$VM_NAME" &>/dev/null; then
    echo "Error: VM '$VM_NAME' already exists. Destroy it first with vm-destroy.sh."
    exit 1
fi

# ── Download base image (cached in IMAGE_DIR, accessible to libvirt-qemu) ────
BASE_IMAGE="${IMAGE_DIR}/${BASE_IMAGE_NAME}"
if [[ ! -f "$BASE_IMAGE" ]]; then
    echo "Downloading Ubuntu 24.04 cloud image..."
    wget -q --show-progress -O "/tmp/${BASE_IMAGE_NAME}.tmp" "$BASE_IMAGE_URL"
    mv "/tmp/${BASE_IMAGE_NAME}.tmp" "$BASE_IMAGE"
else
    echo "Using cached base image: $BASE_IMAGE"
fi

# ── Create overlay disk ──────────────────────────────────────────────────────
VM_DISK="${IMAGE_DIR}/${VM_NAME}.qcow2"
echo "Creating VM disk: $VM_DISK (${DISK_GB}G overlay on base image)..."
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$VM_DISK" "${DISK_GB}G"

# ── Generate cloud-init files ────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/meta-data" <<EOF
instance-id: $VM_NAME
local-hostname: $VM_NAME
EOF

# Collect EVETEST_* variables from the host to propagate into the VM.
# EVETEST_BROKER_ADDRESS is excluded here and appended explicitly afterwards
# so it cannot be overridden by the host environment.
EVETEST_ENV_CONTENT=""
while IFS= read -r line; do
    EVETEST_ENV_CONTENT+="${line}\n"
    echo "  Propagating: $line"
done < <(env | grep '^EVETEST_' | grep -v '^EVETEST_BROKER_ADDRESS=' | sort)

# Optionally embed host Docker credentials into cloud-init so the runner VM
# can pull images without manual docker login.
DOCKER_CONFIG_ENTRY=""
if [[ -f "$HOME/.docker/config.json" ]]; then
    DOCKER_CONFIG_B64=$(base64 -w0 "$HOME/.docker/config.json")
    DOCKER_CONFIG_ENTRY="
  - path: /home/$GH_USER/.docker/config.json
    content: $DOCKER_CONFIG_B64
    encoding: b64
    owner: $GH_USER:$GH_USER
    permissions: '0600'
    defer: true"
    echo "Docker credentials will be embedded into the VM."
fi

# Note: variables like \$RUNNER_VERSION are intentionally escaped — they must
# be evaluated inside the VM, not by this script.
cat > "$TMPDIR/user-data" <<EOF
#cloud-config
package_update: true
packages:
  - docker.io
  - curl
  - jq
  - make

users:
  - name: $GH_USER
    groups: [docker, sudo]
    shell: /bin/bash
    lock_passwd: false
    passwd: $SSH_PASSWORD_HASH

ssh_pwauth: true

# Expose EVETEST_* variables to all processes, including the runner service.
# EVETEST_BROKER_ADDRESS is written last so it takes precedence.
write_files:
  - path: /etc/environment
    content: "${EVETEST_ENV_CONTENT}\nEVETEST_BROKER_ADDRESS=$BROKER_ADDR\n"
    append: true
  # The GitHub runner also reads its own .env file for injected env vars.
  # Written deferred so the directory exists (created by runcmd).
  - path: /opt/actions-runner/.env
    content: "${EVETEST_ENV_CONTENT}\nEVETEST_BROKER_ADDRESS=$BROKER_ADDR\n"
    defer: true
  # Add ~/go/bin to PATH for interactive SSH sessions.
  - path: /etc/profile.d/gopath.sh
    content: 'export PATH="\$HOME/go/bin:\$PATH"'
    permissions: '0644'
$DOCKER_CONFIG_ENTRY

runcmd:
  - systemctl enable --now docker
  - mkdir -p /opt/actions-runner
  - |
    set -e
    cd /opt/actions-runner
    RUNNER_VERSION=\$(curl -s https://api.github.com/repos/actions/runner/releases/latest \
      | jq -r .tag_name | sed 's/v//')
    curl -sLO "https://github.com/actions/runner/releases/download/v\${RUNNER_VERSION}/actions-runner-linux-x64-\${RUNNER_VERSION}.tar.gz"
    tar -xzf "actions-runner-linux-x64-\${RUNNER_VERSION}.tar.gz"
    chown -R $GH_USER:$GH_USER /opt/actions-runner
    # config.sh refuses to run as root; run it as the VM user instead.
    sudo -u $GH_USER ./config.sh \
      --url "https://github.com/$GH_REPO" \
      --token "$GH_TOKEN" \
      --labels "$VM_NAME" \
      --name   "$VM_NAME" \
      --unattended
    # svc.sh install must run as root; pass the username to run the service as.
    ./svc.sh install $GH_USER
    ./svc.sh start
EOF

# ── Build cloud-init seed ISO ────────────────────────────────────────────────
# Write the ISO directly into IMAGE_DIR so the libvirt-qemu user can access it.
SEED_ISO="${IMAGE_DIR}/${VM_NAME}-seed.iso"
genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock \
    "$TMPDIR/user-data" "$TMPDIR/meta-data" 2>/dev/null

# ── Create and start the VM ──────────────────────────────────────────────────
echo "Creating VM '$VM_NAME' (${VCPUS} vCPU, ${RAM_MB}MB RAM, ${DISK_GB}GB disk)..."
virt-install \
    --name        "$VM_NAME" \
    --memory      "$RAM_MB" \
    --vcpus       "$VCPUS" \
    --disk        "path=$VM_DISK,format=qcow2" \
    --disk        "path=$SEED_ISO,device=cdrom" \
    --network     network=default \
    --os-variant  ubuntu24.04 \
    --noautoconsole \
    --import \
    --wait 0

# ── Wait for VM to obtain a DHCP lease ──────────────────────────────────────
echo "Waiting for VM to obtain an IP address (timeout: 5 min)..."
VM_IP=""
for _ in $(seq 1 60); do
    VM_IP=$(virsh domifaddr "$VM_NAME" --source lease 2>/dev/null \
        | awk '/ipv4/ {split($4, a, "/"); print a[1]; exit}')
    [[ -n "$VM_IP" ]] && break
    sleep 5
done

echo ""
if [[ -n "$VM_IP" ]]; then
    echo "VM '$VM_NAME' is up at $VM_IP. The GitHub runner will self-register in ~2 minutes."
    echo ""
    echo "Useful commands:"
    echo "  SSH:      ssh $GH_USER@$VM_IP   (password: $SSH_PASSWORD)"
    echo "  Console:  virsh console $VM_NAME   (Ctrl+] to exit)"
else
    echo "VM '$VM_NAME' is booting (DHCP lease not yet visible — timed out)."
    echo "Run 'virsh domifaddr $VM_NAME' to get the IP once the VM is up."
    echo ""
    echo "Useful commands:"
    echo "  Get IP:   virsh domifaddr $VM_NAME"
    echo "  SSH:      ssh $GH_USER@<vm-ip>   (password: $SSH_PASSWORD)"
    echo "  Console:  virsh console $VM_NAME   (Ctrl+] to exit)"
fi
echo ""
echo "EVETEST_BROKER_ADDRESS=$BROKER_ADDR is set inside the runner."
echo "Make sure the broker is running on this host:"
echo "  make -C .. libvirt-run-broker-container"

# ── Write env file for evetest CLI ──────────────────────────────────────────
# A child process cannot export variables to the parent shell, so we write an
# env file instead.  Source it once to point the evetest CLI at this runner.
ENV_FILE="$(dirname "$0")/evetest-runner.env"
if [[ -n "$VM_IP" ]]; then
    echo "export EVETEST_API_ADDRESS=$VM_IP" > "$ENV_FILE"
    echo ""
    echo "To use the evetest CLI against this runner:"
    echo "  source $ENV_FILE"
else
    echo ""
    echo "Once you have the VM IP, run:"
    echo "  export EVETEST_API_ADDRESS=<vm-ip>"
fi
