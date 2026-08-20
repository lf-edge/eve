# evetest GitHub Runner

Scripts for creating and destroying a local KVM/libvirt Ubuntu VM that runs
as a GitHub self-hosted runner, pre-configured for use with the evetest
framework in distributed mode with the libvirt provider.

Intended for local experimentation only — not part of the production CI pipeline.

## Prerequisites

- libvirt + KVM (`virt-install`, `virsh`, `qemu-img`, `genisoimage`)
- User in the `libvirt` group with write access to `/var/lib/libvirt/images`:

  ```bash
  sudo usermod -aG libvirt $USER
  sudo chgrp libvirt /var/lib/libvirt/images
  sudo chmod g+w /var/lib/libvirt/images
  # Log out and back in for the group change to take effect
  ```

- libvirt default network active (`virsh net-start default`)
- Docker (to run the evetest broker on the host)
- evetest broker user created on the host (one-time setup):

  ```bash
  cd evetest   # from the EVE repo root
  sudo make libvirt-setup-broker-user
  ```

- Internet access (to download the Ubuntu cloud image on first run)

## Usage

```bash
# PAT is a GitHub Personal Access Token configured with read and write access
# to eve repository (your fork) Administration.
# Create one at:
# https://github.com/settings/personal-access-tokens/new
GH_USERNAME=user123   # Change to your GitHub username
GH_PAT=github_pat_xxx # Change to your GitHub PAT

# 1. Create the runner VM
./vm-create.sh --user ${GH_USERNAME} --pat ${GH_PAT}

# 2. Point the evetest CLI at the runner (run in the same terminal)
source ./evetest-runner.env  # sets EVETEST_API_ADDRESS to the VM's IP

# 3. Start the broker on your laptop (in a separate terminal)
cd ..  # Run from the evetest directory
make libvirt-run-broker-container

# 4. Destroy the runner when done
./vm-destroy.sh --user ${GH_USERNAME} --pat ${GH_PAT}
```

`vm-create.sh` accepts the following options:

| Option | Default | Description |
|--------|---------|-------------|
| `--user <username>` | — | GitHub username (required); repo is always `<username>/eve` |
| `--pat <pat>` | — | GitHub PAT with Read & Write Administration permission (required) |
| `--name <name>` | `evetest-runner` | VM and runner name |
| `--cpus <n>` | `2` | Number of vCPUs |
| `--ram <MB>` | `4096` | RAM in MB |
| `--disk <GB>` | `20` | Disk size in GB |
| `--password <password>` | `password123` | SSH password; username is the GitHub username |
| `--broker-addr <ip>` | gateway IP of the libvirt default network | `EVETEST_BROKER_ADDRESS` value |
| `--image-dir <dir>` | `/var/lib/libvirt/images` | Directory for VM disks and the cached base image |

`vm-destroy.sh` accepts the following options:

| Option | Default | Description |
|--------|---------|-------------|
| `--name <name>` | `evetest-runner` | VM name to destroy |
| `--user <username>` | — | GitHub username; if set together with `--pat`, unregisters the runner |
| `--pat <pat>` | — | GitHub PAT with Read & Write Administration permission |

The runner VM is intentionally relatively small because in distributed mode all EVE and
SDN VMs are created by the broker directly on the host — the runner only runs
the lightweight evetest container (Adam controller + gRPC server + test binary).

## How it works

- The VM gets an IP on libvirt's default NAT network (`192.168.122.x`).
  The host is reachable from the VM at the gateway address `192.168.122.1`,
  which is the default value of `--broker-addr`.
- All `EVETEST_*` variables present in the host environment at VM creation time
  are propagated into the VM (written to `/etc/environment` and the runner's
  own `.env` file), so they are available to every workflow step and interactive
  SSH session. `EVETEST_BROKER_ADDRESS` is always appended last and cannot be
  overridden by the host environment.
- After the VM obtains a DHCP lease, `vm-create.sh` writes the VM's IP address
  to `gh-runner/evetest-runner.env` as `export EVETEST_API_ADDRESS=<ip>`.
  Source this file in your terminal to point the `evetest` CLI at the runner.
  The file (`gh-runner/evetest-runner.env`) is deleted automatically by
  `vm-destroy.sh` and is listed in `.gitignore`.
- The Ubuntu 24.04 cloud image is downloaded once and cached locally.
  Subsequent VM creations use a qcow2 overlay on top of the cached image,
  so disk creation is near-instant.
