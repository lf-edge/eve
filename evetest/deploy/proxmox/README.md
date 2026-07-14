# evetest broker on Proxmox VE

This directory contains everything needed to run the evetest **broker** against a
[Proxmox VE](https://www.proxmox.com/en/) host, using the `proxmox` device provider.

## Prerequisites (on the Proxmox host)

Set these up on the PVE host itself before running the installer:

- A VM disk storage (default `local-lvm`) and an **import**-content storage (default
  `local`, with the `import` content type enabled) — the broker uploads EVE/SDN disk images
  there. The installer enables the `snippets` content type on `local` for you.
- The `dnsmasq` package must be installed on the PVE host (`apt-get install dnsmasq`) — it
  is PVE SDN's DHCP backend for the `evu` uplink VNet and is **not installed by default**.
  The installer checks for it and fails fast with a clear message if it's missing.
  Installing it also enables and starts the plain system-wide `dnsmasq.service`*, which
  binds the same ports PVE's own per-zone `dnsmasq@evetest.service` needs — leave it running
  and the broker VM will fail to start with `Address already in use`. Disable it once,
  right after installing the package:

  ```sh
  apt-get install -y dnsmasq
  systemctl disable --now dnsmasq
  ```

- `ifupdown2` must be installed (`apt-get install ifupdown2`) so PVE can apply new SDN
  bridges live via `ifreload`, without a reboot. Most PVE hosts have it by default.
- If you want the `evu` uplink's IPv6 subnet (on by default, `fd11:778b:03dd:2222::/64`),
  the PVE host needs a real IPv6 route to the internet: PVE auto-detects the outbound
  interface for that subnet's SNAT rule by doing a route lookup against a public IPv6
  address, and if that lookup fails, PVE silently aborts *all* local network config
  generation for the zone — not just IPv6 — so the `evu` bridge itself never gets created
  and `qm start` fails with `bridge 'evu' does not exist`. The installer detects this ahead
  of time and automatically skips the IPv6 subnet (with a warning) if the host has no IPv6
  route, so this only bites you if you pass `--uplink-ipv6-subnet` explicitly on such a
  host. If your LAN actually provides IPv6 but the PVE host isn't picking up a global
  address via SLAAC, it's likely because IPv6 forwarding is enabled on the LAN bridge (PVE
  does this for VM traffic), which makes the kernel ignore Router Advertisements by default
  (`accept_ra=1` only accepts RAs when forwarding is disabled). A plain `sysctl -w` or
  `/etc/sysctl.d/*.conf` override is *not enough*: every SDN operation (including running
  this installer) calls `pvesh set /cluster/sdn`, which reloads the network config via
  `ifreload` and, as a side effect of re-applying bridge forwarding, resets `accept_ra` back
  to its default — undoing a one-off/boot-time-only sysctl. Pin it as a `post-up` hook on
  the bridge in `/etc/network/interfaces` instead, so it's re-applied every time the
  interface comes up (boot *and* every `ifreload`), replacing `vmbr0` with your LAN bridge:

  ```sh
  cp /etc/network/interfaces /etc/network/interfaces.bak
  # Add this line inside the "iface vmbr0 inet static" block:
  #     post-up sysctl -w net.ipv6.conf.vmbr0.accept_ra=2
  # Then apply it now (it'll self-apply on every future ifreload/boot from here on):
  ifreload -a
  # Force an immediate router solicitation instead of waiting for the next periodic RA:
  sysctl -w net.ipv6.conf.vmbr0.disable_ipv6=1
  sysctl -w net.ipv6.conf.vmbr0.disable_ipv6=0
  ```

- For devices to actually reach the Internet over the `evu` uplink's IPv6 subnet (as
  opposed to just getting a DHCPv6 address and local link-local connectivity), the PVE host
  needs `net.ipv6.conf.all.forwarding=1`. PVE's SDN code sets `forwarding=1` on the specific
  interfaces it manages (`evu`, the uplink bridge), but never touches the global `all`
  setting, which is `0` by default on most Debian/PVE installs. Symptom: DHCPv6 works (the
  guest gets a real global IPv6 address and a default route via RA), and packets reach the
  `evu` bridge, but never reach the uplink interface or beyond — no firewall involved (PVE
  firewall disabled, `ip6tables`/`nftables` FORWARD chains empty), the kernel just never
  forwards them. Unlike `accept_ra` above, this is a genuinely global sysctl, not tied to a
  specific bridge's `/etc/network/interfaces` stanza, so it is *not* reset by
  `ifreload`/SDN re-apply — a plain persistent override is enough:

  ```sh
  sysctl -w net.ipv6.conf.all.forwarding=1
  echo 'net.ipv6.conf.all.forwarding=1' > /etc/sysctl.d/99-evetest-ipv6-forward.conf
  ```

### Quick summary (everything above, in one place)

Run on the PVE host before the installer:

```sh
apt-get install -y dnsmasq ifupdown2
systemctl disable --now dnsmasq   # frees the ports PVE's own per-zone dnsmasq needs
```

Only needed if you want the `evu` uplink's IPv6 subnet and your LAN bridge doesn't
already have working IPv6 (skip if the installer's IPv6 subnet works out of the box, or
if you're fine with it auto-skipping IPv6):

```sh
# add "post-up sysctl -w net.ipv6.conf.vmbr0.accept_ra=2" to the "iface vmbr0 inet
# static" block in /etc/network/interfaces, then:
ifreload -a
sysctl -w net.ipv6.conf.vmbr0.disable_ipv6=1 net.ipv6.conf.vmbr0.disable_ipv6=0
sysctl -w net.ipv6.conf.all.forwarding=1
echo 'net.ipv6.conf.all.forwarding=1' > /etc/sysctl.d/99-evetest-ipv6-forward.conf
```

## Install (on the Proxmox host)

```sh
ssh root@<pve-host>
wget <release-url>/evetest-broker-proxmox-installer.sh
chmod +x evetest-broker-proxmox-installer.sh
./evetest-broker-proxmox-installer.sh            # all defaults; prompts for the root@pam password
```

The installer (idempotent) installs the hookscript and cloud-init snippet, pre-provisions
the `evetest` SDN zone + `evu` uplink VNet/subnet (DHCP + SNAT), and creates & starts the
broker VM. Rerunning it reuses the existing `evetest-broker` VM by name instead of creating
a new one, and if a run fails partway through creating a brand-new VM, that VM is
automatically destroyed again so failed/interrupted runs don't leave stray VMs behind. Run
with `--help` to see all flags; common overrides:

```sh
./evetest-broker-proxmox-installer.sh \
  --storage local-lvm --import-storage local \
  --lan-bridge vmbr0 --broker-vm-ssh-pubkey /root/.ssh/id_rsa.pub \
  --broker-log-level debug --broker-max-clients 3 \
  --with-oci-registry-mirrors
```

The broker authenticates to the Proxmox API as the real `root@pam` user (not an API
token), so the installer always prompts you interactively for that account's password
(masked, never accepted as a flag, never touching shell history). The password/URL/etc.
are written into the broker VM's `/etc/evetest/broker.env`. The broker container image
tag is **baked into the installer** from `evetest/VERSION` at assembly time (e.g.
`lfedge/evetest-broker:v0.0.1`); override with `--broker-image`.

### Docker registry credentials

The broker uses Docker to pull EVE and evetest-SDN images. Pass `--docker-username
USER --docker-password PASS` (both required together, and optionally
`--docker-registry SERVER`, default Docker Hub) to authenticate those pulls —
useful to avoid Docker Hub's anonymous-pull rate limits.

### Broker log level

Pass `--broker-log-level LEVEL` (e.g. `debug`, `info`, `warn`, `error`) to set
`EVETEST_LOG_LEVEL` in the broker VM's `broker.env`. Omit it to leave the broker at
its own default (`info`).

### Max concurrent clients

Pass `--broker-max-clients N` to set `EVETEST_BROKER_MAX_CLIENTS`, a simple guard
against hypervisor over-provisioning: once `N` evetest clients are connected, the broker
rejects any further new `Connect` calls with an error until a session frees up. Default
is `-1` (unlimited).

### Docker image cleanup

The broker periodically removes old, unused Docker images (EVE/SDN image versions
pulled over time) so they don't fill up the VM's disk. Pass
`--docker-image-retention MINUTES` (default `10080`, 7 days) to change how long an
unused image is kept, and `--docker-disk-usage-threshold PERCENT` (default `80`) to
change the disk usage percentage at or above which the broker aggressively evicts the
oldest unused images regardless of the retention setting. Only images the broker
itself pulled or built are ever eligible for removal -- anything else on the VM (an
image currently backing any container, running or stopped, such as the broker's own
image and the OCI registry mirrors; or an image the broker never touched, e.g. one you
pulled manually for something unrelated) is never removed, no matter how old or unused
it looks.

### OCI registry mirrors

Pass `--with-oci-registry-mirrors` (and optionally `--registry-mirror-base-port`,
default `5000`) to also run pull-through cache containers on the broker VM for
`docker.io`, `ghcr.io`, `quay.io`, `registry.k8s.io`, `gcr.io`, and
`mcr.microsoft.com`. Their addresses are sent to every evetest client automatically,
no manual configuration needed. If you already export one of the
`EVETEST_REGISTRY_MIRROR_*` env vars on your own evetest container, that value
wins over the broker-provided one for that registry.

## Point evetest at the broker

The installer itself waits for the broker VM's LAN IP and prints the exact `export
EVETEST_BROKER_ADDRESS=...` command to run once it's ready — just copy it from the
installer's output. If you need to look it up again later (e.g. after a host reboot):

```sh
# On the proxmox host (once the guest agent is up):
apt-get install -y jq
VMID=$(qm list | awk '$2=="evetest-broker" {print $1}')
qm guest cmd "$VMID" network-get-interfaces | jq '.[] | select(.name=="eth0") | ."ip-addresses"' # LAN-facing NIC IPs

# On the test runner:
export EVETEST_BROKER_ADDRESS=<broker-VM-LAN-IP>
make evetest NAME=<TestFunctionName>
```

Ensure the broker gRPC port (`50221`) is allowed by any firewall between the evetest
container and the broker VM.

## Uninstall

```sh
./evetest-broker-proxmox-installer.sh --destroy
```

This stops and destroys the broker VM, deletes the `evetest` SDN zone and its VNets
(`evu`, and any leftover `evx*` xconnect VNets), clears the zone's DHCP lease database
(a stale, never-expiring lease left behind by a destroyed VM would otherwise block that
same address from being reassigned on the next install), and removes the installed
snippets. It is best-effort. The downloaded Ubuntu cloud image is left in place.

## Architecture

Background on how the pieces fit together -- useful for troubleshooting or modifying
the installer, but not required just to get a broker running.

### How it fits together

The broker runs **inside a VM on the Proxmox host** and is **dual-homed**:

- `net0` on the external **LAN bridge** (e.g. `vmbr0`) — the broker's gRPC (`:50221`) is
  reachable here by evetest containers.
- `net1` on the **SDN uplink VNet** (`evu`) — lets the broker reach the SDN VMs' gRPC for
  `ConnectTunnelToSDN` (the only broker→SDN-VM connection; everything else goes through the
  Proxmox API).

This keeps the hypervisor clean (no Docker/broker/SSH on the PVE host itself). The one
thing the broker cannot do from inside a VM is the host-level xconnect L2-forwarding tweaks
(LACP / EAPOL / LLDP / ARP), so those are applied by a **Proxmox hookscript**
(`evetest-hook.pl`) installed on the host and attached to every VM the broker creates; it
runs on `post-start` and enables forwarding on the `evx*` xconnect bridges. On `post-stop`
it also cleans up any stale DHCP leases the VM held on the `evu` network, so a later VM
reusing the same address doesn't collide with an old, not-yet-expired lease.

### Files

- `evetest-hook.pl` — the host hookscript (installed to `/var/lib/vz/snippets/`).
- `broker-cloudinit.yaml` — cloud-init user-data template for the broker VM (installs
  Docker, runs the broker container with host networking).
- `installer.sh.tmpl` — installer template. `make proxmox-broker-installer` assembles it
  with the two files above into the self-contained
  `evetest-broker-proxmox-installer.sh`.

### Networking details

The installer creates a **single** uplink VNet and attaches the broker VM to it, so it can
reach every SDN VM over that one uplink:

- `net0` — external LAN bridge, DHCP. Provides the broker VM's **default route** (Internet
  for the Docker pull, and replies to test clients).
- `net1` — `evu` (the uplink), **static** `<subnet>.2/…`, no gateway.

The uplink NIC uses a static address with no gateway on purpose: it is on-link to the SDN
subnet, so it doesn't compete for the default route. Every SDN VM is placed on `evu` by the
broker and gets its address from that subnet's DHCP (which starts at `.3`, leaving `.2` for
the broker VM). `evu` also gets an **IPv6** subnet (internal ULA, independent of external
LAN IPv6) whenever `--uplink-ipv6-subnet` is non-empty (the default), so SDN VMs are
dual-stack — unless the PVE host has no IPv6 route to the Internet, in which case the
installer auto-skips it (see Prerequisites).

The `evetest` SDN zone and the `evu` uplink VNet + subnets are **fully owned by
the installer** — the broker provider never creates or deletes them (that would break the
always-running broker VM). The broker only creates/removes the per-test `evx*`
**xconnect** VNets (virtual crossover cables between EVE and SDN VMs).
