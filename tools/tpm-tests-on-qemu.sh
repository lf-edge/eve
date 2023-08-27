#!/usr/bin/env bash
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Some of the EVE unit-tests require a TPM to run, on Github runners there is
# no TPM, and as a result, we skip those tests. It is possible to simulate a TPM
# on the host using the tpm_vtpm_proxy kernel module and swtp, but there is a good
# chance that the runner's kernel is not compiled with tpm_vtpm_proxy support enabled.
#
# This script aims to solve the issue by spinning up a Ubuntu VM with swtpm
# emulating the TPM on the Ubuntu VM.

# add more TPM tests here
TESTS=(
  "/pillar/evetpm"
  )

IMG=ubuntu-20.04-server-cloudimg-amd64.img
GOLANG=https://go.dev/dl/go1.20.5.linux-amd64.tar.gz

sudo apt-get -qq update -y > /dev/null
sudo apt-get -qq install cloud-image-utils qemu swtpm wget libguestfs-tools > /dev/null

echo "[+] Downloading the ubuntu qemu image..."
if [ ! -f "$IMG" ]; then
  wget -q "https://cloud-images.ubuntu.com/releases/20.04/release/${IMG}"
  qemu-img resize "$IMG" +128G > /dev/null
fi

echo "[+] Setting up image credentials..."
ssh-keygen -q -N '' -f id_rsa
sudo virt-customize --ssh-inject "root:file:id_rsa.pub" --root-password password:whocares -a ${IMG} > /dev/null

# we need this for some reasons
cat >user-data <<EOF
#cloud-config
chpasswd: { expire: False }
ssh_pwauth: True
EOF

echo "[+] Creating user data image..."
cloud-localds user-data.img user-data

echo "[+] Preparing swtpm..."
mkdir /tmp/emulated_tpm
swtpm socket --tpmstate dir=/tmp/emulated_tpm --ctrl type=unixio,path=/tmp/emulated_tpm/swtpm-sock --log level=20 --tpm2 -d

echo "[+] Launching the vm..."
qemu-system-x86_64 \
  -drive "file=${IMG},format=qcow2" \
  -drive "file=user-data.img,format=raw" \
  -device rtl8139,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -chardev socket,id=chrtpm,path="/tmp/emulated_tpm/swtpm-sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -m 2G \
  -smp 4 \
  -display none \
  -daemonize

echo "[+] Waiting for vm to start..."
ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" 'touch /tmp/test'
while test $? -gt 0
do
  sleep 5
  echo "[+] Waiting for vm to start..."
  ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" 'touch /tmp/test'
done

echo "[+] Preparing the vm ..."
ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" << EOF
  sudo apt-get -qq update -y > /dev/null
  sudo apt-get -qq install tpm2-tools > /dev/null
  sudo mkdir -p /hostfs/sys/kernel/security/tpm0
  sudo touch /hostfs/sys/kernel/security/tpm0/binary_bios_measurements
  sudo mkdir -p /persist/status
EOF

echo "[+] Preparing the TPM ..."
ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" << EOF
  tpm2_clear > /dev/null
  tpm2_createprimary -c ek.ctx -C e > /dev/null
  tpm2_evictcontrol -c ek.ctx 0x81000001 > /dev/null
  tpm2_create -C ek.ctx -G rsa2048 -u srk.pub -r srk.priv -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth' > /dev/null
  tpm2_load -C ek.ctx -u srk.pub -r srk.priv -c srk.ctx > /dev/null
  tpm2_evictcontrol -C o -c srk.ctx 0x81000002 > /dev/null
EOF

echo "[+] Copying tests to vm ..."
scp -rp -q -i id_rsa -P 2222 -o "StrictHostKeyChecking no" pkg/pillar/ root@localhost:/tmp

echo "[+] Preparing golang..."
# We want this to expand here, not on the target, so:
# shellcheck disable=SC2087
ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" << EOF
  wget -q "$GOLANG"
  rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
EOF

echo "[+] Running tests ..."
for T in "${TESTS[@]}"; do
  TEST="cd /tmp$T && /usr/local/go/bin/go test -v -coverprofile=coverage.txt -covermode=atomic"
  ssh -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" "$TEST"
done

echo "[+] Copying code-coverage data..."
for T in "${TESTS[@]}"; do
  scp -rp -q -i id_rsa -P 2222 -o "StrictHostKeyChecking no" root@localhost:/tmp"$T"/coverage.txt pkg"$T"
done
