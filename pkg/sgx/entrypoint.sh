#!/bin/bash

ensure_aesm_service() {
  AESM_SOCKET=/var/run/aesmd/aesm.socket

  if [ -e "$AESM_SOCKET" ]; then
    return 0
  fi

  LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm /opt/intel/sgxpsw/aesm/aesm_service

  waited=0
  while [ ! -e "$AESM_SOCKET" ] && [ "$waited" -lt 60 ]; do
    echo "$(date -Ins -u) waiting for $AESM_SOCKET"
    sleep 3
    waited=$((waited + 3))
  done
  if [ ! -e "$AESM_SOCKET" ]; then
    echo "$(date -Ins -u) gave up waiting for $AESM_SOCKET"
  else
    echo "$(date -Ins -u) waited $waited for $AESM_SOCKET"
  fi
}

if [ ! -c "/dev/isgx" ] && [ ! -d "/dev/sgx" ]; then
  echo "$(date -Ins -u) no support for sgx"
  if [ -f "$DEVICE_KEY_NAME_SGX" ]; then
    echo "$(date -Ins -u) cannot unseal previously sealed key"
    exit 1
  fi
  exit 0
fi

CONFIG_DIR=/hostfs/config
DEVICE_KEY_NAME="$CONFIG_DIR/device.key.pem"
DEVICE_KEY_NAME_SGX="$CONFIG_DIR/device.key.pem.sgx"
SGX_DIR="/run/sgx"
DEVICE_KEY_NAME_UNSEAL_SGX="$SGX_DIR/device.key.pem"

mount -o remount,exec /dev

mkdir -p /var/run/aesmd
mkdir -p "$SGX_DIR"

cd /app || exit 1

CONFIG_PART="$(findmnt -vfno source --mountpoint "$CONFIG_DIR")"
REMOUNTED=

# if we have device key, try to seal it
if [ -f "$DEVICE_KEY_NAME" ]; then
  if [ ! -f "$DEVICE_KEY_NAME_SGX" ]; then
    # remount config to write new sealed key
    mount -o remount,flush,dirsync,noatime,rw "$CONFIG_DIR"
    blockdev --flushbufs "$CONFIG_PART"
    sleep 1
    sync
    REMOUNTED=1
    ensure_aesm_service
    if ! ./sealer seal "$DEVICE_KEY_NAME" "$DEVICE_KEY_NAME_SGX"; then
      echo "$(date -Ins -u) seal failed"
      rm -rf "$DEVICE_KEY_NAME_SGX"
      if [ -n "$REMOUNTED" ]; then
        blockdev --flushbufs "$CONFIG_PART"
        sync
        mount -o remount,flush,ro "$CONFIG_DIR"
      fi
    fi
  fi
fi

# if we have sealed key
if [ -f "$DEVICE_KEY_NAME_SGX" ]; then
  ensure_aesm_service
  # try to unseal key and store in memory
  if ! ./sealer unseal "$DEVICE_KEY_NAME_SGX" "$DEVICE_KEY_NAME_UNSEAL_SGX"; then
    echo "$(date -Ins -u) unseal failed"
    if [ -n "$REMOUNTED" ]; then
      blockdev --flushbufs "$CONFIG_PART"
      sync
      mount -o remount,flush,ro "$CONFIG_DIR"
    fi
  else
    if [ -f "$DEVICE_KEY_NAME" ]; then
      if [ -z "$REMOUNTED" ]; then
        mount -o remount,flush,dirsync,noatime,rw "$CONFIG_DIR"
      fi
      rm -rf "$DEVICE_KEY_NAME"
      blockdev --flushbufs "$CONFIG_PART"
      sleep 1
      sync
    fi
    # copy real config into in-memory config
    cp -rp "$CONFIG_DIR"/* "$SGX_DIR/"
    umount -f "$CONFIG_DIR" || echo "$(date -Ins -u) failed to umount"
    # mount in0memory config instead real
    mount --rbind "$SGX_DIR" "$CONFIG_DIR" || echo "$(date -Ins -u) failed to mount"
  fi
fi
