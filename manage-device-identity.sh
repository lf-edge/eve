#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./manage-device-identity.sh --store-id [--host <ssh-host>] [--backup-dir <dir>]
  ./manage-device-identity.sh --store-tpm-id [--host <ssh-host>] [--backup-dir <dir>]
  ./manage-device-identity.sh --enable-ssh [--host <ssh-host>]
  ./manage-device-identity.sh --restore-local-id [--backup-dir <dir>]
  ./manage-device-identity.sh --restore-tpm-id [--backup-dir <dir>]
  ./manage-device-identity.sh --restore-id [--host <ssh-host>] [--backup-dir <dir>]
  ./manage-device-identity.sh --restore-id-when-ready [--host <ssh-host>] [--backup-dir <dir>] [--wait-interval-sec <n>] [--wait-timeout-sec <n>]
  ./manage-device-identity.sh --clean-id [--backup-dir <dir>]

Options:
  --store-id            Auto-detect local device identity type and back it up.
                        Software-backed: stores /persist/certs and /config identity.
                        TPM-backed: stores /config/soft_serial plus local ./swtpm.
                        For local_eve, auto-enables SSH through zcli if needed.
  --store-tpm-id        Copy TPM-backed local QEMU identity:
                        - /config/soft_serial into ./conf and backup
                        - optional TPM/bootstrap config files into ./conf and backup
                        - local ./swtpm TPM state into backup
  --enable-ssh          For local_eve, enable device SSH through zcli using
                        the node name from ./conf/soft_serial or backup config.
  --restore-local-id    Auto-detect backup identity type and restore local
                        identity into this repo before the next local QEMU boot.
  --restore-tpm-id      Restore TPM-backed local QEMU identity into this repo:
                        - ./conf/soft_serial and optional TPM/bootstrap files
                        - ./swtpm TPM state
                        Run this before starting the next local QEMU boot.
  --restore-id          Restore identity files from backup into device /persist/certs.
  --restore-id-when-ready
    Wait until SSH is reachable, then restore identity files.
  --clean-id            Remove device identity from ./conf so the next build
                        onboards as a new device. Keeps soft_serial, onboard
                        certs, server, and root-certificate. Optionally
                        removes backup dir.
  --host <ssh-host>     SSH host (default: local_eve).
  --backup-dir <dir>    Backup base dir (default: ./persist-backup/<host>).
  --wait-interval-sec <n>
                        Poll interval for --restore-id-when-ready (default: 5).
  --wait-timeout-sec <n>
                        Timeout for --restore-id-when-ready (default: 0 = no timeout).
  -h, --help            Show this help.
EOF
}

MODE=""
HOST="local_eve"
BACKUP_BASE_OVERRIDE=""
WAIT_INTERVAL_SEC=5
WAIT_TIMEOUT_SEC=0
SSH_RECOVERY_ATTEMPTED=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --store-id)
      if [[ -n "${MODE}" && "${MODE}" != "store" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="store"
      ;;
    --store-tpm-id)
      if [[ -n "${MODE}" && "${MODE}" != "store_tpm" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="store_tpm"
      ;;
    --enable-ssh)
      if [[ -n "${MODE}" && "${MODE}" != "enable_ssh" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="enable_ssh"
      ;;
    --restore-id)
      if [[ -n "${MODE}" && "${MODE}" != "restore" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="restore"
      ;;
    --restore-local-id)
      if [[ -n "${MODE}" && "${MODE}" != "restore_local" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="restore_local"
      ;;
    --restore-tpm-id)
      if [[ -n "${MODE}" && "${MODE}" != "restore_tpm" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="restore_tpm"
      ;;
    --restore-id-when-ready)
      if [[ -n "${MODE}" && "${MODE}" != "restore_wait" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="restore_wait"
      ;;
    --clean-id)
      if [[ -n "${MODE}" && "${MODE}" != "clean" ]]; then
        echo "Only one mode is allowed: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
        exit 1
      fi
      MODE="clean"
      ;;
    --host)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Missing value for --host" >&2
        exit 1
      fi
      HOST="$1"
      ;;
    --backup-dir)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Missing value for --backup-dir" >&2
        exit 1
      fi
      BACKUP_BASE_OVERRIDE="$1"
      ;;
    --wait-interval-sec)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Missing value for --wait-interval-sec" >&2
        exit 1
      fi
      WAIT_INTERVAL_SEC="$1"
      ;;
    --wait-timeout-sec)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Missing value for --wait-timeout-sec" >&2
        exit 1
      fi
      WAIT_TIMEOUT_SEC="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ -z "${MODE}" ]]; then
  echo "Select mode: --store-id, --store-tpm-id, --enable-ssh, --restore-local-id, --restore-tpm-id, --restore-id, --restore-id-when-ready, or --clean-id" >&2
  usage
  exit 1
fi

if ! [[ "${WAIT_INTERVAL_SEC}" =~ ^[0-9]+$ ]]; then
  echo "--wait-interval-sec must be a non-negative integer" >&2
  exit 1
fi
if ! [[ "${WAIT_TIMEOUT_SEC}" =~ ^[0-9]+$ ]]; then
  echo "--wait-timeout-sec must be a non-negative integer" >&2
  exit 1
fi
if [[ "${WAIT_INTERVAL_SEC}" -eq 0 ]]; then
  echo "--wait-interval-sec must be greater than 0" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_BASE_DEFAULT="${SCRIPT_DIR}/persist-backup/${HOST}"
BACKUP_BASE="${BACKUP_BASE_OVERRIDE:-${BACKUP_BASE_DEFAULT}}"
BACKUP_DIR="${BACKUP_BASE}/certs"
CONFIG_BACKUP_DIR="${BACKUP_BASE}/config"
CONF_DIR="${SCRIPT_DIR}/conf"
SWTPM_DIR="${SCRIPT_DIR}/swtpm"
SWTPM_BACKUP_DIR="${BACKUP_BASE}/swtpm"
IDENTITY_KIND_FILE="${BACKUP_BASE}/identity-kind.txt"
IDENTITY_KIND_SOFTWARE="software"
IDENTITY_KIND_TPM="tpm"

required_files=(
  "ecdh.cert.pem"
  "ecdh.key.pem"
  "attest.cert.pem"
  "attest.key.pem"
)

required_config_files=(
  "device.cert.pem"
  "soft_serial"
)

optional_config_files=(
  "device.key.pem"
  "tpm_credential"
  "onboard.cert.pem"
  "onboard.key.pem"
  "server"
  "root-certificate.pem"
  "v2tlsbaseroot-certificates.pem"
)

tpm_optional_config_files=(
  "tpm_credential"
  "onboard.cert.pem"
  "onboard.key.pem"
  "server"
  "root-certificate.pem"
  "v2tlsbaseroot-certificates.pem"
)

remove_if_missing_config_files=(
  "device.key.pem"
  "tpm_credential"
)

swtpm_runtime_files=(
  "swtpm-sock"
  "swtpm.pid"
  "swtpm.log"
)

is_remove_if_missing_config_file() {
  local needle="$1"
  local file
  for file in "${remove_if_missing_config_files[@]}"; do
    if [[ "${file}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

copy_remote_config_file() {
  local file="$1"
  local mode="$2"
  local remove_if_missing=0

  ensure_ssh_access || return 1

  if is_remove_if_missing_config_file "${file}"; then
    remove_if_missing=1
  fi

  if ssh "${HOST}" "test -f /config/${file}" >/dev/null 2>&1; then
    ssh "${HOST}" "cat /config/${file}" > "${CONFIG_BACKUP_DIR}/${file}"
    cp "${CONFIG_BACKUP_DIR}/${file}" "${CONF_DIR}/${file}"
    chmod "${mode}" "${CONFIG_BACKUP_DIR}/${file}" "${CONF_DIR}/${file}"
    return 0
  fi

  if [[ "${remove_if_missing}" -eq 1 ]]; then
    rm -f "${CONFIG_BACKUP_DIR}/${file}" "${CONF_DIR}/${file}"
  fi
  return 1
}

restore_config_file_from_backup() {
  local file="$1"
  local mode="$2"
  local remove_if_missing=0

  if is_remove_if_missing_config_file "${file}"; then
    remove_if_missing=1
  fi

  if [[ -f "${CONFIG_BACKUP_DIR}/${file}" ]]; then
    cp "${CONFIG_BACKUP_DIR}/${file}" "${CONF_DIR}/${file}"
    chmod "${mode}" "${CONF_DIR}/${file}"
    return 0
  fi

  if [[ "${remove_if_missing}" -eq 1 ]]; then
    rm -f "${CONF_DIR}/${file}"
  fi
  return 1
}

restore_required_local_config_file() {
  local file="$1"
  local mode="$2"

  if [[ -f "${CONFIG_BACKUP_DIR}/${file}" ]]; then
    cp "${CONFIG_BACKUP_DIR}/${file}" "${CONF_DIR}/${file}"
    chmod "${mode}" "${CONF_DIR}/${file}"
    return 0
  fi

  if [[ -f "${CONF_DIR}/${file}" ]]; then
    chmod "${mode}" "${CONF_DIR}/${file}"
    echo "Using existing local ${CONF_DIR}/${file}"
    return 0
  fi

  return 1
}

local_swtpm_pid() {
  local pid_file="${SWTPM_DIR}/swtpm.pid"
  if [[ ! -f "${pid_file}" ]]; then
    return 1
  fi
  cat "${pid_file}"
}

is_local_swtpm_running() {
  local pid
  pid="$(local_swtpm_pid)" || return 1
  [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

cleanup_swtpm_runtime_files() {
  local dir="$1"
  local file
  for file in "${swtpm_runtime_files[@]}"; do
    rm -f "${dir}/${file}"
  done
}

write_identity_kind() {
  printf "%s\n" "$1" > "${IDENTITY_KIND_FILE}"
}

ssh_probe() {
  ssh -o BatchMode=yes -o ConnectTimeout=3 "${HOST}" 'true' >/dev/null 2>&1
}

local_node_name() {
  local candidate
  for candidate in "${CONF_DIR}/soft_serial" "${CONFIG_BACKUP_DIR}/soft_serial"; do
    if [[ -f "${candidate}" ]]; then
      tr -d '[:space:]' < "${candidate}"
      return 0
    fi
  done
  return 1
}

maybe_enable_local_eve_ssh() {
  local node_name

  if [[ "${SSH_RECOVERY_ATTEMPTED}" -ne 0 ]]; then
    return 1
  fi
  SSH_RECOVERY_ATTEMPTED=1

  if [[ "${HOST}" != "local_eve" ]]; then
    return 1
  fi
  if [[ ! -x "${SCRIPT_DIR}/run_with_zcli.sh" ]]; then
    echo "Cannot auto-enable SSH for ${HOST}: missing executable ${SCRIPT_DIR}/run_with_zcli.sh" >&2
    return 1
  fi
  if [[ ! -f "${SCRIPT_DIR}/enable-ssh.sh" ]]; then
    echo "Cannot auto-enable SSH for ${HOST}: missing ${SCRIPT_DIR}/enable-ssh.sh" >&2
    return 1
  fi
  if ! node_name="$(local_node_name)"; then
    echo "Cannot auto-enable SSH for ${HOST}: missing soft_serial in ${CONF_DIR} or ${CONFIG_BACKUP_DIR}" >&2
    return 1
  fi

  echo "SSH is not reachable on ${HOST}; trying to enable it via controller for node ${node_name}"
  NODE_NAME="${node_name}" "${SCRIPT_DIR}/run_with_zcli.sh" "${SCRIPT_DIR}/enable-ssh.sh"
}

ensure_ssh_access() {
  local attempt

  if ssh_probe; then
    return 0
  fi

  if ! maybe_enable_local_eve_ssh; then
    echo "SSH is not reachable on ${HOST}" >&2
    return 1
  fi

  for attempt in 1 2 3 4 5 6; do
    if ssh_probe; then
      echo "SSH is reachable on ${HOST}"
      return 0
    fi
    sleep 2
  done

  echo "SSH is not reachable on ${HOST}" >&2
  return 1
}

detect_remote_identity_kind() {
  ensure_ssh_access || return 1
  if ssh "${HOST}" 'test -f /config/device.key.pem' >/dev/null 2>&1; then
    printf "%s\n" "${IDENTITY_KIND_SOFTWARE}"
    return 0
  fi
  if ssh "${HOST}" 'test -f /config/soft_serial' >/dev/null 2>&1; then
    printf "%s\n" "${IDENTITY_KIND_TPM}"
    return 0
  fi
  echo "Unable to detect identity type on ${HOST}: neither /config/device.key.pem nor /config/soft_serial is present." >&2
  return 1
}

detect_backup_identity_kind() {
  local kind
  if [[ -f "${IDENTITY_KIND_FILE}" ]]; then
    kind="$(tr -d '[:space:]' < "${IDENTITY_KIND_FILE}")"
    case "${kind}" in
      "${IDENTITY_KIND_SOFTWARE}"|"${IDENTITY_KIND_TPM}")
        printf "%s\n" "${kind}"
        return 0
        ;;
    esac
  fi

  if [[ -f "${CONFIG_BACKUP_DIR}/device.cert.pem" || -f "${CONF_DIR}/device.cert.pem" ]]; then
    printf "%s\n" "${IDENTITY_KIND_SOFTWARE}"
    return 0
  fi

  if [[ -d "${SWTPM_BACKUP_DIR}" || -f "${CONFIG_BACKUP_DIR}/soft_serial" || -f "${CONF_DIR}/soft_serial" ]]; then
    printf "%s\n" "${IDENTITY_KIND_TPM}"
    return 0
  fi

  echo "Unable to detect backed-up identity type under ${BACKUP_BASE}." >&2
  return 1
}

backup_local_swtpm_state() {
  local item

  if [[ ! -d "${SWTPM_DIR}" ]]; then
    echo "No local swtpm state directory at ${SWTPM_DIR}; skipping TPM state backup."
    return 0
  fi

  if is_local_swtpm_running; then
    echo "Warning: local swtpm appears to be running (pid $(local_swtpm_pid))."
    echo "Backing up live TPM state from ${SWTPM_DIR}; for the safest snapshot, stop QEMU and rerun the store command."
  fi

  rm -rf "${SWTPM_BACKUP_DIR}"
  install -d -m 700 "${SWTPM_BACKUP_DIR}"
  shopt -s dotglob nullglob
  for item in "${SWTPM_DIR}"/*; do
    if [[ -S "${item}" || -p "${item}" ]]; then
      continue
    fi
    cp -a "${item}" "${SWTPM_BACKUP_DIR}/"
  done
  shopt -u dotglob nullglob
  cleanup_swtpm_runtime_files "${SWTPM_BACKUP_DIR}"
  echo "Backed up local swtpm state to ${SWTPM_BACKUP_DIR}"
}

store_tpm_id() {
  echo "Storing TPM-backed local QEMU identity from ${HOST} into ${BACKUP_BASE}"
  install -d -m 755 "${CONF_DIR}"
  install -d -m 700 "${CONFIG_BACKUP_DIR}"

  if ! copy_remote_config_file "soft_serial" 0644; then
    echo "Missing required TPM identity file on ${HOST}: /config/soft_serial" >&2
    exit 1
  fi

  local file
  for file in "${tpm_optional_config_files[@]}"; do
    case "${file}" in
      onboard.key.pem)
        copy_remote_config_file "${file}" 0600 || true
        ;;
      *)
        copy_remote_config_file "${file}" 0644 || true
        ;;
    esac
  done

  backup_local_swtpm_state
  write_identity_kind "${IDENTITY_KIND_TPM}"

  echo "Done."
  echo "Backed up TPM identity inputs:"
  ls -l "${CONF_DIR}/soft_serial"
  if [[ -f "${CONF_DIR}/tpm_credential" ]]; then
    ls -l "${CONF_DIR}/tpm_credential"
  fi
  echo "Next step: run --restore-tpm-id before the next local QEMU boot."
}

restore_local_swtpm_state() {
  if [[ ! -d "${SWTPM_BACKUP_DIR}" ]]; then
    echo "No backed up local swtpm state at ${SWTPM_BACKUP_DIR}; skipping TPM state restore."
    return 0
  fi

  if is_local_swtpm_running; then
    echo "Local swtpm appears to be running (pid $(local_swtpm_pid)). Stop local QEMU before restoring TPM state." >&2
    exit 1
  fi

  rm -rf "${SWTPM_DIR}"
  install -d -m 700 "${SWTPM_DIR}"
  cp -a "${SWTPM_BACKUP_DIR}/." "${SWTPM_DIR}/"
  cleanup_swtpm_runtime_files "${SWTPM_DIR}"
  echo "Restored local swtpm state to ${SWTPM_DIR}"
}

restore_tpm_id() {
  install -d -m 755 "${CONF_DIR}"

  if ! restore_required_local_config_file "soft_serial" 0644; then
    echo "Missing required local TPM identity file: soft_serial" >&2
    echo "Looked in ${CONFIG_BACKUP_DIR}/soft_serial and ${CONF_DIR}/soft_serial" >&2
    echo "Run --store-tpm-id once against the currently running local QEMU before trying --restore-tpm-id." >&2
    exit 1
  fi

  local file
  for file in "${tpm_optional_config_files[@]}"; do
    case "${file}" in
      onboard.key.pem)
        restore_config_file_from_backup "${file}" 0600 || true
        ;;
      *)
        restore_config_file_from_backup "${file}" 0644 || true
        ;;
    esac
  done

  # For TPM-backed identity the device cert/key come from TPM state.
  rm -f "${CONF_DIR}/device.cert.pem" "${CONF_DIR}/device.key.pem"

  restore_local_swtpm_state
  write_identity_kind "${IDENTITY_KIND_TPM}"

  echo "Done."
  echo "Restored local TPM identity into ${CONF_DIR} and ${SWTPM_DIR}"
  echo "Next step: boot the rebuilt local QEMU. The device cert should be recreated from TPM state."
}

store_software_id() {
  echo "Storing identity files from ${HOST} into ${BACKUP_DIR}"
  install -d -m 700 "${BACKUP_DIR}"
  install -d -m 755 "${CONF_DIR}"
  install -d -m 700 "${CONFIG_BACKUP_DIR}"
  ensure_ssh_access || exit 1

  for file in "${required_files[@]}"; do
    ssh "${HOST}" "cat /persist/certs/${file}" > "${BACKUP_DIR}/${file}"
  done

  if ssh "${HOST}" 'test -f /persist/certs/ek.cert.pem'; then
    ssh "${HOST}" 'cat /persist/certs/ek.cert.pem' > "${BACKUP_DIR}/ek.cert.pem"
  else
    rm -f "${BACKUP_DIR}/ek.cert.pem"
  fi

  ssh "${HOST}" 'cat /persist/status/uuid' > "${BACKUP_BASE}/device-uuid.txt"
  ssh "${HOST}" 'date -u +"%Y-%m-%dT%H:%M:%SZ"' > "${BACKUP_BASE}/backup-timestamp-utc.txt"

  chmod 0644 "${BACKUP_DIR}"/*.cert.pem
  chmod 0600 "${BACKUP_DIR}"/*.key.pem

  # Keep config-image identity in sync with running device.
  for file in "${required_config_files[@]}"; do
    if ! copy_remote_config_file "${file}" 0644; then
      echo "Missing required device config file on ${HOST}: /config/${file}" >&2
      exit 1
    fi
  done

  if copy_remote_config_file "device.key.pem" 0600; then
    echo "Stored software-backed device private key from /config/device.key.pem"
  else
    echo "No /config/device.key.pem on device; treating identity as TPM-backed."
  fi

  if copy_remote_config_file "tpm_credential" 0644; then
    echo "Stored /config/tpm_credential"
  fi

  # Also sync onboarding/controller bootstrap files if present on device.
  copy_remote_config_file "onboard.cert.pem" 0644 || true
  copy_remote_config_file "onboard.key.pem" 0600 || true
  copy_remote_config_file "server" 0644 || true
  copy_remote_config_file "root-certificate.pem" 0644 || true
  copy_remote_config_file "v2tlsbaseroot-certificates.pem" 0644 || true

  backup_local_swtpm_state
  write_identity_kind "${IDENTITY_KIND_SOFTWARE}"

  echo "Done."
  echo "Backed up certs:"
  ls -l "${BACKUP_DIR}"
  echo "Synced conf files:"
  ls -l "${CONF_DIR}/device.cert.pem" "${CONF_DIR}/soft_serial"
  if [[ -f "${CONF_DIR}/device.key.pem" ]]; then
    ls -l "${CONF_DIR}/device.key.pem"
  fi
  if [[ -f "${CONF_DIR}/tpm_credential" ]]; then
    ls -l "${CONF_DIR}/tpm_credential"
  fi
}

restore_software_local_id() {
  install -d -m 755 "${CONF_DIR}"

  local file
  for file in "${required_config_files[@]}"; do
    if ! restore_required_local_config_file "${file}" 0644; then
      echo "Missing required local identity file: ${file}" >&2
      echo "Looked in ${CONFIG_BACKUP_DIR}/${file} and ${CONF_DIR}/${file}" >&2
      echo "If this is a TPM-backed local QEMU identity, use --restore-tpm-id instead." >&2
      echo "Run --store-id once against the currently running old QEMU before trying --restore-local-id." >&2
      exit 1
    fi
  done

  restore_config_file_from_backup "device.key.pem" 0600 || true
  restore_config_file_from_backup "tpm_credential" 0644 || true

  restore_config_file_from_backup "onboard.cert.pem" 0644 || true
  restore_config_file_from_backup "onboard.key.pem" 0600 || true
  restore_config_file_from_backup "server" 0644 || true
  restore_config_file_from_backup "root-certificate.pem" 0644 || true
  restore_config_file_from_backup "v2tlsbaseroot-certificates.pem" 0644 || true

  restore_local_swtpm_state
  write_identity_kind "${IDENTITY_KIND_SOFTWARE}"

  echo "Done."
  echo "Restored local config identity into ${CONF_DIR}"
  echo "Next step: boot the rebuilt local QEMU with this repo, then run --restore-id-when-ready to restore /persist/certs."
}

store_id() {
  local kind
  kind="$(detect_remote_identity_kind)"
  echo "Detected identity type on ${HOST}: ${kind}"
  case "${kind}" in
    "${IDENTITY_KIND_SOFTWARE}")
      store_software_id
      ;;
    "${IDENTITY_KIND_TPM}")
      store_tpm_id
      ;;
    *)
      echo "Unexpected identity type: ${kind}" >&2
      exit 1
      ;;
  esac
}

restore_local_id() {
  local kind
  kind="$(detect_backup_identity_kind)"
  echo "Detected backed-up identity type: ${kind}"
  case "${kind}" in
    "${IDENTITY_KIND_SOFTWARE}")
      restore_software_local_id
      ;;
    "${IDENTITY_KIND_TPM}")
      restore_tpm_id
      ;;
    *)
      echo "Unexpected identity type: ${kind}" >&2
      exit 1
      ;;
  esac
}

restore_id() {
  if [[ ! -d "${BACKUP_DIR}" ]]; then
    echo "Backup directory not found: ${BACKUP_DIR}" >&2
    echo "Expected backups under: ${BACKUP_BASE_DEFAULT}/certs" >&2
    exit 1
  fi

  for file in "${required_files[@]}"; do
    if [[ ! -f "${BACKUP_DIR}/${file}" ]]; then
      echo "Missing required backup file: ${BACKUP_DIR}/${file}" >&2
      exit 1
    fi
  done

  echo "Restoring persisted certs to ${HOST} from ${BACKUP_DIR}"
  ensure_ssh_access || exit 1
  ssh "${HOST}" 'install -d -m 700 /persist/certs'

  for file in "${required_files[@]}"; do
    cat "${BACKUP_DIR}/${file}" | ssh "${HOST}" "cat > /persist/certs/${file}"
  done

  if [[ -f "${BACKUP_DIR}/ek.cert.pem" ]]; then
    cat "${BACKUP_DIR}/ek.cert.pem" | ssh "${HOST}" 'cat > /persist/certs/ek.cert.pem'
  fi

  # Remove stale tpmmgr EdgeNodeCert status objects so zedagent does not send
  # a mixed old+new cert set and trigger EdgeNodeCertsRefused maintenance mode.
  ssh "${HOST}" '
    set -e
    dir="/persist/status/tpmmgr/EdgeNodeCert"
    ecdh_id="$(sha256sum /persist/certs/ecdh.cert.pem | awk "{print substr(\$1,1,32)}")"
    attest_id="$(sha256sum /persist/certs/attest.cert.pem | awk "{print substr(\$1,1,32)}")"
    if [ -d "${dir}" ]; then
      for f in "${dir}"/*.json; do
        [ -e "${f}" ] || continue
        base="$(basename "${f}" .json)"
        if [ "${base}" != "${ecdh_id}" ] && [ "${base}" != "${attest_id}" ]; then
          rm -f "${f}"
        fi
      done
    fi
  '

  ssh "${HOST}" '
    chmod 0644 /persist/certs/*.cert.pem
    [ -f /persist/certs/ecdh.key.pem ] && chmod 0600 /persist/certs/ecdh.key.pem
    [ -f /persist/certs/attest.key.pem ] && chmod 0600 /persist/certs/attest.key.pem
    sync
  '

  echo "Done."
  echo "Recommended next step: reboot ${HOST} so tpmmgr/zedagent republish restored certs."
  echo "Command: ssh ${HOST} 'reboot'"
}

wait_for_ssh() {
  local start elapsed
  start="$(date +%s)"
  echo "Waiting for SSH on ${HOST}..."

  if ! ssh_probe; then
    maybe_enable_local_eve_ssh || true
  fi

  while true; do
    if ssh_probe; then
      echo "SSH is reachable on ${HOST}"
      return 0
    fi

    elapsed="$(( $(date +%s) - start ))"
    if [[ "${WAIT_TIMEOUT_SEC}" -gt 0 && "${elapsed}" -ge "${WAIT_TIMEOUT_SEC}" ]]; then
      echo "Timed out waiting for SSH on ${HOST} after ${elapsed}s" >&2
      return 1
    fi
    echo "SSH not ready yet on ${HOST}; retrying in ${WAIT_INTERVAL_SEC}s (elapsed ${elapsed}s)"
    sleep "${WAIT_INTERVAL_SEC}"
  done
}

enable_ssh() {
  if ssh_probe; then
    echo "SSH is already reachable on ${HOST}"
    return 0
  fi

  if ! maybe_enable_local_eve_ssh; then
    echo "Failed to auto-enable SSH on ${HOST}" >&2
    exit 1
  fi

  wait_for_ssh
}

clean_id() {
  local id_files=(
    "${CONF_DIR}/device.cert.pem"
    "${CONF_DIR}/device.key.pem"
  )

  echo "Removing device identity files from ${CONF_DIR}:"
  for f in "${id_files[@]}"; do
    if [[ -f "${f}" ]]; then
      rm -f "${f}"
      echo "  removed: ${f}"
    else
      echo "  not found: ${f}"
    fi
  done
  echo "  kept: ${CONF_DIR}/soft_serial"

  if [[ -d "${BACKUP_DIR}" ]]; then
    echo ""
    echo "Backup directory exists: ${BACKUP_BASE}"
    read -r -p "Remove backup too? [y/N] " answer
    if [[ "${answer}" =~ ^[Yy]$ ]]; then
      rm -rf "${BACKUP_BASE}"
      echo "  removed: ${BACKUP_BASE}"
    else
      echo "  kept: ${BACKUP_BASE}"
    fi
  fi

  # Clean swtpm state so new device gets fresh TPM.
  local swtpm_dir="${SCRIPT_DIR}/swtpm"
  if [[ -d "${swtpm_dir}" ]]; then
    echo ""
    rm -rf "${swtpm_dir}"
    echo "  removed swtpm state: ${swtpm_dir}"
  fi

  echo ""
  echo "Done. Next build will onboard as a new device."
  echo "Onboard certs, server, and root-certificate are preserved."
}

case "${MODE}" in
  store)
    store_id
    ;;
  store_tpm)
    store_tpm_id
    ;;
  enable_ssh)
    enable_ssh
    ;;
  restore_local)
    restore_local_id
    ;;
  restore_tpm)
    restore_tpm_id
    ;;
  restore)
    restore_id
    ;;
  restore_wait)
    wait_for_ssh
    restore_id
    ;;
  clean)
    clean_id
    ;;
  *)
    echo "Unexpected mode: ${MODE}" >&2
    exit 1
    ;;
esac
