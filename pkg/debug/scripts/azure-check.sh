#!/bin/sh
# List/download the blobs from the Azure storage container.

# account name must be set as the first argument
ACCOUNT_NAME=""
# container name must be set as the second argument
CONTAINER_NAME=""
# if blob_name flag set will download blob instead of list blob in container
BLOB_NAME=""

# use base64 encoded 123 by default
ACCESS_KEY="MTIzCg=="
# default domain for azure
DOMAIN_NAME="blob.core.windows.net"
# default scheme is https
SCHEME="https"
# if defined will store curl output to the file
FILE_TO_SAVE=""
# if defined will set x-ms-range header from 0 to LIMIT_IN_BYTES
LIMIT_IN_BYTES=""

help() {
  cat <<__EOT__
Usage: ${0} <account-name> <container-name>  [-k <access_key>] [-b <blob_name>] [-d <domain_name>] [-o <file_to_save_output>] [-l <limit_in_bytes>] [-i] [-h]

Required argument:
1) account-name - account on Azure
2) container-name - container to use for list/download operations

Optional arguments:
-k <access_key> - access key for Azure account. If not defined we will use dummy key and the script will show errors contains headers
-b <blob_name> - if defined the script will download blob instead of listing blobs in container
-d <domain_name> - if defined will use instead of default blob.core.windows.net
-o <file_to_save_output> - store output into defined file instead of showing in stdout
-l <limit_in_bytes> - limit blob download in bytes
-i - use http instead of https
-h - show help
__EOT__
}

dependencies_check() {
  for prog in base64 openssl xxd curl; do
    if ! [ -x "$(command -v ${prog})" ]; then
      echo "Error: ${prog} is not installed." >&2
      exit 1
    fi
  done
}

args_parse() {
  ACCOUNT_NAME="${1}"
  CONTAINER_NAME="${2}"
  if [ -z "${CONTAINER_NAME}" ] || [ -z "${ACCOUNT_NAME}" ]; then
    echo "Error: account-name and container-name are required" >&2
    help "${0}"
    exit 1
  fi
  shift 2

  while true; do
    case "${1}" in
    -h*)
      help "${0}"
      exit 0
      ;;
    -b)
      BLOB_NAME="${2}"
      shift 2
      ;;
    -k)
      ACCESS_KEY="${2}"
      shift 2
      ;;
    -d)
      DOMAIN_NAME="${2}"
      shift 2
      ;;
    -o)
      FILE_TO_SAVE="${2}"
      shift 2
      ;;
    -l)
      LIMIT_IN_BYTES="${2}"
      shift 2
      ;;
    -i)
      SCHEME="http"
      shift
      ;;
    *)
      break
      ;;
    esac
  done
}

main() {
  # the same as in zedUpload
  AUTHORIZATION="SharedKey"
  STORAGE_SERVICE_VERSION="2020-04-08"

  REQUEST_METHOD="GET"
  REQUEST_DATE=$(TZ=GMT LC_ALL=en_US.utf8 date "+%a, %d %h %Y %H:%M:%S %Z")

  # HTTP Request headers
  X_MS_DATE_HEADER="x-ms-date:${REQUEST_DATE}"
  X_MX_VERSION_HEADER="x-ms-version:${STORAGE_SERVICE_VERSION}"
  X_MS_RANGE_HEADER="x-ms-range:bytes=0-${LIMIT_IN_BYTES}"

  # Build the SIGNATURE string

  if [ -z "${LIMIT_IN_BYTES}" ] || [ -z "${BLOB_NAME}" ]; then
    CANNONICALIZED_HEADERS="${X_MS_DATE_HEADER}\n${X_MX_VERSION_HEADER}"
  else
    CANNONICALIZED_HEADERS="${X_MS_DATE_HEADER}\n${X_MS_RANGE_HEADER}\n${X_MX_VERSION_HEADER}"
  fi

  # in case of port provided we cannot use subdomain
  # checked with azurite
  case "${DOMAIN_NAME}" in
  *:*)
    RESOURCE_PREFIX="${ACCOUNT_NAME}/${ACCOUNT_NAME}/${CONTAINER_NAME}"
    URL_PREFIX="${DOMAIN_NAME}/${ACCOUNT_NAME}/${CONTAINER_NAME}"
    ;;
  *)
    RESOURCE_PREFIX="${ACCOUNT_NAME}/${CONTAINER_NAME}"
    URL_PREFIX="${ACCOUNT_NAME}.${DOMAIN_NAME}/${CONTAINER_NAME}"
    ;;
  esac

  if [ -z "${BLOB_NAME}" ]; then
    CANNONICALIZED_RESOURCE="/${RESOURCE_PREFIX}\ncomp:list\nrestype:container"
    URL="${SCHEME}://${URL_PREFIX}?restype=container&comp=list"
  else
    CANNONICALIZED_RESOURCE="/${RESOURCE_PREFIX}/${BLOB_NAME}"
    URL="${SCHEME}://${URL_PREFIX}/${BLOB_NAME}"
  fi

  STRING_TO_SIGN="${REQUEST_METHOD}\n\n\n\n\n\n\n\n\n\n\n\n${CANNONICALIZED_HEADERS}\n${CANNONICALIZED_RESOURCE}"

  # Decode the Base64 encoded access key, convert to Hex.
  # shellcheck disable=SC2059
  DECODED_HEX_KEY="$(printf "${ACCESS_KEY}" | base64 -d | xxd -p -c256)"

  if [ -z "${DECODED_HEX_KEY}" ]; then
    echo "Failed to decode access key, make sure it is in base64 format"
    exit 1
  fi

  # Create the HMAC SIGNATURE for the Authorization header
  # shellcheck disable=SC2059
  SIGNATURE=$(printf "${STRING_TO_SIGN}" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${DECODED_HEX_KEY}" -binary | base64)

  if [ -z "${SIGNATURE}" ]; then
    echo "Failed to generate signature"
    exit 1
  fi

  AUTHORIZATION_HEADER="Authorization: ${AUTHORIZATION} ${ACCOUNT_NAME}:${SIGNATURE}"

  COMMAND_TO_RUN="curl -H \"${X_MS_DATE_HEADER}\" -H \"${X_MX_VERSION_HEADER}\" -H \"${AUTHORIZATION_HEADER}\" \"${URL}\""

  if [ -n "${FILE_TO_SAVE}" ]; then
    COMMAND_TO_RUN="${COMMAND_TO_RUN} --output ${FILE_TO_SAVE}"
  fi

  if [ -n "${LIMIT_IN_BYTES}" ] && [ -n "${BLOB_NAME}" ]; then
    COMMAND_TO_RUN="${COMMAND_TO_RUN} -H \"${X_MS_RANGE_HEADER}\""
  fi

  echo "${COMMAND_TO_RUN}"
  eval "${COMMAND_TO_RUN}"
}

dependencies_check
args_parse "${@}"
main
