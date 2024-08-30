#!/bin/bash

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

BASE_COMMIT=$1

# List of files to check, excluding vendor directories
files=$(git diff --name-only --diff-filter=A "${BASE_COMMIT}"..HEAD | grep -v "vendor/")

# SPDX License Identifier to check for
license_identifier="SPDX-License-Identifier: Apache-2.0"

# Array of file extensions to check for SPDX header
file_extensions=(
  "sh"
  "c" "h"
  "go"
  "py"
  "rs"
  "yaml" "yml"
  "proto"
)

# Array of file names to check for SPDX header
file_names=(
  "Dockerfile" "Dockerfile.in"
  "Makefile"
)

# Flag to check if all files contain the SPDX header
all_files_contain_spdx=true

check_spdx() {
  local file="$1"
  # Check if the file contains the SPDX identifier
  if ! grep -q -i "$license_identifier" "$file"; then
    return 1
  fi
  return 0
}

file_to_be_checked() {
  local file="$1"
  # Check if the file is a source file that should have a license header
  for ext in "${file_extensions[@]}"; do
    if [[ "$file" == *.$ext ]]; then
      return 0
    fi
  done
  for name in "${file_names[@]}"; do
    if [[ "$1" == "$name" ]]; then
      return 0
    fi
  done
  return 1
}

# Loop through the files and check for the SPDX header
for file in $files; do
  if file_to_be_checked "$file"; then
    echo -n "Checking $file ..."
    if ! check_spdx "$file"; then
      echo " missing SPDX-License-Identifier."
      all_files_contain_spdx=false
    else
      echo " OK"
    fi
  fi
done

if [ "$all_files_contain_spdx" = true ]; then
  echo "All files contain SPDX-License-Identifier."
  exit 0
else
  exit 1
fi
