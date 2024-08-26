#!/bin/bash

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

BASE_COMMIT=$1

# List of files to check, excluding vendor directories
files=$(git diff --name-only --diff-filter=A "${BASE_COMMIT}"..HEAD | grep -v "vendor/")

# SPDX License Identifier to check for
license_identifier="SPDX-License-Identifier: Apache-2.0"

# Array of file extensions to check for SPDX header
file_extensions=("sh" "c" "h" "go" "py" "rs" "yaml" "yml" "proto")
file_names=("Dockerfile" "Dockerfile.in" "Makefile")

# Flag to check if all files contain the SPDX header
all_files_contain_spdx=true

# Loop through the files and check for the SPDX header
for file in $files; do
  echo "Checking $file"
  # Get the file extension
  file_extension="${file##*.}"

  # Check if the file is a source file that should have a license header
  for ext in "${file_extensions[@]}"; do
    if [[ "$file_extension" == "$ext" ]]; then
      # Check if the file contains the SPDX identifier
      if ! grep -q "$license_identifier" "$file"; then
        all_files_contain_spdx=false
        echo "Missing SPDX-License-Identifier in $file"
      fi
      break
    fi
  done
  for name in "${file_names[@]}"; do
    if [[ "$file" == "$name" ]]; then
      # Check if the file contains the SPDX identifier
      if ! grep -q "$license_identifier" "$file"; then
        all_files_contain_spdx=false
        echo "Missing SPDX-License-Identifier in $file"
      fi
      break
    fi
  done
done

if [ "$all_files_contain_spdx" = true ]; then
  echo "All files contain SPDX-License-Identifier."
  exit 0
else
  exit 1
fi
