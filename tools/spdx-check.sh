#!/bin/bash

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

IGNORE_FILE=".spdxignore"
if [ -f "$1" ];
then
    files="$1"
else
    BASE_COMMIT=$1

    # List of files to check, excluding vendor directories
    files=$(git diff --name-only --diff-filter=A "${BASE_COMMIT}"..HEAD)
fi


check_branch_rebased() {
  local base_commit="$1"
  local merge_base

  merge_base=$(git merge-base HEAD "$base_commit")
  base_commit=$(git rev-parse "$base_commit")

  if [ "$merge_base" != "$base_commit" ]; then
    return 1
  fi
  return 0
}

# SPDX License Identifier to check for
license_identifiers=(
  "Apache-2.0"
  "MIT"
  "BSD-2-Clause"
  "BSD-3-Clause"
  "ISC" # Internet Systems Consortium license
  "Python-2.0"
  "PostgreSQL"
  "Zlib"
  "BSL-1.0" # Boost Software License 1.0
  "CC0-1.0" # Creative Commons Zero v1.0 Universal
)

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

# Flag to check if all files fulfill the license requirements
all_files_proper_licensed=true

check_spdx() {
  local file="$1"
  # Check that the file contains the SPDX-License-Identifier
  if ! grep -q "SPDX-License-Identifier" "$file"; then
    echo "missing SPDX-License-Identifier!"
    return 1
  fi
  # Check if the file contains the SPDX identifier
  for license_identifier in "${license_identifiers[@]}"; do
    if grep -q -i "$license_identifier" "$file"; then
      return 0
    fi
  done
  echo "the SPDX-License-Identifier is not compatible with the allowed licenses"
  return 1
}

check_copyright() {
  local file="$1"
  local current_year

  current_year=$(date +"%Y")

  # Check if the file contains the copyright
  if ! grep -iq "Copyright[ ]*(c)" "$file"; then
    echo "does not have the copyright!"
    return 1
  fi

  # Check if the file contains the current year
  if ! grep -iq "Copyright[ ]*(c) .*$current_year" "$file"; then
    echo "does not have the current year $current_year in the copyright notice!"
    return 1
  fi

  return 0
}

ignore_paths=()
if [[ -f "$IGNORE_FILE" ]]; then
  while IFS= read -r line; do
    ignore_paths+=("$line")
  done < "$IGNORE_FILE"
else
  echo "No .spdxignore file found"
fi

file_to_be_checked() {
  local file="$1"
  # Check if the file or directory is excluded
  for ignore_path in "${ignore_paths[@]}"; do
    if [[ "$file" == "$ignore_path" || "$file" == "$ignore_path"* ]]; then
      return 1
    fi
  done
  # Check if the file is a source file that should have a license header
  for ext in "${file_extensions[@]}"; do
    if [[ "$file" == *.$ext ]]; then
      return 0
    fi
  done
  # Extract the file name from the path
  file_name=$(basename "$file")
  for name in "${file_names[@]}"; do
    if [[ "$file_name" == "$name" ]]; then
      return 0
    fi
  done
  return 1
}

check_branch_rebased "$BASE_COMMIT"
rebased=$?

if [ $rebased -ne 0 ]; then
  echo "The branch is not rebased on top of base branch!"
  echo "Rebase the branch!"
  echo "The check might run on a wrong set of files!"
fi

# Loop through the files and check for the SPDX header
for file in $files; do
  if file_to_be_checked "$file"; then
    echo "Checking $file"
    echo -n "  - SPDX-License-Identifier: "
    if check_spdx "$file"; then
      echo "OK"
    else
      all_files_proper_licensed=false
    fi
    echo -n "  - Copyright: "
    if check_copyright "$file"; then
      echo "OK"
    else
      all_files_proper_licensed=false
    fi
  fi
done

if [ "$all_files_proper_licensed" = true ]; then
  echo "All files are properly licensed!"
  exit 0
else
  echo "Some files are not properly licensed!"
  if [ $rebased -ne 0 ]; then
    echo "The error might appear on files that are not part of the branch!"
    echo "Rebase the branch!"
  fi
  exit 1
fi
