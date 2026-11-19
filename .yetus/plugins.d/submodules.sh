#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Yetus plugin: initialize git submodules after the patch is applied so that
# tools like buf can resolve imports from submodule proto files.

add_test_type submodules

function submodules_precompile
{
  echo "Initializing git submodules..."
  git -C "${BASEDIR}" submodule update --init --recursive || true

  # Remove eve-api's own buf.yaml so buf does not treat it as a nested
  # workspace; without this buf scans beyond evetest/ and hits vendor
  # proto conflicts.
  rm -f "${BASEDIR}/evetest/grpcapi/eve-api/proto/buf.yaml"
  return 0
}
