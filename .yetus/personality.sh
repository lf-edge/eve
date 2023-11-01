#!/usr/bin/env bash

# shellcheck disable=SC2034
personality_globals() {

  # at some point, we should wire up make but
  # for now this is fine
  BUILDTOOL=nobuild

  # configure buf
  BUF_BASEDIR=api/proto

  # we want this on so master does not break
  CONTINUOUS_IMPROVEMENT=true

  # set the project name for reports, etc
  PROJECT="eve"

  # configure revive
  REVIVE_CONFIG=.revive.toml

  delete_test_type asflicense
  delete_test_type author
  delete_test_type findbugs
  delete_test_type gitlab
  delete_test_type jira
  delete_test_type shelldocs
  delete_test_type spotbugs
  delete_test_type detsecrets

}
