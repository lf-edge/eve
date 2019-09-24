#!/usr/bin/env bash

this="${BASH_SOURCE-$0}"
BINDIR=$(cd -P -- "$(dirname -- "${this}")" >/dev/null && pwd -P)

# NOTE: Circle CI config assumes this directory
YETUS_OUT_DIR=/tmp/yetus-out

# check the usual places for a pre-installed test-patch
if [[ -f "${YETUS_HOME}/bin/test-patch" ]]; then
      TESTPATCHBIN="${YETUS_HOME}/bin/test-patch"
elif [[ -f /usr/local/bin/test-patch ]]; then
      TESTPATCHBIN=/usr/local/bin/test-patch
elif [[ -f /usr/bin/test-patch ]]; then
      TESTPATCHBIN=/usr/bin/test-patch
else
      # not pre-installed, so download it instead
      #
      # NOTE: This will only download officially released binaries
      EXTRACTDIR=/tmp/yetus "${BINDIR}/yetus-wrapper.sh"
      TESTPATCHBIN=/tmp/yetus/bin/test-patch
fi

if [[ "${CIRCLECI}" = true ]] ; then
      # shellcheck source=build-tools/src/yetus/yetus-docker-bootstrap.sh
      . "${BINDIR}"/yetus-docker-bootstrap.sh
      TPARGS=()

      # by default, Yetus' built-in Circle CI support sets our flags
      # correctly, including --resetrepo which is the opposite
      # of --dirty-workspace!
else
      # for non-Circle CI builds, test-patch needs to know a bit of
      # extra setup ...

      # a) Tell Yetus not to stomp all over the local repo
      TPARGS=('--dirty-workspace')

      # b) use a container to do the real run
      TPARGS+=('--docker')

      # c) define the container image to use
      TPARGS+=('--dockerfile=build-tools/src/yetus/Dockerfile')

      # d) enable docker-in-docker
      TPARGS+=('--dockerind=true')

      # Weird things can happen if the report output directory isn't empty
      # it is always fresh on CI systems; rarely on local desktop runs
      if [[ -n "${YETUS_OUT_DIR}" && -e "${YETUS_OUT_DIR}" ]]; then
            rm -rf "${YETUS_OUT_DIR}"
      fi
fi

"${TESTPATCHBIN}" \
      --build-tool=nobuild \
      --plugins=all,-asflicense,-shelldocs,-gitlab,-findbugs \
      --basedir="${BINDIR}/../../.." \
      --patch-dir="${YETUS_OUT_DIR}" \
      --project="eve" \
      --whitespace-tabs-ignore-list='.*Makefile.*','.*\.go','.*\.dts','.*\.md' \
      --html-report-file="${YETUS_OUT_DIR}"/report.html \
      --console-report-file="${YETUS_OUT_DIR}"/console.txt \
      --brief-report-file="${YETUS_OUT_DIR}"/brief.txt \
      --junit-report-xml="${YETUS_OUT_DIR}"/results.xml \
      --excludes=.yetus-excludes \
      --revive-config=.revive.toml \
      --linecomments='' \
      --bugcomments=briefreport,htmlout,junit \
      --tests-filter=checkmake,golang,golangcilint \
      --continuous-improvement=true \
      --empty-patch \
      "${TPARGS[@]}" \
      "$@"
