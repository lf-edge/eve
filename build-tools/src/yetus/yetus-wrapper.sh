#!/bin/sh

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

EXTRACTDIR="${1:-/tmp/yetus}"
YETUS_VERSION=${2:-0.11.0}
KEYSURL="https://www.apache.org/dist/yetus/KEYS"
if [ "${YETUS_VERSION}" != "latest" ]; then
  BASEURL="https://www.apache.org/dyn/closer.cgi?action=download&filename=yetus/${YETUS_VERSION}"
  YETUSTGZ="apache-yetus-${YETUS_VERSION}-bin.tar.gz"
  ASCURL="https://www.apache.org/dist/yetus/${YETUS_VERSION}/${YETUSTGZ}.asc"
else
  BASEURL="https://yetus.apache.org"
  YETUSTGZ="latest.tgz"
  ASCURL="${BASEURL}/${YETUSTGZ}.asc"
fi

if [ ! -d "${EXTRACTDIR}" ]; then
  if ! mkdir -p "${EXTRACTDIR}"; then
    echo "ERROR: yetus-dl: unable to create ${EXTRACTDIR}"
    exit 1
  fi
fi

if ! curl -f -s -L -o "${EXTRACTDIR}/KEYS" "${KEYSURL}"; then
  echo "ERROR: yetus-dl: unable to fetch ${KEYSURL}"
  exit 1
fi

if ! curl -f -s -L -o "${EXTRACTDIR}/${YETUSTGZ}.asc" "${ASCURL}"; then
  echo "ERROR: yetus-dl: unable to fetch ${BASEURL}/${YETUSTGZ}.asc"
  exit 1
fi

if ! curl -f -s -L -o "${EXTRACTDIR}/${YETUSTGZ}" "${BASEURL}/${YETUSTGZ}"; then
  echo "ERROR: yetus-dl: unable to fetch ${BASEURL}/${YETUSTGZ}"
  exit 1
fi

if ! gpg --import "${EXTRACTDIR}/KEYS" >/dev/null 2>&1; then
  echo "ERROR: yetus-dl: gpg unable to import ${EXTRACTDIR}/KEYS"
  exit 1
fi

if ! gpg --verify "${EXTRACTDIR}/${YETUSTGZ}.asc" >/dev/null 2>&1; then
 echo "ERROR: yetus-dl: gpg verify of tarball in ${EXTRACTDIR} failed"
 exit 1
fi

if ! tar -C "${EXTRACTDIR}" --strip-components=1 -xzpf "${EXTRACTDIR}/${YETUSTGZ}"; then
  echo "ERROR: ${YETUSTGZ} is corrupt. Investigate and then remove ${EXTRACTDIR} to try again."
  exit 1
fi
