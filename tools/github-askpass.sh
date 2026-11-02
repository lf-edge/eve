#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# GIT_ASKPASS helper: answers git's credential prompts for github.com with
# GITHUB_TOKEN (or GH_TOKEN). github.com throttles anonymous fetches per source
# IP, which makes clones fail in bursts on the shared CI runners. Git asks for
# credentials only once github.com challenges it, so an authenticated fetch is
# attempted only where an anonymous one just failed.
#
# Prompts for any other host are declined, so the token never reaches a
# third-party remote. Without a token the helper declines too, leaving git to
# fail exactly as it does without this helper.
#
# Point GIT_ASKPASS at this script; do not run it by hand.

prompt="$1"
token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

# git prompts as "Username for 'https://github.com': " or
# "Password for 'https://x-access-token@github.com': ", with a path appended
# under credential.useHttpPath. Check the quoted URL's host exactly, so e.g.
# https://github.com.example.org is declined.
url="${prompt#*\'}"
url="${url%%\'*}"
case "$url" in
  https://*) ;;
  *) exit 1 ;;
esac
host="${url#https://}"
host="${host%%/*}"
host="${host#*@}"
host="${host%:443}"
host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
[ "$host" = "github.com" ] || exit 1

[ -n "$token" ] || exit 1

case "$prompt" in
  *[Uu]sername*) echo "x-access-token" ;;
  *) echo "$token" ;;
esac
