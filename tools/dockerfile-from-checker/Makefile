# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

DOCKERFILE_FROM_CHECKER_SRCS := main.go $(wildcard dockerfilefrom/*.go)

dockerfile-from-checker: go.mod go.sum $(DOCKERFILE_FROM_CHECKER_SRCS)
	go build -o $@ .
