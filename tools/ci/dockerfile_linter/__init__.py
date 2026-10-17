# Re-export the public API for nice imports
"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from .dockerfile_linter import DockerfileTreeSitterLinter, main

__all__ = ["DockerfileTreeSitterLinter", "main"]
