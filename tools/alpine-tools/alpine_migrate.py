#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0

Alpine Linux Package List Migration Tool

This script migrates Alpine Linux package lists from one version to another,
handling package relocations, renames, and dependency changes that occur
between Alpine releases. It's specifically designed for the lfedge/eve
Alpine package mirror caching system.

Key Features:
    - Migrates package lists between Alpine versions (e.g., 3.16 → 3.21)
    - Supports same-version migrations for dependency updates (e.g., 3.16 → 3.16)
    - Handles packages that move between branches (main ↔ community)
    - Resolves all dependencies recursively to ensure complete package sets
    - Maintains architecture-specific package organization
    - Reports missing/renamed packages for manual review
    - Preserves package classification (common vs arch-specific)

Migration Process:
    1. Download APKINDEX metadata for target Alpine version
    2. Load existing package lists from source version directory
    3. For each package in source lists:
       - Find package in target version (may have moved branches)
       - Recursively resolve all dependencies
       - Track package presence across architectures
    4. Classify packages as common (all archs) or architecture-specific
    5. Write updated package lists maintaining directory structure
    6. Generate missing package reports for manual review

Directory Structure:
    Input (source version):
        pkg/alpine/mirrors/3.16/main
        pkg/alpine/mirrors/3.16/main.x86_64
        pkg/alpine/mirrors/3.16/community
        pkg/alpine/mirrors/3.16/community.aarch64

    Output (target version):
        pkg/alpine/mirrors/3.21/main
        pkg/alpine/mirrors/3.21/main.x86_64
        pkg/alpine/mirrors/3.21/community
        pkg/alpine/mirrors/3.21/community.aarch64
        pkg/alpine/mirrors/3.21/MISSING.main.x86_64
        pkg/alpine/mirrors/3.21/MISSING.community.aarch64

Usage Examples:
    Examples:
        # Basic migration from 3.16 to 3.21
        python3 alpine_migrate.py 3.16 3.21

        # Same-version migration to update missing dependencies
        python3 alpine_migrate.py 3.16 3.16

        # Migration with dependency chain analysis
        python3 alpine_migrate.py 3.16 3.21 --print-chains

        # Migration with custom package directory
        python3 alpine_migrate.py 3.16 edge --path /custom/mirrors

Common Migration Scenarios:
    - Package moved from community to main: Automatically detected and handled
    - Package renamed: Will appear in MISSING files for manual mapping
    - Package removed: Will appear in MISSING files
    - New dependencies added: Automatically resolved and included
    - Architecture support changed: Handled by per-arch classification

Author: Mikhail Malyshev <mike.malyshev@gmail.com>
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from alpine_index import (
    fetch_all_indexes,
    resolve_dependencies,
    read_package_lists,
    validate_alpine_version,
    write_packages,
    write_missing_report,
    classify_packages,
    print_dependency_chain,
    BRANCHES,
)

# pylint: disable=too-many-locals
def main(base_path, old_version, new_version, print_chains):
    """
    Main entry point for migrating Alpine Linux package lists between versions.

    Orchestrates the complete migration process from reading source package lists
    through dependency resolution to writing updated target package lists. This
    function handles the complexity of Alpine version differences, including
    package relocations, dependency changes, and architecture variations.

    Supports both cross-version migrations (e.g., 3.16 → 3.21) and same-version
    migrations (e.g., 3.16 → 3.16) for updating missing dependencies.

    Migration Workflow:
        1. Validate input versions and setup
        2. Fetch target version APKINDEX files for all architectures
        3. Load existing package lists from source version
        4. For each source package:
           - Locate in target version (may have moved branches)
           - Recursively resolve complete dependency tree
           - Track package presence by branch/architecture
        5. Classify resolved packages (common vs architecture-specific)
        6. Write classified packages to target version directory
        7. Generate missing package reports for unresolved packages
        8. Optionally display dependency resolution chains

    Args:
        base_path (str): Base directory containing version subdirectories
            (e.g., 'pkg/alpine/mirrors' contains '3.16/', '3.21/' subdirs)
        old_version (str): Source Alpine version to migrate from
            (e.g., '3.16', '3.17', must exist in base_path)
        new_version (str): Target Alpine version to migrate to
            (e.g., '3.21', 'edge', can be same as old_version for dependency updates)
        print_chains (bool): Whether to output detailed dependency chains
            for debugging and analysis purposes

    Side Effects:
        - Creates new_version directory in base_path
        - Writes package list files (main, community, etc.)
        - Writes architecture-specific files (main.x86_64, etc.)
        - Creates MISSING.* files for unresolvable packages
        - Prints progress information to stdout

    Raises:
        SystemExit: If old_version directory doesn't exist or contains no packages
        urllib.error.URLError: If target version APKINDEX files can't be downloaded

    Examples:
        >>> # Cross-version migration
        >>> main('pkg/alpine/mirrors', '3.16', '3.21', False)
        📦 Fetching APKINDEX files...
        📂 Reading old package lists...
        🔄 Resolving dependencies...
        📊 Classifying packages by architecture and branch...
        📂 Writing output files...
        ✅ Done. Missing packages written to missing.txt

        >>> # Same-version dependency update
        >>> main('pkg/alpine/mirrors', '3.16', '3.16', False)
        📦 Fetching APKINDEX files...
        📂 Reading old package lists...
        🔄 Resolving dependencies...
        📊 Classifying packages by architecture and branch...
        📂 Writing output files...
        ✅ Done. Missing packages written to missing.txt

    Notes:
        - Source package lists are not modified, only target lists are created
        - If target version directory exists, files are overwritten
        - Same-version migration refreshes dependencies without changing Alpine version
        - Missing packages indicate potential manual intervention needed
        - Dependency chains help understand why packages were included
    """
    print("📦 Fetching APKINDEX files...")
    apk_indexes, provides_indexes, available_archs = fetch_all_indexes(new_version)

    # Prepare presence and resolved sets by branch and arch
    presence = defaultdict(set)  # key: pkgname, value: set of (branch, arch)
    resolved_by_branch_arch = {branch: {arch: set() for arch in available_archs}
                              for branch in BRANCHES}
    missing_by_branch_arch = {branch: {arch: set() for arch in available_archs}
                             for branch in BRANCHES}
    chains_by_branch_arch = {branch: {arch: {} for arch in available_archs} for branch in BRANCHES}

    print("📂 Reading old package lists...")
    input_packages_by_branch_arch = read_package_lists(base_path, old_version)

    print("🔄 Resolving dependencies...")
    for branch in BRANCHES:
        for arch in available_archs:
            all_set = input_packages_by_branch_arch[branch].get('all', set())
            arch_set = input_packages_by_branch_arch[branch].get(arch, set())
            to_resolve = all_set.union(arch_set)
            for pkgname in to_resolve:
                resolve_dependencies(
                    pkgname,
                    apk_indexes[arch],
                    provides_indexes[arch],
                    resolved_by_branch_arch[branch][arch],
                    missing_by_branch_arch[branch][arch],
                    presence,
                    branch,
                    arch,
                    chain=[pkgname],
                    chains=chains_by_branch_arch[branch][arch]
                )

    print("📊 Classifying packages by architecture and branch...")
    classified = classify_packages(resolved_by_branch_arch, presence, available_archs)

    print("📂 Writing output files...")
    write_packages(base_path, new_version, classified, available_archs)

    if print_chains:
        print_dependency_chain(chains_by_branch_arch, available_archs)

    write_missing_report(base_path, new_version, missing_by_branch_arch, available_archs)
    print("✅ Done. Missing packages written to missing.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migrate Alpine Linux package lists from one version to another",
        epilog="""
Examples:
  %(prog)s 3.16 3.21                    # Basic migration
  %(prog)s 3.16 3.16                    # Same-version dependency update
  %(prog)s 3.16 edge --print-chains     # Migration with dependency analysis
  %(prog)s 3.17 3.21 --path /custom     # Custom package directory

This tool handles package relocations, renames, and dependency changes
that occur between Alpine releases. It also supports same-version migrations
to update missing dependencies. It maintains the directory structure
used by the lfedge/eve Alpine package caching system.

Source packages are read from: PATH/OLD_VERSION/
Target packages are written to: PATH/NEW_VERSION/
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old_version",
                       help="Source Alpine version to migrate from "
                            "(e.g., 3.16, 3.17)")
    parser.add_argument("new_version",
                       help="Target Alpine version to migrate to "
                            "(e.g., 3.21, edge). Can be same as source version "
                            "to update missing dependencies")
    parser.add_argument("--path",
                       default="pkg/alpine/mirrors",
                       help="Base directory containing version subdirectories "
                            "(default: %(default)s)")
    parser.add_argument("--print-chains",
                       action="store_true",
                       help="Display detailed dependency resolution chains "
                            "for debugging")

    args = parser.parse_args()

    # Validate version format for both source and target
    if not validate_alpine_version(args.old_version):
        print(f"ERROR: Invalid source version format: {args.old_version}")
        print("Valid formats: 'edge' or versions like '3.16', '3.17', etc. "
              "(3.16+ only)")
        parser.print_help()
        sys.exit(1)

    if not validate_alpine_version(args.new_version):
        print(f"ERROR: Invalid target version format: {args.new_version}")
        print("Valid formats: 'edge' or versions like '3.16', '3.17', etc. "
              "(3.16+ only)")
        parser.print_help()
        sys.exit(1)

    # Same-version migration is allowed for dependency updates
    if args.old_version == args.new_version:
        print(f"ℹ️  Performing same-version migration ({args.old_version} → {args.new_version})")
        print("   This will update missing dependencies while keeping the same Alpine version")

    # Check if source version directory exists
    source_dir = Path(args.path) / args.old_version
    if not source_dir.exists():
        print(f"ERROR: Source version directory does not exist: {source_dir}")
        print(f"Please ensure {args.old_version} package lists exist in "
              f"{args.path}")
        sys.exit(1)

    if args.old_version == args.new_version:
        print(f"🚀 Starting same-version dependency update for Alpine {args.old_version}")
    else:
        print(f"🚀 Starting migration from Alpine {args.old_version} "
              f"to {args.new_version}")
    print(f"📁 Package directory: {args.path}")

    main(args.path, args.old_version, args.new_version, args.print_chains)
