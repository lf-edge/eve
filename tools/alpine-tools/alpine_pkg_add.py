#!/usr/bin/env python3
"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0

Alpine Linux Package Addition Tool

This script adds specific packages to Alpine Linux package lists with complete
dependency resolution. It's designed for the lfedge/eve Alpine package mirror
caching system to expand existing package collections with new packages and
all their dependencies.

Key Features:
    - Add individual packages to existing Alpine package lists
    - Automatically resolve and include all dependencies recursively
    - Handle virtual packages and provides relationships
    - Maintain proper branch (main/community) and architecture classification
    - Track newly added packages for reporting
    - Generate reports for unresolvable dependencies

Use Cases:
    - Adding development tools to Alpine package cache
    - Including new runtime dependencies for applications
    - Expanding package sets for container base images
    - Testing package availability across architectures

Package Resolution Process:
    1. Download current APKINDEX files for target Alpine version
    2. For each requested package:
       - Locate package in appropriate branch (main/community/testing)
       - Recursively resolve all dependencies
       - Handle virtual provides (so:, cmd:, pc: prefixes)
    3. Classify resolved packages by architecture availability
    4. Merge with existing package lists (preserving current packages)
    5. Write updated lists and report newly added packages

Directory Structure (Maintained):
    pkg/alpine/mirrors/3.21/main              # Common packages (all archs)
    pkg/alpine/mirrors/3.21/main.x86_64       # x86_64-specific packages
    pkg/alpine/mirrors/3.21/community         # Community packages (all archs)
    pkg/alpine/mirrors/3.21/community.aarch64 # aarch64-specific community packages

Usage Examples:
    # Add vim editor with all dependencies
    python3 alpine_pkg_add.py 3.21 vim

    # Add multiple development tools
    python3 alpine_pkg_add.py 3.21 git curl wget build-base

    # Add packages to custom mirror directory
    python3 alpine_pkg_add.py edge python3-pip --path /custom/mirrors

Comparison with alpine_migrate.py:
    - alpine_migrate.py: Migrates complete package sets between Alpine versions
    - alpine_pkg_add.py: Adds specific packages to existing package lists

Author: Mikhail Malyshev <mike.malyshev@gmail.com>
"""

import argparse
import sys
from typing import List

from alpine_index import (
    fetch_all_indexes,
    resolve_and_classify_packages,
    validate_alpine_version,
    write_packages,
    write_missing_report,
    print_dependency_chain,
    BRANCHES,
)

# Default directory for Alpine package mirror cache
MIRRORS_DIR = "pkg/alpine/mirrors"

# pylint: disable=too-many-branches,too-many-locals
def main(version: str, packages_to_add: List[str], print_chains: bool = False,
         base_path: str = MIRRORS_DIR) -> None:
    """
    Add packages to Alpine Linux package lists for a specified version.

    This is the main orchestration function that coordinates the entire package
    addition process. It fetches current Alpine package indexes, resolves all
    dependencies for requested packages, and updates the existing package lists
    while preserving the current package organization structure.

    Workflow:
        1. Validate input parameters and display operation summary
        2. Download APKINDEX files for all available architectures
        3. Resolve dependencies for each requested package:
           - Find package in appropriate repository branch
           - Recursively resolve all dependencies
           - Handle virtual packages and provides relationships
        4. Classify resolved packages (common vs architecture-specific)
        5. Merge with existing package lists (additive operation)
        6. Write updated lists and generate missing package reports
        7. Display summary of newly added packages

    Args:
        version (str): Target Alpine version to add packages to
            (e.g., '3.21', '3.20', 'edge' - must exist in base_path)
        packages_to_add (list): Package names to add with dependencies
            (e.g., ['vim', 'curl', 'python3-pip'])
        print_chains (bool, optional): Display detailed dependency resolution
            chains for debugging and analysis. Defaults to False.
        base_path (str, optional): Base directory containing version subdirectories
            where package lists are stored. Defaults to MIRRORS_DIR.

    Returns:
        None: Function performs file I/O operations and prints status to stdout

    Side Effects:
        - Updates package list files in base_path/version/
        - Creates MISSING.* files for unresolvable dependencies
        - Prints progress information and results to stdout

    Raises:
        SystemExit: If version format is invalid or no packages specified
        urllib.error.URLError: If APKINDEX files cannot be downloaded
        OSError: If base_path directory cannot be accessed

    Examples:
        >>> main('3.21', ['vim'], False, 'pkg/alpine/mirrors')
        📦 Adding packages ['vim'] to Alpine 3.21
        📦 Fetching APKINDEX files...
        ✅ Newly added packages:
        [x86_64]:
          main: ['vim', 'vim-common']
        ✅ Done!

        >>> main('edge', ['build-base', 'git'], True)
        # Adds development tools with dependency chain analysis

    Notes:
        - Operation is additive: existing packages are preserved
        - Package classification (common vs arch-specific) is automatic
        - Virtual packages (e.g., cmd:foo, so:lib.so) are handled transparently
        - Missing packages indicate potential package renames or removals
    """
    if not packages_to_add:
        print("No packages specified to add")
        return

    print(f"📦 Adding packages {packages_to_add} to Alpine {version}")

    print("📦 Fetching APKINDEX files...")
    apk_indexes, provides_indexes, available_archs = fetch_all_indexes(version)

    if not available_archs:
        print("❌ No architectures available for this version")
        return

    print(f"📊 Available architectures: {available_archs}")

    # Resolve and classify packages
    if print_chains:
        result = resolve_and_classify_packages(
            packages_to_add, apk_indexes, provides_indexes, available_archs, collect_chains=True
        )
        classified, missing_by_branch_arch, chains_by_branch_arch = result
    else:
        result = resolve_and_classify_packages(
            packages_to_add, apk_indexes, provides_indexes, available_archs, collect_chains=False
        )
        # pylint: disable=unbalanced-tuple-unpacking
        classified, missing_by_branch_arch = result
        chains_by_branch_arch = None

    print("📂 Writing output files...")
    newly_added = write_packages(base_path, version, classified, available_archs,
                                track_newly_added=True)

    # Report newly added packages
    if newly_added is not None:
        has_new_packages = False
        for arch in available_archs:
            if any(newly_added[arch][branch] for branch in BRANCHES):
                if not has_new_packages:
                    print("\n✅ Newly added packages:")
                    has_new_packages = True
                print(f"\n[{arch}]:")
                for branch in BRANCHES:
                    if newly_added[arch][branch]:
                        print(f"  {branch}: {sorted(newly_added[arch][branch])}")

        if not has_new_packages:
            print("ℹ️  No new packages were added (all already present)")
    else:
        print("ℹ️  No new packages were added (all already present)")

    if print_chains and chains_by_branch_arch is not None:
        print_dependency_chain(chains_by_branch_arch, available_archs)

    # Write missing packages report
    write_missing_report(base_path, version, missing_by_branch_arch, available_archs)

    # Check if there are any missing packages
    has_missing = any(
        missing_by_branch_arch.get(branch, {}).get(arch, set())
        for branch in BRANCHES
        for arch in available_archs
    )

    if has_missing:
        print("⚠️  Some packages could not be resolved. Check MISSING.* files.")

    print("✅ Done!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Add packages to Alpine Linux package lists with dependency resolution",
        epilog="""
Examples:
  %(prog)s 3.21 vim                        # Add vim editor
  %(prog)s 3.21 git curl wget              # Add development tools
  %(prog)s edge python3-pip --path /custom # Add to custom directory
  %(prog)s 3.21 build-base --print-chains  # Add with dependency chains

This tool adds specified packages to existing Alpine package lists,
automatically resolving and including all dependencies. It maintains
the directory structure used by the lfedge/eve Alpine caching system.

The operation is additive - existing packages are preserved, and only
new packages and dependencies are added to the appropriate files.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("version",
                       help="Target Alpine version (e.g., 3.21, 3.20, edge)")
    parser.add_argument("packages",
                       nargs="+",
                       help="Package names to add (space-separated)")
    parser.add_argument("--path",
                       default=MIRRORS_DIR,
                       help="Base directory containing version subdirectories "
                            "(default: %(default)s)")
    parser.add_argument("--print-chains",
                       action="store_true",
                       help="Display detailed dependency resolution chains for debugging")

    args = parser.parse_args()

    # Validate Alpine version format
    if not validate_alpine_version(args.version):
        print(f"ERROR: Invalid Alpine version format: {args.version}")
        print("Valid formats:")
        print("  - 'edge' for rolling release")
        print("  - 'X.Y' for stable releases (3.16+, e.g., 3.21, 3.20)")
        print("\nNote: Only Alpine 3.16+ is supported")
        parser.print_help()
        sys.exit(1)

    # Validate that at least one package was specified
    if not args.packages:
        print("ERROR: At least one package name must be specified")
        parser.print_help()
        sys.exit(1)

    # Display operation summary
    PACKAGE_LIST = ', '.join(args.packages)
    print(f"🎯 Target: Alpine {args.version}")
    print(f"📦 Packages: {PACKAGE_LIST}")
    print(f"📁 Directory: {args.path}")
    print()

    # Execute main package addition workflow
    main(args.version, args.packages, args.print_chains, args.path)
