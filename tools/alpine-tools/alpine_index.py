"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0

Alpine Linux Package Index Utilities

This module provides comprehensive utilities for working with Alpine Linux APKINDEX files,
including parsing, dependency resolution, and managing package presence across branches
and architectures. It serves as the core library for Alpine package management tools
in the lfedge/eve project.

Key Features:
    - Download and parse APKINDEX files from Alpine mirrors
    - Resolve package dependencies recursively
    - Handle virtual packages and provides relationships
    - Classify packages by branch (main/community) and architecture
    - Support for multiple Alpine versions including 'edge'
    - Generate reports for missing dependencies

Supported Architectures:
    - x86_64: Intel/AMD 64-bit
    - aarch64: ARM 64-bit
    - riscv64: RISC-V 64-bit

Supported Branches:
    - main: Core Alpine packages
    - community: Community-maintained packages
    - testing: Testing packages (edge only)

Usage:
    >>> from alpine_index import fetch_all_indexes, resolve_dependencies
    >>> indexes, provides, archs = fetch_all_indexes('3.21')
    >>> # Use indexes and provides for dependency resolution

Author: Mikhail Malyshev <mike.malyshev@gmail.com>
"""

import os
import tarfile
import gzip
import urllib.request
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, Set, List, Optional, DefaultDict

# Alpine Linux mirror configuration
ALPINE_BASE_URL = "https://dl-cdn.alpinelinux.org/alpine"

# All known architectures for Alpine Linux
# Note: Not all architectures are available for all versions
ARCHITECTURES = ["x86_64", "aarch64", "riscv64"]

# Standard Alpine repository branches
BRANCHES = ["main", "community"]

def get_branch_list(version):
    """
    Get the list of repository branches available for a given Alpine version.

    Alpine Linux organizes packages into different repository branches:
    - main: Core system packages and libraries
    - community: Community-maintained packages
    - testing: Experimental packages (edge only)

    Args:
        version (str): Alpine version string ('edge', '3.16', '3.17', etc.)

    Returns:
        list: List of available branch names for the version

    Note:
        We only support Alpine 3.16+, so 'main' and 'community' branches
        are always available. The 'testing' branch is only available for 'edge'.

    Examples:
        >>> get_branch_list('3.21')
        ['main', 'community']
        >>> get_branch_list('edge')
        ['main', 'community', 'testing']
    """
    if version == "edge":
        return BRANCHES + ["testing"]
    return BRANCHES

def validate_alpine_version(version):
    """
    Validate Alpine Linux version string format.

    Accepts either the rolling 'edge' release or semantic versions
    like '3.16', '3.17', etc. This function ensures compatibility
    with supported Alpine versions.

    Args:
        version (str): Version string to validate

    Returns:
        bool: True if version format is valid and supported, False otherwise

    Supported Formats:
        - 'edge': Rolling release (always latest)
        - 'X.Y': Stable releases where X=3 and Y>=16

    Examples:
        >>> validate_alpine_version('3.21')
        True
        >>> validate_alpine_version('edge')
        True
        >>> validate_alpine_version('3.15')
        False
        >>> validate_alpine_version('4.0')
        False

    Note:
        Only Alpine 3.16+ is supported. We don't support future major
        versions (4.x+) as their package format is unknown.
    """
    if version == "edge":
        return True
    match = re.match(r"^(\d+)\.(\d+)$", version)
    if match:
        major, minor = map(int, match.groups())
        # We only support Alpine 3.x series, 3.16 and above
        return major == 3 and minor >= 16
    return False

class ApkPackage:
    """
    Represents a parsed APK package entry from an APKINDEX file.

    This class encapsulates all metadata for a single Alpine package,
    including its dependencies, virtual provides, and branch information.
    It serves as the primary data structure for package information
    throughout the dependency resolution process.

    Attributes:
        name (str): The package name (e.g., 'curl', 'python3')
        metaname (str or None): Name of the metapackage if applicable
            (e.g., 'o:zstd' for zstd metapackage)
        depends (list[str]): List of dependency strings with version constraints
            (e.g., ['libc6>=2.28', 'libssl3'])
        provides (list[str]): List of virtual features provided by this package
            (e.g., ['so:libssl.so.3', 'cmd:openssl'])
        branch (str): Repository branch containing this package
            ('main', 'community', or 'testing')

    Examples:
        >>> pkg = ApkPackage('curl', None, ['libssl3', 'zlib'], ['cmd:curl'], 'main')
        >>> pkg.name
        'curl'
        >>> pkg.branch
        'main'
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, name, metaname, depends, provides, branch):
        # pylint: disable=too-many-arguments
        self.name = name
        self.metaname = metaname
        self.depends = depends
        self.provides = provides
        self.branch = branch

def url_for_version(version):
    """
    Convert an Alpine version string to URL-friendly format for mirror access.

    Alpine mirrors organize releases differently for stable versions vs edge:
    - Stable versions: v3.16, v3.17, etc.
    - Edge version: edge

    Args:
        version (str): Alpine version string ('3.21', 'edge', etc.)

    Returns:
        str: URL-compatible version string

    Examples:
        >>> url_for_version('3.21')
        'v3.21'
        >>> url_for_version('edge')
        'edge'
    """
    if version == "edge":
        return "edge"
    return f"v{version}"

def fetch_and_parse_index(version, branch, arch):
    """
    Download and parse an APKINDEX file for a specific Alpine configuration.

    Downloads the APKINDEX.tar.gz file from Alpine mirrors and extracts
    the package index information. The index contains metadata for all
    packages available in the specified version/branch/architecture combination.

    Args:
        version (str): Alpine version ('3.21', 'edge', etc.)
        branch (str): Repository branch ('main', 'community', 'testing')
        arch (str): Target architecture ('x86_64', 'aarch64', 'riscv64')

    Returns:
        tuple: (pkg_map, provides_map) where:
            - pkg_map (dict): Maps package names to ApkPackage objects
            - provides_map (defaultdict): Maps virtual provides to package names

    Raises:
        urllib.error.URLError: If the APKINDEX URL cannot be accessed
        tarfile.TarError: If the downloaded archive is corrupted

    Examples:
        >>> pkg_map, provides = fetch_and_parse_index('3.21', 'main', 'x86_64')
        >>> 'curl' in pkg_map
        True
        >>> 'cmd:curl' in provides
        True
    """
    version = url_for_version(version)
    url = f"{ALPINE_BASE_URL}/{version}/{branch}/{arch}/APKINDEX.tar.gz"
    print(f"Fetching: {url}")
    pkg_map = {}
    provides_map = defaultdict(list)

    try:
        with urllib.request.urlopen(url) as response:
            with gzip.GzipFile(fileobj=response) as gzip_file:
                with tarfile.open(fileobj=gzip_file, mode="r:") as tar:
                    for member in tar:
                        if member.name == "APKINDEX":
                            fobj = tar.extractfile(member)
                            if fobj is not None:
                                with fobj as index_file:
                                    content = index_file.read().decode()
                                    pkg_map, provides_map = parse_apkindex(content, branch)
                            else:
                                print(f"⚠️ Could not extract APKINDEX from archive: {member.name}")

    # pylint: disable=broad-exception-caught
    except Exception as error:
        print(f"Error fetching {url}: {error}")
    return pkg_map, provides_map

def parse_apkindex(content, branch):
    """
    Parse the raw content of an APKINDEX file into structured package data.

    The APKINDEX format uses key-value pairs separated by newlines, with
    package entries separated by double newlines. Each package can have
    multiple attributes like dependencies, provides, etc.

    APKINDEX Format:
        P: package-name
        D: dependency1 dependency2
        p: provides1=version provides2=version
        o: metapackage-name
        (blank line separates packages)

    Args:
        content (str): Raw APKINDEX file content
        branch (str): Branch name to assign to all packages

    Returns:
        tuple: (pkg_map, provides_map) where:
            - pkg_map (dict): Maps package names to ApkPackage objects
            - provides_map (defaultdict): Maps virtual provides to providing package names

    Special Handling:
        - '/bin/sh' dependency is replaced with 'busybox' (EVE OS default shell)
        - Version constraints in provides are stripped (e.g., 'cmd:foo=1.0' -> 'cmd:foo')
        - Metapackages (o: lines) link subpackages to their parent

    Examples:
        >>> content = "P:curl\\nD:libssl3 zlib\\np:cmd:curl\\n\\nP:wget\\n"
        >>> pkg_map, provides = parse_apkindex(content, 'main')
        >>> pkg_map['curl'].depends
        ['libssl3', 'zlib']
        >>> provides['cmd:curl']
        ['curl']
    """
    pkg_map = {}
    provides_map = defaultdict(list)
    entries = content.split("\n\n")

    for entry in entries:
        lines = entry.strip().split("\n")
        name = None
        metaname = None
        depends = []
        provides = []

        for line in lines:
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("D:"):
                depends = line[2:].strip().split()
                # Special handling for /bin/sh dependency:
                # In EVE OS, busybox provides the default shell, so we
                # replace the generic /bin/sh with the specific busybox package
                depends = [d if d != "/bin/sh" else "busybox" for d in depends]
            elif line.startswith("p:"):
                # Parse provides line: can contain multiple virtual packages
                # Format: 'p:pc:znc=1.9.1 cmd:znc-buildmod=1.9.1-r0'
                provides = line[2:].strip().split()
            elif line.startswith("o:"):
                # Metapackage origin: links subpackages to their metapackage
                # Format: 'o:zstd' means this package belongs to zstd metapackage
                metaname = line[2:].strip()

        if name:
            pkg = ApkPackage(name, metaname, depends, provides, branch)
            pkg_map[name] = pkg

            # Process provides: strip version constraints for compatibility
            for provide in provides:
                # Split on '=' to ignore version part
                # e.g., 'pc:znc=1.9.1' becomes 'pc:znc'
                # Note: Consider keeping versions for more precise dependency resolution
                provide_key = provide.split("=")[0]
                provides_map[provide_key].append(name)

    return pkg_map, provides_map

def fetch_all_indexes(version):
    """
    Fetch and combine APKINDEX data for all branches and supported architectures.

    Downloads package indexes from all available repository branches for each
    supported architecture, then combines them into unified data structures.
    This provides a complete view of all available packages for the specified
    Alpine version.

    Args:
        version (str): Alpine version to fetch indexes for ('3.21', 'edge', etc.)

    Returns:
        tuple: (apk_indexes, provides_indexes, available_arches) where:
            - apk_indexes (dict): Maps arch -> package_name -> ApkPackage
            - provides_indexes (dict): Maps arch -> virtual_provide -> [package_names]
            - available_arches (list): Architectures that have valid indexes

    Process:
        1. For each architecture, fetch indexes from all branches
        2. Combine branch indexes into a single per-architecture index
        3. Skip architectures where no indexes could be fetched
        4. Return unified data structures for dependency resolution

    Examples:
        >>> indexes, provides, archs = fetch_all_indexes('3.21')
        >>> 'x86_64' in archs
        True
        >>> 'curl' in indexes['x86_64']
        True
        >>> 'cmd:curl' in provides['x86_64']
        True

    Note:
        Not all architectures may be available for all Alpine versions.
        The function gracefully handles missing architectures and continues
        with whatever is available.
    """
    apk_indexes = {}
    provides_indexes = {}
    available_arches = []

    for arch in ARCHITECTURES:
        combined_index = {}
        combined_provides = defaultdict(list)
        found = False

        # Fetch indexes from all branches for this architecture
        for branch in get_branch_list(version):
            index, provides = fetch_and_parse_index(version, branch, arch)
            if index:
                combined_index.update(index)
                # Merge provides mappings from all branches
                for provide_key, providers in provides.items():
                    combined_provides[provide_key].extend(providers)
                found = True

        if found:
            apk_indexes[arch] = combined_index
            provides_indexes[arch] = combined_provides
            available_arches.append(arch)
        else:
            print(f"⚠️ Skipping architecture '{arch}' — no APKINDEX files found.")

    return apk_indexes, provides_indexes, available_arches

def strip_version(dep):
    """
    Remove version constraints from a dependency string.

    Alpine package dependencies can include version constraints like
    '>=', '=', '<', '~', etc. This function extracts just the package
    name portion for dependency resolution.

    Args:
        dep (str): Dependency string with potential version constraints

    Returns:
        str: Package name without version constraints

    Examples:
        >>> strip_version('libssl3>=3.0.0')
        'libssl3'
        >>> strip_version('python3~=3.11')
        'python3'
        >>> strip_version('curl')
        'curl'
    """
    return re.split(r'[<>=~]+', dep)[0]

# pylint: disable=too-many-arguments,too-many-branches,too-many-locals
def resolve_dependencies(pkgname, index, provides, resolved, missing, presence,
                        branch, arch, chain=None, chains=None):
    """
    Recursively resolve all dependencies for a given package.

    This is the core dependency resolution function that traverses the
    dependency graph, handling direct packages, virtual provides, metapackages,
    and various dependency types. It builds a complete closure of all
    required packages.

    Args:
        pkgname (str): Name of package to resolve dependencies for
        index (dict): Maps package names to ApkPackage objects for this arch
        provides (dict): Maps virtual provides to providing package names
        resolved (set): Accumulator for successfully resolved package names
        missing (set): Accumulator for packages that couldn't be resolved
        presence (defaultdict): Maps package names to set of (branch, arch) tuples
        branch (str): Current repository branch being processed
        arch (str): Current architecture being processed
        chain (list, optional): Dependency chain path for debugging
        chains (dict, optional): Maps packages to all dependency chains leading to them

    Resolution Process:
        1. Check if package already resolved (avoid cycles)
        2. Try to find package in direct package index
        3. If not found, check virtual provides mapping
        4. Handle special metapackage dependencies (o: prefix)
        5. Recursively resolve all dependencies of found package
        6. Handle virtual provides (so:, cmd:, pc: prefixes)
        7. Record unresolvable dependencies as missing

    Special Dependency Types:
        - so:libname: Shared library dependencies
        - cmd:command: Command/binary dependencies
        - pc:pkgconfig: pkg-config dependencies
        - o:metaname: Metapackage dependencies
        - !package: Conflict dependencies (ignored)

    Examples:
        >>> resolved, missing = set(), set()
        >>> presence = defaultdict(set)
        >>> resolve_dependencies('curl', index, provides, resolved, missing,
        ...                      presence, 'main', 'x86_64')
        >>> 'libssl3' in resolved  # curl depends on libssl3
        True
    """
    if chain is None:
        chain = [pkgname]
    else:
        chain = chain[:]
    if chains is None:
        chains = {}

    # Avoid resolving the same package multiple times (cycle detection)
    if pkgname in resolved:
        return

    # Try to find package in direct package index
    if pkgname in index:
        pkg = index[pkgname]
        resolved.add(pkgname)
        # Always track package in its actual branch, not the requested branch
        presence[pkgname].add((pkg.branch, arch))
        chains.setdefault(pkgname, []).append(chain)
        deps = pkg.depends

    # Package not found directly, check if it's provided by another package
    elif pkgname in provides:
        real_pkg = provides[pkgname][0]  # Take first providing package
        annotated = f"{real_pkg}[{pkgname}]"

        # Special handling for metapackages (o: prefix)
        # When a metapackage is installed, all its subpackages are also installed
        if pkgname.startswith("o:"):
            deps = [p.name for p in index.values() if p.metaname == pkgname]

        resolve_dependencies(real_pkg, index, provides, resolved, missing, presence,
                           branch, arch, chain + [annotated], chains)
        return

    # Package not found anywhere - mark as missing
    else:
        missing.add(pkgname)
        return

    # Recursively resolve all dependencies of this package
    for dep in deps:
        # Skip conflict dependencies (prefixed with '!')
        # These specify packages that conflict with this one, not dependencies
        if dep.startswith("!"):
            continue

        dep_name = strip_version(dep)

        # Handle virtual provides: so:, cmd:, pc: prefixes
        if dep_name.startswith(("so:", "cmd:", "pc:")):
            if dep_name in provides:
                real_pkg = provides[dep_name][0]
                annotated = f"{real_pkg}[{dep_name}]"
                resolve_dependencies(real_pkg, index, provides, resolved, missing,
                                   presence, branch, arch, chain + [annotated], chains)
            else:
                missing.add(dep_name)

        # Handle direct package dependencies
        elif dep_name in index:
            resolve_dependencies(dep_name, index, provides, resolved, missing,
                               presence, branch, arch, chain + [dep_name], chains)
        else:
            missing.add(dep_name)

def read_package_lists(base_path, version):
    """
    Read existing package lists from disk for a given Alpine version.

    Loads previously generated package lists from the filesystem. These
    lists are organized by branch and architecture, with common packages
    stored in branch-only files and architecture-specific packages in
    branch.arch files.

    File Organization:
        mirrors/3.21/main           # Common packages in main branch
        mirrors/3.21/main.x86_64    # x86_64-specific packages in main
        mirrors/3.21/community      # Common packages in community branch
        mirrors/3.21/community.aarch64  # aarch64-specific packages in community

    Args:
        base_path (str): Base directory containing version subdirectories
        version (str): Alpine version to read package lists for

    Returns:
        defaultdict: Nested dict with structure:
            packages_by_branch_arch[branch][arch] = set(package_names)
            where arch can be 'all' for common packages or specific arch names

    Examples:
        >>> packages = read_package_lists('pkg/alpine/mirrors', '3.21')
        >>> 'curl' in packages['main']['all']
        True
        >>> len(packages['community']['x86_64'])
        42
    """
    packages_by_branch_arch = defaultdict(lambda: defaultdict(set))
    base_dir = Path(base_path) / version

    if not base_dir.exists():
        return packages_by_branch_arch

    for branch in get_branch_list(version):
        for entry in base_dir.glob(f"{branch}*"):
            if entry.is_file():
                # Parse filename to determine architecture
                # 'main' -> arch='all', 'main.x86_64' -> arch='x86_64'
                arch = 'all'
                parts = entry.name.split('.')
                if len(parts) == 2:
                    arch = parts[1]

                # Read package names from file (one per line)
                with entry.open() as package_file:
                    for line in package_file:
                        pkg = line.strip()
                        if pkg:
                            packages_by_branch_arch[branch][arch].add(pkg)

    return packages_by_branch_arch

# pylint: disable=too-many-locals
def write_packages(base_path: str, version: str,
                  classified: Dict[str, Dict[str, Set[str]]],
                  available_arches: List[str],
                  track_newly_added: bool = False
                  ) -> Optional[DefaultDict[str, DefaultDict[str, Set[str]]]]:
    """
    Write classified package lists to disk with optional change tracking.

    Takes classified packages (organized by branch and architecture) and writes
    them to the appropriate files. Can optionally track which packages are
    newly added compared to existing files.

    File Structure Created:
        base_path/version/main              # Common packages across all arches
        base_path/version/main.x86_64       # x86_64-specific packages
        base_path/version/community         # Common community packages
        base_path/version/community.aarch64 # aarch64-specific community packages

    Args:
        base_path (str): Base directory to write package lists
        version (str): Alpine version subdirectory name
        classified (dict): Package classification from classify_packages()
            Format: classified[branch]["all"|arch] = set(package_names)
        available_arches (list): Available architectures to process
        track_newly_added (bool): Whether to track newly added packages

    Returns:
        DefaultDict[str, DefaultDict[str, Set[str]]] or None: If track_newly_added=True,
            returns nested dict: newly_added[arch][branch] = set(new_package_names)
            Otherwise returns None

    Examples:
        >>> classified = {'main': {'all': {'curl'}, 'x86_64': {'vim'}}}
        >>> newly_added = write_packages('mirrors', '3.21', classified,
        ...                             ['x86_64'], track_newly_added=True)
        >>> newly_added['x86_64']['main']
        {'vim'}
    """
    outdir = Path(base_path) / version
    outdir.mkdir(parents=True, exist_ok=True)

    def load_existing(path):
        """Load existing package list from file, return empty set if file doesn't exist."""
        if not path.exists():
            return set()
        return {line.strip() for line in path.read_text().splitlines() if line.strip()}

    newly_added = defaultdict(lambda: defaultdict(set)) if track_newly_added else None

    # Process each branch (main, community, etc.)
    for branch in BRANCHES:
        # Handle common packages (available on all architectures)
        common = classified[branch]["all"]
        fpath = outdir / branch
        if track_newly_added:
            current = load_existing(fpath)
            new = common - current
            # Since these are common packages, they're new for all architectures
            if newly_added is not None:
                for arch in available_arches:
                    newly_added[arch][branch].update(new)
            # Write merged package list (existing + new) or remove if empty
            merged = current.union(common)
            if merged:
                with fpath.open("w") as common_file:
                    common_file.write("\n".join(sorted(merged)) + "\n")
            elif fpath.exists():
                fpath.unlink()
        else:
            # Write file if has packages, remove if empty
            if common:
                with fpath.open("w") as common_file:
                    common_file.write("\n".join(sorted(common)) + "\n")
            elif fpath.exists():
                fpath.unlink()

        # Handle architecture-specific packages
        for arch in available_arches:
            arch_pkgs = classified[branch][arch]
            fpath = outdir / f"{branch}.{arch}"
            if track_newly_added:
                current = load_existing(fpath)
                new = arch_pkgs - current
                if newly_added is not None:
                    newly_added[arch][branch].update(new)
                # Write merged package list (existing + new) or remove if empty
                merged = current.union(arch_pkgs)
                if merged:
                    with fpath.open("w") as arch_file:
                        arch_file.write("\n".join(sorted(merged)) + "\n")
                elif fpath.exists():
                    fpath.unlink()
            else:
                # Write file if has packages, remove if empty
                if arch_pkgs:
                    with fpath.open("w") as arch_file:
                        arch_file.write("\n".join(sorted(arch_pkgs)) + "\n")
                elif fpath.exists():
                    fpath.unlink()

    return newly_added if track_newly_added else None


# pylint: disable=too-many-locals
def resolve_and_classify_packages(packages_to_add, apk_indexes, provides_indexes,
                                 available_archs, collect_chains=False):
    """
    Resolve dependencies for specified packages and classify results by branch and architecture.

    This high-level function combines dependency resolution with package classification.
    It processes each requested package across all architectures, resolves their
    complete dependency trees, and organizes the results for writing to package lists.

    Process:
        1. Initialize data structures for tracking resolution results
        2. For each architecture and requested package:
           - Find package in indexes (direct or via provides)
           - Recursively resolve all dependencies
           - Track package presence by branch/architecture
           - Record any unresolvable packages as missing
        3. Classify resolved packages into common vs arch-specific buckets

    Args:
        packages_to_add (list): Package names to resolve and add
        apk_indexes (dict): Maps architecture -> package_name -> ApkPackage
        provides_indexes (dict): Maps architecture -> virtual_provide -> [package_names]
        available_archs (list): Architectures to process packages for
        collect_chains (bool, optional): Whether to collect dependency chains for debugging

    Returns:
        tuple: (classified, missing_by_branch_arch[, chains_by_branch_arch]) where:
            - classified (dict): Package classification by branch/arch from classify_packages()
            - missing_by_branch_arch (dict): Unresolvable packages by branch/arch
            - chains_by_branch_arch (dict): Dependency chains (only if collect_chains=True)

    Examples:
        >>> packages = ['curl', 'vim']
        >>> classified, missing = resolve_and_classify_packages(
        ...     packages, indexes, provides, ['x86_64', 'aarch64'])
        >>> 'curl' in classified['main']['all']  # curl available on all arches
        True
        >>> len(missing['main']['x86_64']) == 0   # no missing packages
        True

        >>> # With dependency chains
        >>> result = resolve_and_classify_packages(
        ...     packages, indexes, provides, ['x86_64'], collect_chains=True)
        >>> classified, missing, chains = result
        >>> 'curl' in chains['main']['x86_64']
        True
    """
    # Initialize data structures for dependency resolution
    presence = defaultdict(set)  # Maps package -> set of (branch, arch) tuples
    resolved_by_branch_arch = {branch: {arch: set() for arch in available_archs}
                              for branch in BRANCHES}
    missing_by_branch_arch = {branch: {arch: set() for arch in available_archs}
                             for branch in BRANCHES}
    chains_by_branch_arch = ({branch: {arch: {} for arch in available_archs}
                             for branch in BRANCHES} if collect_chains else None)

    print("🔄 Resolving dependencies...")

    # Process each architecture separately to handle arch-specific availability
    for arch in available_archs:
        for pkgname in packages_to_add:
            found = False

            # Try to find package directly in package index
            if pkgname in apk_indexes[arch]:
                pkg = apk_indexes[arch][pkgname]
                resolve_dependencies(
                    pkgname,
                    apk_indexes[arch],
                    provides_indexes[arch],
                    resolved_by_branch_arch[pkg.branch][arch],
                    missing_by_branch_arch[pkg.branch][arch],
                    presence,
                    pkg.branch,
                    arch,
                    chain=[pkgname],
                    # pylint: disable=unsubscriptable-object
                    chains=(chains_by_branch_arch[pkg.branch][arch]
                           if (collect_chains and chains_by_branch_arch)
                           else {})
                )
                found = True

            # If not found directly, check if it's provided by another package
            elif pkgname in provides_indexes[arch]:
                # Take the first package that provides this virtual package
                real_pkg = provides_indexes[arch][pkgname][0]
                if real_pkg in apk_indexes[arch]:
                    pkg = apk_indexes[arch][real_pkg]
                    resolve_dependencies(
                        real_pkg,
                        apk_indexes[arch],
                        provides_indexes[arch],
                        resolved_by_branch_arch[pkg.branch][arch],
                        missing_by_branch_arch[pkg.branch][arch],
                        presence,
                        pkg.branch,
                        arch,
                        chain=[real_pkg],
                        # pylint: disable=unsubscriptable-object
                        chains=(chains_by_branch_arch[pkg.branch][arch]
                               if (collect_chains and chains_by_branch_arch)
                               else {})
                    )
                    found = True

            # Package not available for this architecture
            if not found:
                print(f"⚠️  Package '{pkgname}' not found in any branch for architecture '{arch}'")
                # Mark as missing in all branches for this architecture
                for branch in BRANCHES:
                    missing_by_branch_arch[branch][arch].add(pkgname)

    print("📊 Classifying packages by architecture and branch...")
    classified = classify_packages(resolved_by_branch_arch, presence, available_archs)

    if collect_chains:
        return classified, missing_by_branch_arch, chains_by_branch_arch
    return classified, missing_by_branch_arch

def write_missing_report(base_path, version, missing_by_branch_arch, available_archs):
    """
    Write reports of unresolved package dependencies to disk.

    Creates separate files listing packages that couldn't be resolved during
    dependency resolution. This helps identify missing packages, renamed
    packages, or packages that moved between branches/architectures.

    Files Created:
        base_path/version/MISSING.main.x86_64      # Missing packages in main/x86_64
        base_path/version/MISSING.community.aarch64  # Missing packages in community/aarch64
        (Only created if there are missing packages for that branch/arch combination)

    Args:
        base_path (str): Base directory to write missing reports
        version (str): Alpine version subdirectory
        missing_by_branch_arch (dict): Missing packages organized as
            missing_by_branch_arch[branch][arch] = set(missing_package_names)
        available_archs (list): Architectures that were processed

    File Format:
        One package name per line, sorted alphabetically

    Examples:
        >>> missing = {'main': {'x86_64': {'nonexistent-pkg', 'old-pkg'}}}
        >>> write_missing_report('mirrors', '3.21', missing, ['x86_64'])
        # Creates: mirrors/3.21/MISSING.main.x86_64 with:
        # nonexistent-pkg
        # old-pkg
    """
    out_dir = os.path.join(base_path, version)
    os.makedirs(out_dir, exist_ok=True)

    for branch in get_branch_list(version):
        for arch in available_archs:
            missing = missing_by_branch_arch.get(branch, {}).get(arch, set())
            if missing:
                out_path = os.path.join(out_dir, f"MISSING.{branch}.{arch}")
                with open(out_path, "w", encoding="utf-8") as missing_file:
                    for pkg in sorted(missing):
                        missing_file.write(pkg + "\n")

def classify_packages(resolved_by_branch_arch, presence, available_archs):
    """
    Classify resolved packages into common vs architecture-specific categories.

    Organizes packages based on their availability across architectures:
    - Common packages: Available on all architectures (stored in branch files)
    - Arch-specific packages: Only available on some architectures (stored in branch.arch files)

    This classification optimizes storage and allows for efficient package list management
    by avoiding duplication of common packages across architecture-specific files.

    Args:
        resolved_by_branch_arch (dict): Resolved packages organized as
            resolved_by_branch_arch[branch][arch] = set(package_names)
        presence (dict): Maps package_name -> set((branch, arch)) indicating
            where each package is available
        available_archs (list): Architectures being processed

    Returns:
        dict: Classification organized as:
            classified[branch]["all"] = set(packages_available_on_all_archs)
            classified[branch][arch] = set(packages_only_on_this_arch)

    Classification Logic:
        1. Collect all unique packages across all architectures for each branch
        2. For each package, check which architectures it's present on
        3. If present on all architectures -> classify as "all" (common)
        4. If present on subset of architectures -> classify per architecture

    Examples:
        >>> presence = {'curl': {('main', 'x86_64'), ('main', 'aarch64')},
        ...             'vim': {('main', 'x86_64')}}
        >>> available_archs = ['x86_64', 'aarch64']
        >>> classified = classify_packages(resolved, presence, available_archs)
        >>> 'curl' in classified['main']['all']  # Available on all archs
        True
        >>> 'vim' in classified['main']['x86_64']  # Only on x86_64
        True
    """
    # Initialize classification structure
    classified = {
        branch: {"all": set(), **{arch: set() for arch in available_archs}}
        for branch in BRANCHES
    }

    # Process each branch separately
    for branch in BRANCHES:
        # Collect all unique packages in this branch across all architectures
        all_pkgs = set()
        for arch in available_archs:
            all_pkgs.update(resolved_by_branch_arch[branch][arch])

        # Classify each package based on architecture presence
        for pkg in sorted(all_pkgs):
            # Find which architectures have this package in this branch
            present_archs = {arch for (b, arch) in presence[pkg] if b == branch}

            # If package is available on all architectures, it's common
            if present_archs == set(available_archs):
                classified[branch]["all"].add(pkg)
            # Otherwise, it's architecture-specific
            else:
                for arch in present_archs:
                    classified[branch][arch].add(pkg)

    return classified

def print_dependency_chain(chains_by_branch_arch, available_archs, apk_indexes=None):
    """
    Print detailed dependency resolution chains for debugging and analysis.

    Displays the complete dependency paths showing how each package was
    resolved, including the chain of dependencies that led to its inclusion.
    This is useful for understanding why certain packages are being included
    and for debugging dependency resolution issues.

    Args:
        chains_by_branch_arch (dict): Dependency chains organized as
            chains_by_branch_arch[branch][arch][package] = [dependency_paths]
            where each dependency_path is a list showing the resolution chain
        available_archs (list): Architectures to display chains for
        apk_indexes (dict, optional): Maps arch -> package_name -> ApkPackage
            for adding branch indicators to package names

    Output Format:
        [Branch: main, Arch: x86_64]
        curl:m:
          - curl:m → libssl3:m → zlib:m
          - curl:m → libcurl4:m
        wget:m:
          - wget:m → libssl3:m → zlib:m

    Chain Notation:
        - package:m: Package from main branch
        - package:c: Package from community branch
        - package:t: Package from testing branch
        - package[virtual]: Package resolved via virtual provides
        - Arrow (→): Dependency relationship direction

    Examples:
        >>> chains = {'main': {'x86_64': {'curl': [['curl', 'libssl3']]}}}
        >>> print_dependency_chain(chains, ['x86_64'], apk_indexes)
        [Branch: main, Arch: x86_64]
        curl:m:
          - curl:m → libssl3:m
    """
    def get_branch_indicator(pkg_name, arch):
        """Get branch indicator (:m/:c/:t) for a package."""
        if not apk_indexes or arch not in apk_indexes:
            return ""

        # Remove [virtual] annotations for lookup
        clean_name = pkg_name.split('[')[0]

        if clean_name in apk_indexes[arch]:
            branch = apk_indexes[arch][clean_name].branch
            return f":{branch[0]}"
        return ""

    print("\n📋 Dependency chains:\n")

    for branch in BRANCHES:
        for arch in available_archs:
            print(f"[Branch: {branch}, Arch: {arch}]")
            chains = chains_by_branch_arch[branch][arch]

            for parent_pkg, paths in chains.items():
                parent_indicator = get_branch_indicator(parent_pkg, arch)
                print(f"{parent_pkg}{parent_indicator}:")

                # Remove duplicate paths to avoid redundant output
                unique_paths = []
                for path in paths:
                    if path not in unique_paths:
                        unique_paths.append(path)

                # Print each unique dependency path with branch indicators
                for path in unique_paths:
                    annotated_path = []
                    for pkg in path:
                        indicator = get_branch_indicator(pkg, arch)
                        annotated_path.append(f"{pkg}{indicator}")
                    print("  - " + " → ".join(annotated_path))
            print()
