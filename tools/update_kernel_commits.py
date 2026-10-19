#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""
Copyright (c) 2023-2026 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0

This script does two things:
1. Generates the kernel-commits.mk file with commit information from GitHub branches.
2. Generates a commit message with commit subjects and corresponding commit hashes between
    old and new commits for each branch.

this script queries the GitHub API to get the latest commit hashes for the kernel branches
The generated commit message is saved to kernel-update-commit-message.txt

Note:
- This module depends on the 'requests' library for making HTTP requests to the GitHub API.
- Make sure to review the generated commit message before committing the changes to your repository.

Author: Mikhail Malyshev <mike.malyshev@gmail.com>
"""

import argparse
import datetime
import json
import os
import re
import sys
import requests
from colorama import Fore, Style, init  # pylint: disable=import-error

# do not force users to have pytest installed
try:
    import pytest

    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False


class LinuxKernelTagNotPushedError(Exception):
    """Exception raised when a Linux kernel tag is referenced but not pushed to the repository."""


class CommitFetchError(Exception):
    """Exception raised when fetching commit information from GitHub API fails."""


def get_short_arch_flavor(branch_name):
    """
    Get a short representation of the architecture and flavor from the branch name.

    Parameters:
    - branch_name (str): The name of the branch from which to extract architecture and flavor.

    Returns:
    - str: A short representation of the architecture and flavor.
    """
    parts = branch_name.split("-", 4)
    if len(parts) == 5:
        # Versioned branch: eve-kernel-amd64-v5.10-generic
        _, _, arch, _, flavor = parts
        return f"{arch}-{flavor}"
    if len(parts) == 4 and parts[3] == "next":
        # Next branch: eve-kernel-amd64-next
        _, _, arch, version = parts
        return f"{arch}-{version}"
    # Fallback for unexpected format
    _, _, arch, *rest = parts
    return f"{arch}-{'-'.join(rest)}"


def fetch_latest_commits_from_github(user, user_token, verbose=False):
    """
    This function retrieves branch information from a GitHub repository and
    returns the commit hashes for each branch in a set. Protected branches are ignored
    """
    # pylint: disable-next=line-too-long
    repo_url = (
        f"https://api.github.com/repos/{user}/eve-kernel/branches"
        "?protected=false&per_page=100"
    )
    new_commits = {}

    headers = {"Authorization": f"token {user_token}"}

    session = requests.Session()
    session.headers.update(headers)

    print("Fetching branch information from github...")

    while True:
        response = session.get(repo_url)
        if response.status_code == 200:
            branches = response.json()
            for branch in branches:
                commit = branch["commit"]["sha"][:12]
                branch_name = branch["name"]
                if is_valid_branch_format(branch_name):
                    new_commits[branch_name] = commit
                    if verbose:
                        print(f"  {branch_name}, Commit: {commit}")
                else:
                    if verbose:
                        print(f"    skipping: {branch_name}")

            if "next" in response.links:
                repo_url = response.links["next"]["url"]
            else:
                break
        elif response.status_code == 401:
            print(
                Fore.RED
                + Style.BRIGHT
                + "Error: Unauthorized (401). Your GitHub token is invalid or expired."
            )
            print("Please enter a new GitHub personal access token.")
            if os.path.exists(config_file_path):
                os.remove(config_file_path)
            new_token = get_github_token_from_user()
            write_github_token_to_config(new_token)
            # Update session headers and retry
            session.headers.update({"Authorization": f"token {new_token}"})
            continue  # Retry the request with the new token
        else:
            print(
                Fore.RED + Style.BRIGHT + "Error:", response.status_code, response.text
            )
            sys.exit(1)
    return new_commits


def is_valid_branch_format(branch_name):
    """
    Check if the branch name follows a specific pattern and return
    True if it matches, otherwise return False.

    Parameters:
    - branch_name (str): The name of the branch to check.

    Returns:
    - bool: True if the branch name follows the expected format, False otherwise.
    """
    # Match versioned branches: eve-kernel-(arch)-v\d+\.\d+(?:\.\d+)?-.+
    # Or next branches: eve-kernel-(arch)-next
    match = re.fullmatch(
        r"eve-kernel-(amd64|arm64|riscv64)-(v\d+\.\d+(?:\.\d+)?-.+|next)", branch_name
    )
    return match is not None


def variable_to_branch_name(variable_name):
    """
    Convert a variable name to the branch name format.

    Parameters:
    - variable_name (str): The variable name to convert.

    Returns:
    - str: The branch name in the expected format.
    """
    # Handle next branches with flavor: KERNEL_COMMIT_amd64_next_generic -> eve-kernel-amd64-next
    # (strip the flavor part for next branches)
    if "_next_" in variable_name:
        # Extract arch from variable like KERNEL_COMMIT_amd64_next_generic
        parts = variable_name.replace("KERNEL_COMMIT_", "").split("_")
        if len(parts) >= 2 and parts[1] == "next":
            arch = parts[0]
            return f"eve-kernel-{arch}-next"

    # Regular branches: KERNEL_COMMIT_amd64_v6.1.112_generic -> eve-kernel-amd64-v6.1.112-generic
    branch_name = variable_name.replace("KERNEL_COMMIT_", "").replace("_", "-")
    return f"eve-kernel-{branch_name}"


def branch_commit_to_variable(branch_name, commit):
    """
    Convert a branch name and commit hash to a variable name.

    Parameters:
    - branch_name (str): The name of the branch.
    - commit (str): The commit hash.

    Returns:
    - str: The variable name(s) in the expected format.
          For next branches, generates multiple variables for different flavors.
    """
    # pylint: disable-next=line-too-long
    # Match versioned branches: eve-kernel-(arch)-v\d+\.\d+(?:\.\d+)?-(platform)
    # Or next branches: eve-kernel-(arch)-next (no platform suffix)

    # Try matching versioned format first (has platform suffix)
    branch_match = re.match(
        r"(?P<branch>eve-kernel-(amd64|arm64|riscv64)-(v\d+\.\d+(?:\.\d+)?))-(?P<platform>.+)",
        branch_name,
    )

    if branch_match:
        branch_name = (
            branch_match.group("branch")
            .replace("eve-kernel-", "KERNEL_COMMIT_")
            .replace("-", "_")
        )
        variable_name = branch_name + "_" + branch_match.group("platform")
        return f"{variable_name} = {commit}\n"

    # Try matching next format (no platform suffix)
    next_match = re.match(r"eve-kernel-(amd64|arm64|riscv64)-next", branch_name)

    if next_match:
        arch = next_match.group(1)
        # For next branches, always use generic flavor (next branches are generic by default)
        variable_name = f"KERNEL_COMMIT_{arch}_next_generic"
        return f"{variable_name} = {commit}\n"

    sys.exit(f"Error: Invalid branch name format: {branch_name}")


if PYTEST_AVAILABLE:

    def test_branch_commit_to_variable():
        """
        Test the branch_commit_to_variable function with valid branch names.
        """

        assert (
            branch_commit_to_variable("eve-kernel-amd64-v5.10.186-generic", "abcd")
            == "KERNEL_COMMIT_amd64_v5.10.186_generic = abcd\n"
        )
        assert (
            branch_commit_to_variable("eve-kernel-amd64-v5.10-generic", "abcd")
            == "KERNEL_COMMIT_amd64_v5.10_generic = abcd\n"
        )
        assert (
            branch_commit_to_variable("eve-kernel-arm64-v5.10.192-nvidia-jp5", "abcd")
            == "KERNEL_COMMIT_arm64_v5.10.192_nvidia-jp5 = abcd\n"
        )
        assert (
            branch_commit_to_variable("eve-kernel-arm64-v5.10-nvidia-jp5", "abcd")
            == "KERNEL_COMMIT_arm64_v5.10_nvidia-jp5 = abcd\n"
        )
        # Next branches always use generic flavor
        assert (
            branch_commit_to_variable("eve-kernel-amd64-next", "abcd")
            == "KERNEL_COMMIT_amd64_next_generic = abcd\n"
        )
        assert (
            branch_commit_to_variable("eve-kernel-arm64-next", "abcd")
            == "KERNEL_COMMIT_arm64_next_generic = abcd\n"
        )
        assert (
            branch_commit_to_variable("eve-kernel-riscv64-next", "abcd")
            == "KERNEL_COMMIT_riscv64_next_generic = abcd\n"
        )

    def test_branch_commit_to_variable_exit():
        """
        Test the branch_commit_to_variable function on incorrect br.
        """
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            branch_commit_to_variable("eve-kernel-arm64-v5-nvidia-jp5", "abcd")
        assert pytest_wrapped_e.type == SystemExit
        assert (
            pytest_wrapped_e.value.code
            == "Error: Invalid branch name format: eve-kernel-arm64-v5-nvidia-jp5"
        )

    def test_is_valid_branch_format():
        """
        Test the is_valid_branch_format function with valid branch names.
        """
        assert is_valid_branch_format("eve-kernel-arm64-v5.10.186-generic") is True
        assert is_valid_branch_format("eve-kernel-amd64-v5.10-generic") is True
        assert is_valid_branch_format("eve-kernel-riscv64-v5.10.192-nvidia-jp5") is True
        assert is_valid_branch_format("eve-kernel-arm64-v5.10-nvidia-jp5") is True
        assert is_valid_branch_format("eve-kernel-arm64-v5.10-nvidia-jp5") is True
        assert is_valid_branch_format("eve-kernel-amd64-next") is True
        assert is_valid_branch_format("eve-kernel-arm64-next") is True
        assert is_valid_branch_format("eve-kernel-riscv64-next") is True

    def test_is_invalid_branch_format():
        """
        Test the is_valid_branch_format function with invalid branch names.
        """
        assert is_valid_branch_format("v5.10-nvidia-jp5") is False
        assert is_valid_branch_format("eve-kernel-v6.8") is False
        assert is_valid_branch_format("eve-kernel-6.8") is False
        assert is_valid_branch_format("eve-kernel-update") is False
        assert is_valid_branch_format("eve-kernel-v6.8-") is False
        assert is_valid_branch_format("eve-kernel-arm64-v6.8") is False
        assert is_valid_branch_format("eve-kernel-amd64-next-generic") is False
        assert is_valid_branch_format("eve-kernel-arm64-nextstuff") is False


def parse_kernel_commits_file(file_path):
    """
    Parse the kernel commits file and return a dictionary of branch names and commit hashes.

    Parameters:
    - file_path (str): The path to the kernel-commits.mk file.

    Returns:
    - dict: A dictionary mapping branch names to commit hashes.
    """
    commits = {}
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if "=" in line:
                key, value = line.strip().split(" = ")
                branch_name = variable_to_branch_name(key.strip())
                commits[branch_name] = value.strip()
    return commits


def check_tag_exists(tag_name, repo_owner, repo_name, token=None, verbose=False):
    """
    Check if a specific tag exists in the repository.

    Parameters:
    - tag_name (str): The tag name to check (e.g., "v6.1.111").
    - repo_owner (str): The owner of the GitHub repository.
    - repo_name (str): The name of the GitHub repository.
    - token (str): GitHub personal access token for authentication.
    - verbose (bool): Enable verbose output.

    Returns:
    - bool: True if the tag exists, False otherwise.
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    # Check if tag exists using the git refs API
    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/refs/tags/{tag_name}"

    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        if response.status_code == 200:
            if verbose:
                print(f"    Tag {tag_name} exists in repository")
            return True
        if response.status_code == 403:
            # API rate limit - assume tag exists since we can't verify
            if verbose:
                print(
                    f"    Tag {tag_name} not found in repository "
                    f"(status: {response.status_code})"
                )
            return False
        # For other status codes, assume tag doesn't exist
        if verbose:
            print(f"    Tag {tag_name} not found (status: {response.status_code})")
        return False
    except (requests.RequestException, KeyError, ValueError) as exc:
        if verbose:
            print(f"    Error checking tag {tag_name}: {exc}")
        return False


def _fetch_kernel_tags(repo_owner, repo_name, headers, verbose):
    """Helper function to fetch kernel tags from GitHub."""
    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/tags?per_page=100&page=1"
    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        if response.status_code != 200:
            if verbose:
                print(f"    Failed to fetch tags: {response.status_code}")
            return None

        page_tags = response.json()
        # Filter for Linux kernel version tags (vX.Y.Z or vX.Y format)
        tags = [
            tag for tag in page_tags if re.match(r"^v\d+\.\d+(\.\d+)?$", tag["name"])
        ]
        return tags
    except (requests.RequestException, KeyError, ValueError) as exc:
        if verbose:
            print(f"    Error fetching tags: {exc}")
        return None


def _check_single_tag(tag, commit_sha, repo_config, headers, verbose):
    """Helper to check a single tag and return ahead_by count."""
    repo_owner, repo_name = repo_config
    tag_name = tag["name"]

    api_url = (
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/"
        f"compare/{tag_name}...{commit_sha}"
    )

    response = requests.get(api_url, headers=headers, timeout=30)
    if response.status_code != 200:
        return None

    data = response.json()
    ahead_by = data.get("ahead_by", float("inf"))

    if verbose:
        print(f"      {tag_name}: {ahead_by} commits ahead")

    return ahead_by


def _find_best_tag(tags, commit_sha, repo_config, headers, verbose):
    """Helper function to find the best tag among candidates."""
    best_tag = None
    smallest_ahead = float("inf")

    # Check only first 20 tags to limit API calls
    for tag in tags[:20]:
        try:
            ahead_by = _check_single_tag(tag, commit_sha, repo_config, headers, verbose)
            if ahead_by is None:
                continue

            if ahead_by < smallest_ahead:
                smallest_ahead = ahead_by
                best_tag = tag["name"]

                # Early exit if we found a good match
                if ahead_by < 100:
                    if verbose:
                        print("    Found good match, stopping search early")
                    break
        except (requests.RequestException, KeyError, ValueError) as exc:
            if verbose:
                print(f"      Error checking {tag.get('name', 'unknown')}: {exc}")

    return best_tag, smallest_ahead


def find_nearest_kernel_tag(
    commit_sha, repo_owner, repo_name, token=None, verbose=False
):
    """
    Find the nearest Linux kernel tag (vX.Y.Z format) that is an ancestor of the given commit.
    This simulates 'git describe --tags' using GitHub API.

    Parameters:
    - commit_sha (str): The commit SHA to find the nearest tag for.
    - repo_owner (str): The owner of the GitHub repository.
    - repo_name (str): The name of the GitHub repository.
    - token (str): GitHub personal access token for authentication.
    - verbose (bool): Enable verbose output.

    Returns:
    - str: The nearest kernel tag, or None if not found.
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    if verbose:
        print(f"  Searching for nearest kernel tag for commit {commit_sha[:12]}...")

    # Get only the first page of tags (most recent 100)
    tags = _fetch_kernel_tags(repo_owner, repo_name, headers, verbose)
    if not tags:
        if verbose:
            print("    No kernel tags found")
        return None

    if verbose:
        print(f"    Checking {len(tags)} recent kernel tags...")

    # Find the best tag among candidates
    best_tag, smallest_ahead = _find_best_tag(
        tags, commit_sha, (repo_owner, repo_name), headers, verbose
    )

    if best_tag and verbose:
        print(f"    Found nearest tag: {best_tag} ({smallest_ahead} commits ahead)")

    return best_tag


def find_merge_base_for_next_branch(
    branch_name, all_branches, repo_config, token=None, verbose=False
):
    """
    Find the actual branch point for a next branch by finding the nearest Linux kernel tag.

    Parameters:
    - branch_name (str): The next branch name (e.g., "eve-kernel-amd64-next").
    - all_branches (dict): Dictionary of all branch names and their commit hashes.
    - repo_config (tuple): (repo_owner, repo_name) for the GitHub repository.
    - token (str): GitHub personal access token for authentication.
    - verbose (bool): Enable verbose output.

    Returns:
    - str: The tag or commit to use as the starting point, or None if not found.
    """
    # Extract architecture from the next branch name
    parts = branch_name.split("-")
    if len(parts) != 4 or parts[3] != "next":
        return None

    next_commit = all_branches[branch_name]

    # Find the nearest kernel tag using GitHub API
    repo_owner, repo_name = repo_config
    nearest_tag = find_nearest_kernel_tag(
        next_commit, repo_owner, repo_name, token, verbose
    )

    if nearest_tag:
        if verbose:
            print(f"  Using {nearest_tag} as branch point for {branch_name}")
        return nearest_tag

    if verbose:
        print(f"  Failed to find nearest tag for {branch_name}")

    return None


def _validate_old_commit(repo_owner, repo_name, old_commit, headers):
    """Helper function to validate old commit exists."""
    check_url = (
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{old_commit}"
    )
    response = requests.get(check_url, headers=headers, timeout=30)

    if response.status_code == 200:
        return

    # If not found as commit, check if it's a tag (for new branches)
    if re.match(r"^v\d+\.\d+(\.\d+)?$", old_commit):
        tag_url = (
            f"https://api.github.com/repos/{repo_owner}/{repo_name}"
            f"/git/refs/tags/{old_commit}"
        )
        tag_response = requests.get(tag_url, headers=headers, timeout=30)
        if tag_response.status_code == 200:
            return

        # Neither commit nor tag found
        error_msg = f"commit '{old_commit}' is not found in the repository."
        error_msg += (
            " This appears to be a Linux kernel tag (vX.Y.Z format)"
            " that must be pushed to the repository first."
        )
        raise LinuxKernelTagNotPushedError(error_msg)

    # Not a commit and not a tag format
    raise CommitFetchError(f"commit '{old_commit}' is not found in the repository.")


def github_fetch_commit_range(
    repo_config, old_commit, new_commit, token=None, verbose=False
):
    """
    Fetch commit subjects and their corresponding commit hashes
    between old and new commits for a branch.

    Parameters:
    - repo_config (tuple): (repo_owner, repo_name) for the GitHub repository.
    - old_commit (str): The old commit hash.
    - new_commit (str): The new commit hash.
    - token (str): GitHub personal access token for authentication.
    - verbose (bool): Enable verbose output.

    Returns:
    - list: A list of tuples containing commit SHA prefixes and subjects.

    Raises:
    - LinuxKernelTagNotPushedError: When a kernel tag is not found in the repository.
    - CommitFetchError: When there's an error fetching commits.
    """
    repo_owner, repo_name = repo_config

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    # Validate old commit exists
    _validate_old_commit(repo_owner, repo_name, old_commit, headers)

    # Fetch commit range
    api_url = (
        f"https://api.github.com/repos/{repo_owner}/{repo_name}"
        f"/compare/{old_commit}...{new_commit}"
    )

    if verbose:
        print(f"Fetching commit subjects for {old_commit}..{new_commit}...")
        print(f"API URL: {api_url}")

    response = requests.get(api_url, headers=headers, timeout=30)
    if response.status_code != 200:
        raise CommitFetchError(
            f"Failed to fetch commit range from GitHub API. Status: {response.status_code}"
        )

    commit_info = []
    for commit in response.json().get("commits", []):
        commit_info.append(
            (commit["sha"][:12], commit["commit"]["message"].split("\n")[0])
        )

    return commit_info


def generate_commit_message(branches, repo_owner, repo_name, token=None, verbose=False):
    """
    Generate a commit message with commit subjects
    and corresponding commit hashes between old and new commits.

    Parameters:
    - old_commits (dict): A dictionary of branch names and old commit hashes.
    - new_commits (dict): A dictionary of branch names and new commit hashes.
    - token (str): GitHub personal access token for authentication.

    Returns:
    - tuple: A tuple containing (commit_message: str, errors: list)
    where errors is a list of error messages.
    """
    commit_message = ""
    errors = []

    for branch in branches:
        old_commit, new_commit = branches[branch]

        if old_commit is None and new_commit is None:
            commit_message += f"{branch}: branch is now obsolete\n"
            continue

        commit_message += f"{branch}\n"

        # For new next branches (old_commit is None but new_commit exists),
        # just show the new commit without a range
        if old_commit is None and new_commit is not None:
            commit_message += f"    New branch added at commit: {new_commit}\n\n"
            continue
        # Fetch a limited number of commit subjects and their corresponding
        # commit hashes between old and new commits for the branch
        try:
            commit_infos = github_fetch_commit_range(
                (repo_owner, repo_name),
                old_commit,
                new_commit,
                token,
                verbose=verbose,
            )
            if commit_infos:
                for commit_hash, commit_subject in reversed(commit_infos):
                    commit_message += f"    {commit_hash}: {commit_subject}\n"
            else:
                commit_message += "    Unable to fetch commit subjects\n"
        except (LinuxKernelTagNotPushedError, CommitFetchError) as error:
            # Collect the error and continue processing other branches
            errors.append((branch, str(error)))
            commit_message += "    [ERROR: commit not found]\n"
        commit_message += "\n"

    arch_list = f"[{', '.join(get_short_arch_flavor(branch) for branch in branches)}]"
    commit_subject = f"Kernel update - {arch_list}\n\nThis commit changes:\n"

    commit_message = commit_subject + commit_message
    return commit_message, errors


def pattern_to_regex(pattern):
    """
    Converts a pattern string to a regular expression string.

    Args:
        pattern (str): The pattern string to convert.

    Returns:
        str: The regular expression string.
    """
    # Escape any special characters in the pattern
    escaped_pattern = re.escape(pattern)
    # Replace '*' with '.*' to match any sequence of characters
    regex_pattern = escaped_pattern.replace(r"\*", ".*")
    # match from beginning till the end
    regex_pattern = f"^{regex_pattern}$"

    return regex_pattern


def _process_versioned_branch(branch, new_commit, token, verbose):
    """Helper function to process versioned branches."""
    parts = branch.split("-", 4)
    _, _, _, tag, _ = parts

    if verbose:
        print(f"    New versioned branch: {branch}, commit: {new_commit}")
        print(f"    Checking if tag {tag} exists...")

    # Check if the tag exists in the repository
    if check_tag_exists(tag, "lf-edge", "eve-kernel", token, verbose):
        if verbose:
            print(f"    Using tag {tag} as starting point")
        return (tag, new_commit)

    # Tag doesn't exist, try to find the nearest tag
    if verbose:
        print(f"    Tag {tag} not found, searching for nearest tag...")
    nearest_tag = find_nearest_kernel_tag(
        new_commit, "lf-edge", "eve-kernel", token, verbose
    )
    if nearest_tag:
        if verbose:
            print(f"    Using nearest tag: {nearest_tag}")
        return (nearest_tag, new_commit)

    # Last resort: skip this branch or use None
    if verbose:
        print("    No tag found, will add without commit range")
    return (None, new_commit)


def _process_next_branch(branch, new_commit, new_commits, token, verbose):
    """Helper function to process next branches."""
    if verbose:
        print(f"    New next branch: {branch}, commit: {new_commit}")

    # Try to find merge-base with a reference branch
    merge_base = find_merge_base_for_next_branch(
        branch, new_commits, ("lf-edge", "eve-kernel"), token, verbose
    )

    if merge_base:
        if verbose:
            print(f"    Using merge-base: {merge_base[:12]}")
        return (merge_base, new_commit)

    # Fallback: use None if we can't find a merge-base
    if verbose:
        print("    No merge-base found, will add without commit range")
    return (None, new_commit)


def _process_new_branch(branch, new_commit, new_commits, token, verbose):
    """Helper function to process new branches."""
    parts = branch.split("-", 4)

    if len(parts) == 5:
        # Versioned branch: eve-kernel-amd64-v5.10-generic
        return _process_versioned_branch(branch, new_commit, token, verbose)
    if len(parts) == 4 and parts[3] == "next":
        # Next branch: eve-kernel-amd64-next
        return _process_next_branch(branch, new_commit, new_commits, token, verbose)
    # Fallback - use the last part as tag
    tag = parts[-1]
    return (tag, new_commit)


def find_updated_branches(old_commits, new_commits, token=None, verbose=False):
    """
    Find the branches that have been updated.

    Parameters:
    - old_commits (dict): A dictionary of branch names and old commit hashes.
    - new_commits (dict): A dictionary of branch names and new commit hashes.
    - token (str): GitHub personal access token for authentication.
    - verbose (bool): Enable verbose output.

    Returns:
    - list: A list of branch names that have been updated or added.
    """
    branches_updated = {}

    if verbose:
        print("Checking for updated branches...")

    for branch, new_commit in new_commits.items():
        if verbose:
            print(f"  {branch}, current commit: {new_commit}")

        if branch in old_commits:
            old_commit = old_commits[branch]
            if old_commit != new_commit:
                branches_updated[branch] = (old_commit, new_commit)
                if verbose:
                    print(f"    {branch} updated from {old_commit} to {new_commit}")
        else:
            # Process new branch
            result = _process_new_branch(
                branch, new_commit, new_commits, token, verbose
            )
            branches_updated[branch] = result

    if verbose:
        print("Checking for removed branches...")

    # check for removed branches
    for branch, old_commit in old_commits.items():
        if verbose:
            print(f"  {branch}, current commit: {old_commit}")
        if branch not in new_commits:
            branches_updated[branch] = (None, None)

    return branches_updated


def get_kernel_tags_from_dockerhub(
    username, repository, search_pattern: str = "", name_filter: str = "", verbose=False
):
    """
    Retrieves Docker tags from Docker Hub for a given repository.

    Args:
        username (str): The Docker Hub username.
        repository (str): The name of the Docker repository.
        search_pattern (str, optional): A regular expression pattern to filter Docker tags.
        Defaults to None.
        name_filter (str, optional): Substring passed to the Docker Hub API to filter tags
        server-side. Anonymous requests are rejected with 403 once the pagination offset
        exceeds ~1000 tags, so keep the result set small instead of listing every tag.
        verbose (bool, optional): Increase output verbosity if True. Defaults to False.

    Returns:
        list: A list of tuples containing Docker tags and their last push dates.
    """
    tags = []
    tags_url = (
        f"https://hub.docker.com/v2/repositories/{username}/{repository}/"
        f"tags/?page_size=100&ordering=last_updated"
    )
    if name_filter:
        tags_url += f"&name={name_filter}"

    # convert search patterns to gerexp
    regex_pattern = pattern_to_regex(search_pattern) if search_pattern else None

    while True:
        response = requests.get(tags_url, timeout=30)

        if response.status_code == 200:
            tags_json = response.json()
            # pretty print tags_json
            if verbose:
                print(json.dumps(tags_json, indent=4, sort_keys=True))

            for tag in tags_json["results"]:
                if regex_pattern and not re.match(regex_pattern, tag["name"]):
                    continue
                tags.append((tag["name"], tag["tag_last_pushed"]))

            if tags_json["next"]:
                tags_url = tags_json["next"]
                if verbose:
                    print(tags_url)
            else:
                break
        else:
            print(
                Fore.RED + Style.BRIGHT + "Error:", response.status_code, response.text
            )
            sys.exit(1)
    return tags


def _fetch_tags_per_branch(branches, verbose=False):
    """
    Fetches docker tags for each branch separately.

    Args:
        branches (iterable): Branch names to look up tags for.
        verbose (bool, optional): Increase output verbosity if True. Defaults to False.

    Returns:
        list: A list of tuples containing Docker tags and their last push dates.
    """
    docker_username = "lfedge"
    repository = "eve-kernel"
    branch_search_pattern = "eve-kernel-*"
    branches = list(branches)
    tags = []
    for num, branch in enumerate(branches, start=1):
        print(f"Fetching docker tags: {num} / {len(branches)} branches", end="\r")
        tags += get_kernel_tags_from_dockerhub(
            docker_username, repository, branch_search_pattern, branch, verbose
        )
    # to keep progress on the screen
    print(f"Fetching docker tags: {len(branches)} / {len(branches)} branches")
    return tags


def group_docker_tags(branches, known_branches, docker_tag_list, compiler="gcc"):
    """
    Groups Docker tags by image name and assigns each group to its branch.

    A branch with config flavours pushes one image per flavour, e.g.
    eve-kernel-amd64-v6.18.55-generic-core-<commit>-gcc. A group belongs to the
    longest known branch name it equals or extends with "-<flavour>", so tags of
    eve-kernel-arm64-v5.10.192-nvidia-jp5 that a query for
    eve-kernel-arm64-v5.10.192-nvidia returns stay with their own branch.

    Args:
        branches (iterable): Branch names the tags were queried for.
        known_branches (iterable): Every branch name on GitHub and in kernel-commits.mk.
        docker_tag_list (list): (tag, last pushed date) tuples.
        compiler (str): The compiler of the images the build pulls
        (KERNEL_COMPILER in kernel-version.mk); other images do not count.

    Returns:
        dict: {branch: {group: {commit: last pushed date}}} for the queried branches.
    """
    branches = set(branches)
    candidates = sorted(set(known_branches) | branches, key=len, reverse=True)
    branch_groups = {}
    for tag, tag_last_pushed in docker_tag_list:
        match = re.match(r"^(eve-kernel-.*)-([a-f0-9]+)-(gcc|clang)$", tag)
        if not match:
            print(f"Warning: tag '{tag}' doesn't match regex")
            continue
        group, commit, tag_compiler = match.groups()
        branch = next(
            (b for b in candidates if group == b or group.startswith(b + "-")), None
        )
        if branch not in branches or tag_compiler != compiler:
            continue
        groups = branch_groups.setdefault(branch, {})
        groups.setdefault(group, {})[commit] = tag_last_pushed
    return branch_groups


def select_docker_commits(branch_groups):
    """
    Picks for each branch the most recent commit whose image was pushed to every
    group (flavour) of the branch. A commit dates from its earliest push among
    the groups, so rebuilding an old commit does not make it recent.

    Args:
        branch_groups (dict): The result of group_docker_tags().

    Returns:
        dict: {branch: commit}. A branch with no commit common to all its groups
        is left out.
    """
    docker_commits = {}
    for branch, groups in branch_groups.items():
        common = set.intersection(*(set(commits) for commits in groups.values()))
        if common:
            _, docker_commits[branch] = max(
                (min(commits[commit] for commits in groups.values()), commit)
                for commit in common
            )
    return docker_commits


def fetch_docker_tags(branches, known_branches, verbose=False):
    """
    Fetches kernel commits from docker hub and returns them as a dictionary of
    (branch, commit) pairs.

    Args:
        branches (list): Branch names to look up tags for. Each one is queried
        separately so no single listing runs past the anonymous pagination limit.
        known_branches (iterable): Every branch name, to assign tags to the right one.
        verbose (bool): If True, prints all tags with decoded dates and all kernel commits
        from docker hub.

    Returns:
        dict: A dictionary of (branch, commit) pairs.
    """
    branch_groups = group_docker_tags(
        branches, known_branches, _fetch_tags_per_branch(branches, verbose)
    )

    # print all tags with decoded dates
    if verbose:
        print("All tags:")
        for branch, groups in branch_groups.items():
            print(branch)
            for group, commits in groups.items():
                print(f"  {group}")
                for commit, tag_last_pushed in sorted(
                    commits.items(), key=lambda x: x[1], reverse=True
                ):
                    # not really needed, makes sure we can handle the date format
                    date = datetime.datetime.strptime(
                        tag_last_pushed, "%Y-%m-%dT%H:%M:%S.%fZ"
                    )
                    print(f"\t{commit} : {date.isoformat()}")

    docker_commits = select_docker_commits(branch_groups)

    # print all kernel commits from docker hub
    if verbose:
        # sort commits from dockerhub by branch name
        print("Kernel commits from docker hub:")
        for branch in sorted(docker_commits, key=lambda x: x[0]):
            print(f"{branch} : {docker_commits[branch]}")

    return docker_commits


if PYTEST_AVAILABLE:

    def test_docker_commits_cover_every_flavour():
        """
        Flavoured tags map to their branch and the newest commit pushed for
        every flavour wins; one missing in a flavour is not chosen, and a
        rebuild of an old commit does not make it the newest.
        """
        branch = "eve-kernel-amd64-v6.18.55-generic"
        flavours = ["", "ai-", "core-", "hwe-", "rt-"]
        tags = [
            (f"{branch}-{flavour}{commit}-gcc", pushed)
            for commit, pushed in [
                ("111111111111", "2026-01-01T00:00:00.000000Z"),
                ("222222222222", "2026-02-01T00:00:00.000000Z"),
            ]
            for flavour in flavours
        ] + [
            (f"{branch}-{flavour}333333333333-gcc", "2026-03-01T00:00:00.000000Z")
            for flavour in flavours
            if flavour != "rt-"
        ]

        branch_groups = group_docker_tags([branch], [branch], tags)
        assert sorted(branch_groups[branch]) == [
            branch + suffix for suffix in ["", "-ai", "-core", "-hwe", "-rt"]
        ]
        assert select_docker_commits(branch_groups) == {branch: "222222222222"}

        rebuilt = f"{branch}-core-111111111111-gcc"
        tags = [
            (tag, "2026-04-01T00:00:00.000000Z" if tag == rebuilt else pushed)
            for tag, pushed in tags
        ]
        branch_groups = group_docker_tags([branch], [branch], tags)
        assert select_docker_commits(branch_groups) == {branch: "222222222222"}

    def test_docker_commits_plain_branch():
        """
        A branch without config flavours has a single group and its newest gcc
        image wins: clang images do not count, and the tags of a longer branch
        that the name query also returns stay with that branch.
        """
        nvidia = "eve-kernel-arm64-v5.10.192-nvidia"
        jp5 = nvidia + "-jp5"
        tags = [
            (f"{nvidia}-444444444444-gcc", "2026-01-01T00:00:00.000000Z"),
            (f"{nvidia}-555555555555-gcc", "2026-02-01T00:00:00.000000Z"),
            (f"{nvidia}-666666666666-clang", "2026-03-01T00:00:00.000000Z"),
            (f"{jp5}-777777777777-gcc", "2026-04-01T00:00:00.000000Z"),
        ]

        branch_groups = group_docker_tags([nvidia], [nvidia, jp5], tags)
        assert branch_groups == {
            nvidia: {
                nvidia: {
                    "444444444444": "2026-01-01T00:00:00.000000Z",
                    "555555555555": "2026-02-01T00:00:00.000000Z",
                }
            }
        }
        assert select_docker_commits(branch_groups) == {nvidia: "555555555555"}


def print_user_tips():
    """
    Prints user tips for committing kernel updates.

    The function prints instructions for reviewing and committing kernel updates.
    """
    print("Commit message generated and saved to kernel-update-commit-message.txt")
    print("Please review the commit message and make any necessary changes.")
    print("Once you are satisfied with the commit message, run the following command:")
    print("  git add kernel-commits.mk")
    print("  git commit -s --file kernel-update-commit-message.txt")


# Define the path to the configuration file
config_file_path = os.path.expanduser("~/.config/eve-ci/gh.json")


# Function to read the GitHub token from the config file
def read_github_token_from_config():
    """
    Reads the GitHub token from the config file.

    Returns:
        str: The GitHub token if it exists in the config file, otherwise None.
    """
    if os.path.exists(config_file_path):
        with open(config_file_path, "r", encoding="utf-8") as config_file:
            config_data = json.load(config_file)
            return config_data.get("gh-token")
    return None


# Function to write the GitHub token to the config file
def write_github_token_to_config(token):
    """
    Writes a GitHub token to the configuration file at `config_file_path`.

    Args:
        token (str): The GitHub token to write to the configuration file.
    """
    os.makedirs(os.path.dirname(config_file_path), exist_ok=True)
    with open(config_file_path, "w", encoding="utf-8") as config_file:
        json.dump({"gh-token": token}, config_file)


# Function to interactively prompt the user for a GitHub token
def get_github_token_from_user():
    """
    Prompts the user to enter their GitHub personal access token.

    Returns:
    str: The user's GitHub personal access token.
    """
    return input("Enter your GitHub personal access token: ")


def get_github_token(token):
    """
    Get the GitHub personal access token.

    If the token is provided, it is written to the configuration file and returned.
    If the token is not provided, it is read from the configuration file and returned.
    If the token is not found in the configuration file, it is obtained from the user
    and written to the configuration file.

    Args:
        token (str): The GitHub personal access token.

    Returns:
        str: The GitHub personal access token.
    """
    if token:
        github_token = token
        write_github_token_to_config(github_token)
    else:
        github_token = read_github_token_from_config()

    if not github_token:
        print("GitHub personal access token is required.")
        github_token = get_github_token_from_user()
        write_github_token_to_config(github_token)

    return github_token


def parse_cmd_args():
    """
    Parse command line arguments for updating kernel-commits.mk with latest.

    Args:
        None

    Returns:
        args: An argparse.Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Update kernel-commits.mk with latest")
    parser.add_argument(
        "-t", "--token", help="GitHub personal access token", required=False
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose output",
        action="store_true",
        required=False,
    )
    args = parser.parse_args()
    return args


def adjust_branches_by_docker_tags(
    new_commits, updated_branches, docker_tags, pinned_branches
):
    """
    Adjusts the branches by comparing the commits from GitHub and Docker Hub.

    Args:
        new_commits (dict): A dictionary containing the new commits.
        updated_branches (dict): A dictionary containing the updated branches.
        docker_tags (dict): A dictionary containing the Docker tags.
        pinned_branches (iterable): The branches in kernel-commits.mk.

    Returns:
        bool: A boolean value indicating whether an error occurred.
    """
    is_error = False
    for branch, (current_gh_commit, latest_gh_commit) in list(updated_branches.items()):
        if current_gh_commit is None and latest_gh_commit is None:
            # branch was removed. Print nice info message
            print(
                Fore.YELLOW
                + "[warning]"
                + Style.RESET_ALL
                + f" :{branch}: the branch was removed from the repository or protected."
            )
            continue

        docker_commit = docker_tags.get(branch)
        if docker_commit is None and branch in pinned_branches:
            # dropping the pin would break the build
            is_error = True
            print(
                Fore.RED
                + "[Error]"
                + Style.RESET_ALL
                + f" :{branch}: no commit has an image on docker hub for every flavour.\n"
                + "\tKeeping the pinned commit: "
                + Fore.GREEN
                + f"{current_gh_commit}"
            )
            del updated_branches[branch]
            new_commits[branch] = current_gh_commit
            continue
        if docker_commit is None:
            print(
                Fore.YELLOW
                + "[ WARN ]"
                + Style.RESET_ALL
                + f" :{branch}: the image for commit {latest_gh_commit} was not pushed to "
                + "docker.\n\tNo docker tag found for the branch. Is this a new branch?"
            )
            print(
                f"Deleting the branch from updated branches. "
                f"{branch} will not be updated."
            )
            del updated_branches[branch]
            del new_commits[branch]
            continue

        # if a commit from docker doesn't match commit from github
        # it means the image was not pushed so we cannot use commit from github
        # and we fallback to the commit from docker hub
        if docker_commit != latest_gh_commit:
            is_error = True
            msg = (
                " :"
                + Fore.LIGHTYELLOW_EX
                + Style.BRIGHT
                + f"{branch}"
                + Style.RESET_ALL
                + ": the image for commit "
                + Fore.RED
                + f"{latest_gh_commit}"
                + Style.RESET_ALL
                + " was not pushed to docker.\n"
                "\tUsing the latest commit from docker hub: "
                + Fore.GREEN
                + f"{docker_commit}"
            )

            print(Fore.RED + "[Error]" + Style.RESET_ALL + msg)
            # no update to the branch
            if current_gh_commit == docker_commit:
                del updated_branches[branch]
            else:
                # adjust commit to the latest available on docker hub
                updated_branches[branch] = (current_gh_commit, docker_commit)

        # always update to our source of truth
        new_commits[branch] = docker_commit

    return is_error


if PYTEST_AVAILABLE:

    def test_adjust_branches_by_docker_tags_checks_every_branch():
        """
        Every updated branch is checked against Docker Hub, not only the first:
        the second one falls back to its Docker commit and the error is reported,
        a new branch without Docker tags is dropped.
        """
        amd64 = "eve-kernel-amd64-v6.18.55-generic"
        arm64 = "eve-kernel-arm64-v6.1.155-generic"
        riscv64 = "eve-kernel-riscv64-v6.1.112-generic"
        new_commits = {amd64: "a2", arm64: "b3", riscv64: "c2"}
        updated_branches = {
            amd64: ("a1", "a2"),
            arm64: ("b1", "b3"),
            riscv64: ("v6.1.112", "c2"),
        }
        docker_tags = {amd64: "a2", arm64: "b2"}

        assert adjust_branches_by_docker_tags(
            new_commits, updated_branches, docker_tags, [amd64, arm64]
        )
        assert updated_branches == {amd64: ("a1", "a2"), arm64: ("b1", "b2")}
        assert new_commits == {amd64: "a2", arm64: "b2"}

    def test_adjust_branches_by_docker_tags_keeps_pins(capsys):
        """
        A pinned branch without a usable Docker commit keeps its pinned commit and
        is an error; a removed branch needs no image.
        """
        jp5 = "eve-kernel-arm64-v5.10.192-nvidia-jp5"
        removed = "eve-kernel-amd64-v6.1.112-generic"
        new_commits = {jp5: "d2"}
        updated_branches = {jp5: ("d1", "d2"), removed: (None, None)}

        assert adjust_branches_by_docker_tags(
            new_commits, updated_branches, {}, [jp5, removed]
        )
        assert updated_branches == {removed: (None, None)}
        assert new_commits == {jp5: "d1"}
        assert "commit None" not in capsys.readouterr().out


def print_commit_errors(errors):
    """
    Print formatted error messages for missing commits.

    Parameters:
    - errors (list): List of tuples containing (branch_name, error_message).
    """
    print(
        Fore.RED
        + Style.BRIGHT
        + "\n[Error] The following commits were not found in the repository:\n"
        + Style.RESET_ALL
    )
    for branch, error_msg in errors:
        # Extract just the error message without the "Error: " prefix if present
        clean_msg = error_msg.replace("Error: ", "")
        print(
            "  "
            + Fore.RED
            + Style.BRIGHT
            + "ERROR: "
            + Style.RESET_ALL
            + Style.BRIGHT
            + Fore.WHITE
            + branch
            + Style.RESET_ALL
            + ": "
            + clean_msg
        )
    print(
        Fore.RED
        + Style.BRIGHT
        + "\nPlease push the missing tags/commits to the repository and rerun the script."
    )


def print_updated_branches(updated_branches):
    """
    Print the list of updated branches with color formatting.

    Parameters:
    - updated_branches (dict): Dictionary of branch names and their commits.
    """
    print("Updated branches:")
    for branch, commits in updated_branches.items():
        if commits[0] is None and commits[1] is None:
            print(
                Fore.YELLOW
                + Style.BRIGHT
                + "  REMOVED: "
                + Style.RESET_ALL
                + Style.BRIGHT
                + f"{branch}"
            )
        else:
            print(
                Fore.GREEN
                + Style.BRIGHT
                + "  UPDATED: "
                + Style.RESET_ALL
                + Style.BRIGHT
                + f"{branch}"
                + Style.RESET_ALL
                + f" {commits[0]} -> {commits[1]}"
            )


def main():
    """
    The main function that orchestrates the generation of a commit message for kernel updates.
    """
    # init colorama
    init(autoreset=True)

    kernel_commits_mk_file = "kernel-commits.mk"
    gh_user = "lf-edge"

    # parse command line arguments. Only token is supported for now
    args = parse_cmd_args()
    new_commits = fetch_latest_commits_from_github(
        gh_user, get_github_token(args.token), args.verbose
    )
    old_commits = parse_kernel_commits_file(kernel_commits_mk_file)
    updated_branches = find_updated_branches(
        old_commits, new_commits, get_github_token(args.token), args.verbose
    )

    if not updated_branches:
        print("No kernel updates available.")
        return

    print_updated_branches(updated_branches)

    # fetch tags from docker hub and convert them to branch names
    docker_tags = fetch_docker_tags(
        list(new_commits), set(new_commits) | set(old_commits), args.verbose
    )
    if adjust_branches_by_docker_tags(
        new_commits, updated_branches, docker_tags, old_commits
    ):
        print(
            Fore.RED
            + "[Error]"
            + Style.RESET_ALL
            + ": Please fix the issues and rerun the script."
        )
        return

    if not updated_branches:
        print(
            Fore.YELLOW
            + "[warning]"
            + Style.RESET_ALL
            + ":No possible kernel updates available on docker hub,"
            + " but github has more recent commits."
        )
        return

    commit_message, errors = generate_commit_message(
        updated_branches, gh_user, "eve-kernel", get_github_token(args.token)
    )

    if errors:
        print_commit_errors(errors)
        sys.exit(1)

    # dump updated commits to kernel-commits.mk
    with open(kernel_commits_mk_file, "w", encoding="utf-8") as new_file:
        for branch, commit in new_commits.items():
            new_file.write(branch_commit_to_variable(branch, commit))

    with open("kernel-update-commit-message.txt", "w", encoding="utf-8") as commit_file:
        commit_file.write(commit_message)

    print_user_tips()


if __name__ == "__main__":
    main()
