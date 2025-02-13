#!/usr/bin/env python3
"""
Copyright (c) 2023 Zededa, Inc.
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

def get_short_arch_flavor(branch_name):
    """
    Get a short representation of the architecture and flavor from the branch name.

    Parameters:
    - branch_name (str): The name of the branch from which to extract architecture and flavor.

    Returns:
    - str: A short representation of the architecture and flavor.
    """
    _, _, arch, _, flavor = branch_name.split("-", 4)
    return f"{arch}-{flavor}"


def fetch_latest_commits_from_github(user_token):
    """
    Generate the kernel-commits.mk-new file with commit information from GitHub branches.

    This function retrieves branch information from a GitHub repository and
    returns the commit hashes for each branch in a set.
    """
    repo_url = "https://api.github.com/repos/lf-edge/eve-kernel/branches?per_page=100"
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

            if "next" in response.links:
                repo_url = response.links["next"]["url"]
            else:
                break
        else:
            print("Error:", response.status_code, response.text)
            break
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
    return branch_name.startswith("eve-kernel-") and "-" in branch_name


def variable_to_branch_name(variable_name):
    """
    Convert a variable name to the branch name format.

    Parameters:
    - variable_name (str): The variable name to convert.

    Returns:
    - str: The branch name in the expected format.
    """
    branch_name = variable_name.replace("KERNEL_COMMIT_", "").replace("_", "-")
    return f"eve-kernel-{branch_name}"


def branch_commit_to_variable(branch_name, commit):
    """
    Convert a branch name and commit hash to a variable name.

    Parameters:
    - branch_name (str): The name of the branch.
    - commit (str): The commit hash.

    Returns:
    - str: The variable name in the expected format.
    """
    branch_match = re.match(r"(?P<branch>.*v\d+\.\d+(?:\.\d+)?)-(?P<platform>.*)", branch_name)

    if not branch_match:
        sys.exit(f"Error: Invalid branch name format: {branch_name}")

    branch_name = branch_match.group("branch").replace("eve-kernel-", "KERNEL_COMMIT_") \
        .replace("-", "_")
    variable_name = branch_name + "_" + branch_match.group("platform")
    return f"{variable_name} = {commit}\n"

if PYTEST_AVAILABLE:
    def test_branch_commit_to_variable():
        """
        Test the branch_commit_to_variable function with valid branch names.
        """

        assert branch_commit_to_variable("eve-kernel-amd64-v5.10.186-generic", "abcd") \
            == "KERNEL_COMMIT_amd64_v5.10.186_generic = abcd\n"
        assert branch_commit_to_variable("eve-kernel-amd64-v5.10-generic", "abcd") \
            == "KERNEL_COMMIT_amd64_v5.10_generic = abcd\n"
        assert branch_commit_to_variable("eve-kernel-arm64-v5.10.192-nvidia-jp5", "abcd") \
            == "KERNEL_COMMIT_arm64_v5.10.192_nvidia-jp5 = abcd\n"
        assert branch_commit_to_variable("eve-kernel-arm64-v5.10-nvidia-jp5", "abcd") \
            == "KERNEL_COMMIT_arm64_v5.10_nvidia-jp5 = abcd\n"

    def test_branch_commit_to_variable_exit():
        """
        Test the branch_commit_to_variable function on incorrect br.
        """
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            branch_commit_to_variable("eve-kernel-arm64-v5-nvidia-jp5", "abcd")
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == \
            "Error: Invalid branch name format: eve-kernel-arm64-v5-nvidia-jp5"


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


def github_fetch_commit_range(repo_owner, repo_name, old_commit, new_commit, verbose=False):
    """
    Fetch commit subjects and their corresponding commit hashes
    between old and new commits for a branch.

    Parameters:
    - repo_owner (str): The owner of the GitHub repository.
    - repo_name (str): The name of the GitHub repository.
    - old_commit (str): The old commit hash.
    - new_commit (str): The new commit hash.

    Returns:
    - list: A list of tuples containing commit hashes and their subjects.
    - None: If the retrieval of commit information fails.
    """
    api_url = (
        "https://api.github.com/"
        f"repos/{repo_owner}/{repo_name}/compare/{old_commit}...{new_commit}"
    )
    headers = {
        "Accept": "application/vnd.github.v3+json",
    }

    if verbose:
        print(f"Fetching commit subjects for {old_commit}..{new_commit}...")
        print(f"API URL: {api_url}")

    response = requests.get(api_url, headers=headers, timeout=30)
    if response.status_code == 200:
        comparison = response.json()
        commit_info = []

        for commit in comparison.get("commits", []):
            commit_subject = commit.get("commit", {}).get("message", "").split("\n")[0]
            commit_hash = commit.get("sha")
            commit_info.append((commit_hash[:12], commit_subject))

        return commit_info

    return None


def generate_commit_message(branches, repo_owner, repo_name, verbose=False):
    """
    Generate a commit message with commit subjects
    and corresponding commit hashes between old and new commits.

    Parameters:
    - old_commits (dict): A dictionary of branch names and old commit hashes.
    - new_commits (dict): A dictionary of branch names and new commit hashes.

    Returns:
    - str: A commit message containing commit information for updated branches.
    """
    commit_message = ""

    for branch in branches:
        old_commit, new_commit = branches[branch]
        commit_message += f"{branch}\n"
        # Fetch a limited number of commit subjects and their corresponding
        # commit hashes between old and new commits for the branch
        commit_infos = github_fetch_commit_range(
            repo_owner,
            repo_name,
            old_commit,
            new_commit,
            verbose=verbose,
        )
        if commit_infos:
            for commit_hash, commit_subject in reversed(commit_infos):
                commit_message += f"    {commit_hash}: {commit_subject}\n"
        else:
            commit_message += "    Unable to fetch commit subjects\n"
        commit_message += "\n"

    arch_list = f"[{', '.join(get_short_arch_flavor(branch) for branch in branches)}]"
    commit_subject = f"Kernel update - {arch_list}\n\nThis commit changes:\n"

    commit_message = commit_subject + commit_message
    return commit_message


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


def find_updated_branches(old_commits, new_commits):
    """
    Find the branches that have been updated.

    Parameters:
    - old_commits (dict): A dictionary of branch names and old commit hashes.
    - new_commits (dict): A dictionary of branch names and new commit hashes.

    Returns:
    - list: A list of branch names that have been updated or added.
    """
    branches_updated = {}

    for branch, new_commit in new_commits.items():
        if branch in old_commits:
            old_commit = old_commits[branch]
            if old_commit != new_commit:
                branches_updated[branch] = (old_commit, new_commit)
        else:
            # get tag from branch name
            _, _, _, tag, _ = branch.split("-", 4)
            new_commit = new_commits[branch]
            branches_updated[branch] = (tag, new_commit)

    return branches_updated


def get_kernel_tags_from_dockerhub(username, repository, search_pattern: str="", verbose=False):
    """
    Retrieves Docker tags from Docker Hub for a given repository.

    Args:
        username (str): The Docker Hub username.
        repository (str): The name of the Docker repository.
        search_pattern (str, optional): A regular expression pattern to filter Docker tags.
        Defaults to None.
        verbose (bool, optional): Increase output verbosity if True. Defaults to False.

    Returns:
        list: A list of tuples containing Docker tags and their last push dates.
    """
    tags = []
    tags_url = (
        f"https://hub.docker.com/v2/repositories/{username}/{repository}/tags/?page_size=1000"
    )

    total_tags_fetched = 0
    regex_pattern = None

    # convert search patterns to gerexp
    if search_pattern != "":
        regex_pattern = pattern_to_regex(search_pattern)

    while True:
        response = requests.get(tags_url, timeout=30)

        if response.status_code == 200:
            tags_json = response.json()
            count = tags_json["count"]
            # pretty print tags_json
            if verbose:
                print(json.dumps(tags_json, indent=4, sort_keys=True))

            raw_results = tags_json["results"]
            total_tags_fetched += len(raw_results)

            for tag in raw_results:
                if regex_pattern:
                    if re.match(regex_pattern, tag["name"]):
                        tags.append((tag["name"], tag["tag_last_pushed"]))
                else:
                    tags.append((tag["name"], tag["tag_last_pushed"]))

            # print progress overwrite the same line
            print(f"Fetching docker tags: {total_tags_fetched} / {count}", end="\r")

            if tags_json["next"]:
                tags_url = tags_json["next"]
                if verbose:
                    print(tags_url)
            else:
                # to keep progress on the screen
                print(f"Fetching docker tags: {total_tags_fetched} / {count}")
                break
        else:
            print("Error:", response.status_code, response.text)
            break
    return tags


def fetch_docker_tags(verbose=False):
    """
    Fetches kernel commits from docker hub and returns them as a dictionary of
    (branch, commit) pairs.

    Args:
        verbose (bool): If True, prints all tags with decoded dates and all kernel commits
        from docker hub.

    Returns:
        dict: A dictionary of (branch, commit) pairs.
    """
    docker_username = "lfedge"
    repository = "eve-kernel"
    branch_search_pattern = "eve-kernel-*"
    docker_tag_list = get_kernel_tags_from_dockerhub(
        docker_username, repository, branch_search_pattern
    )

    # group tags by common capture group e.g. amd64-v6.1.38-generic
    tag_groups = {}
    for tag, tag_last_pushed in docker_tag_list:
        match = re.match(r"^(eve-kernel-.*)-[a-f0-9]+-gcc|clang$", tag)
        if match:
            branch_name = match.group(1)
            if branch_name not in tag_groups:
                tag_groups[branch_name] = []
            tag_groups[branch_name].append((tag, tag_last_pushed))
        else:
            print(f"Warning: tag '{tag}' doesn't match regex")

    # sort each group by date in descending order
    # so the first tag in each group is the most recent one
    for branch, docker_tag_list in tag_groups.items():
        docker_tag_list.sort(key=lambda x: x[1], reverse=True)
        tag_groups[branch] = docker_tag_list

    # print all tags with decoded dates
    if verbose:
        print("All tags:")
        for branch, docker_tag_list in tag_groups.items():
            print(branch)
            for tag, tag_last_pushed in docker_tag_list:
                # decode date from tag. Not really needed. To make sure we can handle date format
                date = datetime.datetime.strptime(tag_last_pushed, "%Y-%m-%dT%H:%M:%S.%fZ")
                print(f"\t{tag} : {date.isoformat()}")

    # and collect (branch, commit) pairs by splitting tag name by '-'
    # and taking second last element as commit
    docker_commits = {}
    for branch, docker_tag_list in tag_groups.items():
        # take first tag from each group. The is the most recent one
        latest_tag = docker_tag_list[0][0]
        commit = latest_tag.split("-")[-2]
        docker_commits[branch] = commit

    # print all kernel commits from docker hub
    if verbose:
        # sort commits from dockerhub by branch name
        print("Kernel commits from docker hub:")
        for branch in sorted(docker_commits, key=lambda x: x[0]):
            print(f"{branch} : {docker_commits[branch]}")

    return docker_commits


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
    parser.add_argument("-t", "--token", help="GitHub personal access token", required=False)
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose output",
        action="store_true",
        required=False,
    )
    args = parser.parse_args()
    return args


def adjust_branches_by_docker_tags(new_commits, updated_branches, docker_tags):
    """
    Adjusts the branches by comparing the commits from GitHub and Docker Hub.

    Args:
        new_commits (dict): A dictionary containing the new commits.
        updated_branches (dict): A dictionary containing the updated branches.
        docker_tags (dict): A dictionary containing the Docker tags.

    Returns:
        bool: A boolean value indicating whether an error occurred.
    """
    for branch, docker_commit in docker_tags.items():
        is_error = False
        # only for updated branches
        if branch not in updated_branches:
            continue
        # if a commit from docker doesn't match commit from github
        # it means the image was not pushed so we cannot use commit from github
        # and we fallback to the commit from docker hub
        current_gh_commit, latest_gh_commit = updated_branches[branch]

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
                "\tUsing the latest commit from docker hub: " + Fore.GREEN + f"{docker_commit}"
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

        # if we have updated branches check that we have any docker tag for them
        # it means that the branch is just added
        saved_updated_branches = updated_branches.copy()
        for branch in updated_branches:
            if branch not in docker_tags:
                is_error = True
                print(
                    Fore.RED
                    + "[Error]"
                    + Style.RESET_ALL
                    + f" :{branch}: the image for commit {new_commits[branch]}"
                    + "was not pushed to docker.\n\tNo docker tag found for the branch."
                    " Is this a new branch?"
                )
                del saved_updated_branches[branch]
        updated_branches = saved_updated_branches
        return is_error


def main():
    """
    The main function that orchestrates the generation of a commit message for kernel updates.
    """
    # init colorama
    init(autoreset=True)

    kernel_commits_mk_file = "kernel-commits.mk"

    # parse command line arguments. Only token is supported for now
    args = parse_cmd_args()
    github_user_token = get_github_token(args.token)

    new_commits = fetch_latest_commits_from_github(github_user_token)
    old_commits = parse_kernel_commits_file(kernel_commits_mk_file)
    # updated on github
    updated_branches = find_updated_branches(old_commits, new_commits)

    if not updated_branches:
        print("No kernel updates available.")
        return

    # fetch tags from docker hub and convert them to branch names
    docker_tags = fetch_docker_tags(verbose=args.verbose)

    is_error = adjust_branches_by_docker_tags(new_commits, updated_branches, docker_tags)

    if is_error:
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

    commit_message = generate_commit_message(updated_branches, "lf-edge", "eve-kernel")

    # dump updated commits to kernel-commits.mk
    with open(kernel_commits_mk_file, "w", encoding="utf-8") as new_file:
        for branch, commit in new_commits.items():
            new_file.write(branch_commit_to_variable(branch, commit))

    with open("kernel-update-commit-message.txt", "w", encoding="utf-8") as commit_file:
        commit_file.write(commit_message)

    print_user_tips()


if __name__ == "__main__":
    main()
