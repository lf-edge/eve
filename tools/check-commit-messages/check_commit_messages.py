"""
Copyright (c) 2024, Zededa Inc.
SPDX-License-Identifier: Apache-2.0

This script checks the commit messages in the current branch to ensure they follow the
recommended format. The recommended format is as follows:
* Commit message should have a subject and body
* An empty line should separate the subject and body
* Body should start with a capital letter
* The body should not be empty (it should contain more than just "Signed-off-by")
"""

import sys

import git

def check_commit_message(commit):
    """
    Check if a commit message follows the recommended format.
    """
    message_lines = commit.message.strip().splitlines()

    if len(message_lines) < 2:
        return False, f"Commit {commit.hexsha} has no body."

    subject = message_lines[0].strip()
    second_line = message_lines[1].strip()

    if not subject:
        return False, f"Commit {commit.hexsha} has no subject."

    # Check if the second line is empty (indicating a blank line between subject and body)
    if second_line:
        return False, f"Commit {commit.hexsha} does not have an empty line after the subject."

    # Remove the subject and empty line to get the body
    body_lines = [line.strip() for line in message_lines[2:] if line.strip()]

    # Remove lines that are just "Signed-off-by"
    body_lines = [line for line in body_lines if not line.lower().startswith("signed-off-by")]

    if not body_lines:
        return False, f"Commit {commit.hexsha} has a body but only contains Signed-off-by."

    # Check if the body starts with a capital letter
    if not body_lines[0][0].isupper():
        return False, f"Body of commit {commit.hexsha} does not start with a capital letter."

    return True, None


def main():
    """
    Main function to check the commit messages in the current branch.
    """
    repo = git.Repo(search_parent_directories=True)

    # Base hash should be provided as an argument
    base_hash = sys.argv[1]

    commits = list(repo.iter_commits(f'{base_hash}..HEAD'))

    if not commits:
        print(f"No commits between {base_hash} and HEAD.")
        sys.exit(1)

    print(f"Checking {len(commits)} commits between {base_hash} and HEAD...")

    for commit in commits:
        valid, error_message = check_commit_message(commit)
        if not valid:
            print(error_message)
            sys.exit(1)

    print("All commits are valid.")

if __name__ == "__main__":
    main()
