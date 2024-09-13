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
        return False, f"Commit {commit.hexsha} has no body."

    return True, None

def check_branch_rebased(repo, base_hash):
    """
    Check if the current branch is rebased on top of base_hash.
    """
    try:
        # Get the current commit (HEAD)
        head_commit = repo.head.commit
        # Get the base commit
        base_commit = repo.commit(base_hash)
        # Find the merge base between HEAD and base_commit
        merge_base = repo.merge_base(head_commit, base_commit)
        if not merge_base:
            print(f"Cannot find a common ancestor between HEAD and {base_hash}.")
            return False
        # Check if the base_commit is an ancestor of HEAD
        if merge_base[0] != base_commit:
            return False
        return True
    except git.BadName:
        print(f"The base hash {base_hash} is invalid.")
        return False

def main():
    """
    Main function to check the commit messages in the current branch.
    """
    repo = git.Repo(search_parent_directories=True)

    # Base hash should be provided as an argument
    base_hash = sys.argv[1]

    rebased = check_branch_rebased(repo, base_hash)

    if not rebased:
        print("Current branch is not rebased on top of the base branch!")
        print("Please rebase the branch!")
        print("The check will be performed on an incorrect set of commits.")

    commits = list(repo.iter_commits(f'{base_hash}..HEAD'))

    if not commits:
        print(f"No commits between {base_hash} and HEAD.")
        sys.exit(1)

    print(f"Checking {len(commits)} commits between {base_hash} and HEAD...")

    all_valid = True
    for commit in commits:
        valid, error_message = check_commit_message(commit)
        if not valid:
            print(error_message)
            print(f"Commit message:\n{'-'*72}\n{commit.message}{'-'*72}")
            print("For more details, see: "
            "https://github.com/lf-edge/eve/blob/master/CONTRIBUTING.md#commit-messages")
            all_valid = False

    if not all_valid:
        if not rebased:
            print("The error(s) above might be due to the branch not being rebased.")
            print("Please rebase the branch!")
        sys.exit(1)

    print("All commits are valid.")

if __name__ == "__main__":
    main()
