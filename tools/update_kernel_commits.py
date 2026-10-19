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
Only the branches kernel-version.mk selects for some ZARCH, PLATFORM and HV, plus the
next branches already pinned, are written.

Note:
- This module depends on the 'requests' library for making HTTP requests to the GitHub API.
- It reads kernel-version.mk with the 'tree-sitter' and 'tree-sitter-make' libraries.
- Make sure to review the generated commit message before committing the changes to your repository.

Author: Mikhail Malyshev <mike.malyshev@gmail.com>
"""

import argparse
import datetime
import json
import os
import re
import sys
from typing import NamedTuple
import requests
from colorama import Fore, Style, init  # pylint: disable=import-error

# do not force users to have pytest installed
try:
    import pytest

    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

# main() requires tree-sitter, the module and its other tests do not
try:
    import tree_sitter_make  # pylint: disable=import-error
    from tree_sitter import Language, Parser  # pylint: disable=import-error

    # tree-sitter before 0.23 rejects the language object of tree-sitter-make
    MAKE_LANGUAGE = Language(tree_sitter_make.language())
    TREE_SITTER_AVAILABLE = True
except (ImportError, TypeError):
    TREE_SITTER_AVAILABLE = False


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


class KernelVersionScanError(Exception):
    """Exception raised when a makefile cannot be evaluated without running make."""


class _InvalidCombination(Exception):
    """Raised when kernel-version.mk calls $(error) for a ZARCH, PLATFORM and HV combination."""


_SCAN_INPUTS = ("ZARCH", "PLATFORM", "HV")


class ParsedMakefile:
    """A makefile parsed with tree-sitter-make, to read assignments without running make."""

    def __init__(self, source, path):
        self._path = path
        self._src = source.encode("utf-8")
        self._root = Parser(MAKE_LANGUAGE).parse(self._src).root_node

    def text(self, node):
        """The source text of a node."""
        return self._src[node.start_byte : node.end_byte].decode("utf-8")

    def unsupported(self, node, reason="unsupported make construct"):
        """A KernelVersionScanError naming the node's construct and line."""
        snippet = (self.text(node).strip().splitlines() or [""])[0]
        return KernelVersionScanError(
            f"{self._path}:{node.start_point[0] + 1}: {reason} ({node.type}): {snippet}"
        )

    def single_assignment(self, name):
        """The only assignment of name in the file, which must be unconditional."""
        found = [
            node
            for node in self._assignments([self._root])
            if self._name(node).rstrip("+?:!") == name
        ]
        if len(found) != 1:
            raise KernelVersionScanError(
                f"{self._path}: expected one {name} assignment, found {len(found)}"
            )
        if (
            found[0].parent.type != "makefile"
            or found[0].has_error
            or self._name(found[0]) != name
        ):
            raise self.unsupported(
                found[0], f"{name} must be an unconditional top-level assignment"
            )
        return found[0]

    def literal_words(self, name):
        """The words of the only assignment of name, whose value must be literal."""
        value = self.single_assignment(name).child_by_field_name("value")
        if value is None:
            return []
        if value.named_children:
            raise self.unsupported(value, f"{name} must be a literal list")
        return self._literal(value, self.text(value)).split()

    def _name(self, assignment):
        return self.text(assignment.child_by_field_name("name"))

    def _descendants(self, nodes):
        for node in nodes:
            yield node
            yield from self._descendants(node.named_children)

    def _assignments(self, nodes):
        return (n for n in self._descendants(nodes) if n.type == "variable_assignment")

    def _literal(self, node, text):
        # tree-sitter-make keeps both in the value, make does not
        if "#" in text or "\\\n" in text:
            raise self.unsupported(node, "comment or line continuation in a value")
        return text


def read_hv_supported(source, path="Makefile"):
    """
    Returns the HV values of the top-level Makefile's HV_SUPPORTED.

    Parameters:
    - source (str): The content of the top-level Makefile.
    - path (str): The file name used in error messages.
    """
    return ParsedMakefile(source, path).literal_words("HV_SUPPORTED")


class KernelVersionScanner(ParsedMakefile):
    """
    Evaluates the kernel selection of kernel-version.mk for ZARCH, PLATFORM and HV
    combinations without running make.

    The statements before 'include kernel-commits.mk' are evaluated. Supported are
    the constructs the file uses there, = and ?= assignments, ifeq/ifneq in the
    (a, b) form with else ifeq/ifneq chains and else, variable references with
    computed names, and the findstring, filter and error functions, plus :=.
    Anything else, and what tree-sitter-make misreads, raises
    KernelVersionScanError, so a new construct is never guessed at.
    """

    def __init__(self, source, path="kernel-version.mk"):
        super().__init__(source, path)
        if self._root.has_error:
            raise KernelVersionScanError(
                f"{path}:{self._error_line(self._root)}: make syntax error"
            )
        statements = self._root.named_children
        include = next(
            (
                index
                for index, statement in enumerate(statements)
                if statement.type == "include_directive"
                and statement.children[0].type == "include"
                and self.text(statement.child_by_field_name("filenames"))
                == "kernel-commits.mk"
            ),
            None,
        )
        if include is None:
            raise KernelVersionScanError(f"{path}: no 'include kernel-commits.mk'")
        for assignment in self._assignments(statements):
            if self._name(assignment)[-1] in "+?:!":
                raise self.unsupported(
                    assignment, "write a blank between the name and the operator"
                )
        self._selection = statements[:include]
        self._commit_name = self._kernel_commit_name()
        # the assigned names, each mapped to its assignment after the include if
        # any, as make expands the name with that later value
        self._assigned = {
            name: None for name in map(self._name, self._assignments(self._selection))
        }
        self._assigned.update(
            (self._name(a), a) for a in self._assignments(statements[include + 1 :])
        )
        self._vars = {}

    def combinations(self, hypervisors):
        """Yields every (ZARCH, PLATFORM, HV) from ARCHS, PLATFORMS_<arch> and hypervisors."""
        for zarch in self.literal_words("ARCHS"):
            for platform in self.literal_words(f"PLATFORMS_{zarch}"):
                for hv in hypervisors:  # pylint: disable=invalid-name
                    yield zarch, platform, hv

    def select(self, zarch, platform, hv):  # pylint: disable=invalid-name
        """
        Returns (KERNEL_COMMIT_* variable name, KERNEL_CONFIG_FLAVOR, KERNEL_COMPILER)
        for the combination, or None if it is invalid: it calls $(error) or leaves
        a variable of the KERNEL_COMMIT name empty.
        """
        self._vars = dict(zip(_SCAN_INPUTS, (zarch, platform, hv)))
        try:
            for statement in self._selection:
                self._run(statement)
            if not all(self._value(name) for name in self._required_names()):
                return None
            return (
                self._expand([self._commit_name]),
                # main() mirrors what the file does with it after the include
                self._raw_value("KERNEL_CONFIG_FLAVOR"),
                self._value("KERNEL_COMPILER"),
            )
        except _InvalidCombination:
            return None

    def _error_line(self, node):
        if node.is_error or node.is_missing:
            return node.start_point[0] + 1
        return next(
            (self._error_line(c) for c in node.children if c.has_error),
            node.start_point[0] + 1,
        )

    def _kernel_commit_name(self):
        assignment = self.single_assignment("KERNEL_COMMIT")
        value = assignment.child_by_field_name("value")
        references = value.named_children if value else []
        if (
            len(references) != 1
            or references[0].type != "variable_reference"
            or self.text(references[0]) != self.text(value)
        ):
            raise self.unsupported(
                assignment, "KERNEL_COMMIT must be a single variable reference"
            )
        return self._reference_name(references[0])

    def _required_names(self):
        """The variables the KERNEL_COMMIT name is built from."""
        return [
            self.text(node.named_children[0])
            for node in self._descendants([self._commit_name])
            if node.type == "variable_reference"
            and node.named_children[0].type == "word"
        ]

    def _reference_name(self, node):
        tokens = [child.type for child in node.children[:2]]
        names = node.named_children
        if (
            tokens not in (["$", "("], ["$", "{"])
            or len(names) != 1
            or names[0].type not in ("word", "concatenation")
        ):
            raise self.unsupported(node)
        return names[0]

    def _run(self, node):
        if node.type == "comment":
            return
        if node.type == "variable_assignment":
            self._assign(node)
        elif node.type == "conditional":
            self._run_conditional(node)
        elif node.type == "function_call" and self._function(node) == "error":
            raise _InvalidCombination()
        else:
            raise self.unsupported(node)

    def _run_conditional(self, node):
        branches = [node] + [
            c
            for c in node.named_children
            if c.type in ("elsif_directive", "else_directive")
        ]
        for branch in branches:
            condition = branch.child_by_field_name("condition")
            if condition is None or self._holds(condition):
                for index, child in enumerate(branch.children):
                    if (
                        child.is_named
                        and branch.field_name_for_child(index) != "condition"
                        and child.type not in ("elsif_directive", "else_directive")
                    ):
                        self._run(child)
                return

    def _holds(self, node):
        if node.type not in ("ifeq_directive", "ifneq_directive"):
            raise self.unsupported(node)
        parens = [child for child in node.children if child.type in ("(", ")")]
        if not parens:
            raise self.unsupported(node, "only the ifeq (a, b) form is supported")
        after_open = self._src[parens[0].end_byte : parens[0].end_byte + 1]
        before_close = self._src[parens[-1].start_byte - 1 : parens[-1].start_byte]
        if after_open.isspace() or before_close.isspace():
            raise self.unsupported(
                node, "make keeps a blank after '(' or before ')' in the arguments"
            )
        equal = self._expand(node.children_by_field_name("arg0")) == self._expand(
            node.children_by_field_name("arg1")
        )
        return equal == (node.type == "ifeq_directive")

    def _assign(self, node):
        name = self._name(node)
        if name in _SCAN_INPUTS:
            raise self.unsupported(node, f"{name} is an input of the scan")
        operator = node.child_by_field_name("operator").type
        value = node.child_by_field_name("value")
        nodes = [value] if value is not None else []
        if operator == "=" or (operator == "?=" and name not in self._vars):
            # a recursive variable keeps its nodes and is expanded where it is used
            self._vars[name] = nodes
        elif operator == ":=":
            self._vars[name] = self._expand(nodes)
        elif operator != "?=":
            raise self.unsupported(node, f"unsupported assignment operator {operator}")

    def _value(self, name):
        late = None if name in _SCAN_INPUTS else self._assigned.get(name)
        if late is not None:
            raise self.unsupported(
                late,
                "assigned after 'include kernel-commits.mk', which the selection reads",
            )
        return self._raw_value(name)

    def _raw_value(self, name):
        value = self._vars.get(name, "")
        if isinstance(value, str):
            return value
        if value is None:
            raise KernelVersionScanError(
                f"{self._path}: variable {name} references itself"
            )
        self._vars[name] = None
        try:
            return self._expand(value)
        finally:
            self._vars[name] = value

    def _references(self, nodes):
        for node in nodes:
            if node.type in ("variable_reference", "function_call"):
                yield node
            elif node.type in ("text", "word", "concatenation", "arguments"):
                yield from self._references(node.named_children)
            else:
                raise self.unsupported(node)

    def _pieces(self, nodes):
        """Yields (is_literal, text) for the source spanned by nodes, references expanded."""
        if not nodes:
            return
        position = nodes[0].start_byte
        for reference in self._references(nodes):
            literal = self._src[position : reference.start_byte].decode("utf-8")
            yield True, self._literal(nodes[0], literal)
            yield False, self._expand_reference(reference)
            position = reference.end_byte
        literal = self._src[position : nodes[-1].end_byte].decode("utf-8")
        yield True, self._literal(nodes[0], literal)

    def _expand(self, nodes):
        return "".join(text for _, text in self._pieces(nodes))

    def _function(self, node):
        return node.child_by_field_name("function").type

    def _arguments(self, node):
        arguments = [""]
        for is_literal, text in self._pieces(
            [c for c in node.named_children if c.type == "arguments"]
        ):
            if is_literal:
                first, *rest = text.split(",")
                arguments[-1] += first
                arguments += rest
            else:
                arguments[-1] += text
        return arguments

    def _expand_reference(self, node):
        if node.type == "variable_reference":
            name_node = self._reference_name(node)
            name = self._expand([name_node])
            if (
                name_node.type == "word"
                and name not in _SCAN_INPUTS
                and name not in self._assigned
            ):
                raise self.unsupported(
                    node, f"{name} is neither an input nor assigned before the include"
                )
            return self._value(name)
        function = self._function(node)
        if function == "error":
            raise _InvalidCombination()
        arguments = self._arguments(node)
        if function == "findstring" and len(arguments) == 2:
            find, text = arguments
            return find if find in text else ""
        if function == "filter" and len(arguments) == 2:
            patterns, words = (argument.split() for argument in arguments)
            return " ".join(
                word
                for word in words
                if any(self._filter_matches(pattern, word) for pattern in patterns)
            )
        raise self.unsupported(node)

    @staticmethod
    def _filter_matches(pattern, word):
        prefix, percent, suffix = pattern.partition("%")
        if not percent:
            return pattern == word
        return (
            len(word) >= len(prefix) + len(suffix)
            and word.startswith(prefix)
            and word.endswith(suffix)
        )


def scan_kernel_version_mk(source, hypervisors, path="kernel-version.mk"):
    """
    Evaluates kernel-version.mk for every ZARCH, PLATFORM and HV combination.

    Parameters:
    - source (str): The content of kernel-version.mk.
    - hypervisors (iterable): The HV values to combine (HV_SUPPORTED).
    - path (str): The file name used in error messages.

    Returns:
    - tuple: ({KERNEL_COMMIT_* variable: set of KERNEL_CONFIG_FLAVOR values} for the
      valid combinations, their KERNEL_COMPILER)

    Raises:
    - KernelVersionScanError: When the file uses a construct the scanner does not
      evaluate, or no combination selects a kernel.
    """
    scanner = KernelVersionScanner(source, path)
    config_flavours, compilers = {}, set()
    for combination in scanner.combinations(hypervisors):
        selected = scanner.select(*combination)
        if selected:
            variable, config_flavour, compiler = selected
            config_flavours.setdefault(variable, set()).add(config_flavour)
            compilers.add(compiler)
    if not config_flavours:
        raise KernelVersionScanError(f"{path}: no combination selects a kernel")
    if len(compilers) != 1 or "" in compilers:
        raise KernelVersionScanError(
            f"{path}: expected one KERNEL_COMPILER, found {sorted(compilers)}"
        )
    return config_flavours, compilers.pop()


if PYTEST_AVAILABLE:

    REQUIRES_TREE_SITTER = pytest.mark.skipif(
        not TREE_SITTER_AVAILABLE, reason="needs tree-sitter and tree-sitter-make"
    )

    SAMPLE_KERNEL_VERSION_MK = """\
KERNEL_COMPILER=gcc
KERNEL_CONFIG_FLAVOR ?=
FLAVOR_DEFAULT ?= generic
FLAVOR_DEFAULT ?= ignored
PLATFORMS_amd64=generic rt
PLATFORMS_arm64=generic nvidia-jp6 imx
ARCHS=amd64 arm64

ifeq (, $(filter $(ZARCH), $(ARCHS)))
    $(error "Unsupported architecture $(ZARCH)")
endif

ifeq ($(ZARCH), amd64)
    KERNEL_VERSION=v6.18.55
    ifneq ($(PLATFORM), rt)
        KERNEL_FLAVOR=$(FLAVOR_DEFAULT)
        KERNEL_CONFIG_FLAVOR=core
    else ifeq ($(HV), k)
        $(error "PLATFORM=rt does not support HV=k")
    else
        # rt has its own branch
        KERNEL_FLAVOR=rt
    endif
else ifeq ($(ZARCH), arm64)
    ifeq (, $(findstring nvidia,$(PLATFORM)))
        KERNEL_FLAVOR=generic
        KERNEL_VERSION=v6.1.155
        ifeq ($(PLATFORM), imx)
            KERNEL_VERSION=
        endif
    else
        KVER_nvidia-jp6=v5.15.136
        KERNEL_FLAVOR=$(PLATFORM)
        KERNEL_VERSION=$(KVER_$(PLATFORM))
    endif
endif

include kernel-commits.mk

KERNEL_COMMIT=$(KERNEL_COMMIT_$(ZARCH)_$(KERNEL_VERSION)_$(KERNEL_FLAVOR))
"""

    @REQUIRES_TREE_SITTER
    def test_scan_kernel_version_mk_sample():
        """
        ifeq/ifneq/else ifeq chains, ?=, computed names, findstring and filter are
        evaluated; $(error) and an empty KERNEL_VERSION invalidate a combination.
        """
        scanner = KernelVersionScanner(SAMPLE_KERNEL_VERSION_MK)
        assert len(list(scanner.combinations(["kvm", "k", "mini"]))) == 15
        assert scanner.select("amd64", "generic", "k") == (
            "KERNEL_COMMIT_amd64_v6.18.55_generic",
            "core",
            "gcc",
        )
        assert scanner.select("amd64", "rt", "kvm") == (
            "KERNEL_COMMIT_amd64_v6.18.55_rt",
            "",
            "gcc",
        )
        assert scanner.select("amd64", "rt", "k") is None
        assert scanner.select("arm64", "imx", "kvm") is None
        assert scanner.select("riscv64", "generic", "mini") is None
        assert scan_kernel_version_mk(SAMPLE_KERNEL_VERSION_MK, ["kvm", "k"]) == (
            {
                "KERNEL_COMMIT_amd64_v6.18.55_generic": {"core"},
                "KERNEL_COMMIT_amd64_v6.18.55_rt": {""},
                "KERNEL_COMMIT_arm64_v6.1.155_generic": {""},
                "KERNEL_COMMIT_arm64_v5.15.136_nvidia-jp6": {""},
            },
            "gcc",
        )

    @REQUIRES_TREE_SITTER
    def test_scan_kernel_version_mk_names():
        """
        Validity comes from the variables inside the KERNEL_COMMIT reference, a
        file that selects nothing is an error, and so is an assignment after the
        include to a variable the selection reads, even through a computed name.
        """
        source = (
            "ARCHS=amd64\nPLATFORMS_amd64=generic imx\nKERNEL_COMPILER=gcc\n"
            "KVER_generic=v6.18.55\nKVER=$(KVER_$(PLATFORM))\n"
            "include kernel-commits.mk\n"
            "KERNEL_COMMIT=$(KERNEL_COMMIT_$(ZARCH)_$(KVER)_generic)\n"
        )
        assert scan_kernel_version_mk(source, ["kvm"]) == (
            {"KERNEL_COMMIT_amd64_v6.18.55_generic": {""}},
            "gcc",
        )
        with pytest.raises(KernelVersionScanError, match="no combination selects"):
            scan_kernel_version_mk(source.replace("generic imx", "imx"), ["kvm"])
        for late in ["KVER=v6.19", "KVER_generic=v6.19", "KERNEL_COMPILER=clang"]:
            with pytest.raises(KernelVersionScanError, match=":8: assigned after"):
                scan_kernel_version_mk(source + late + "\n", ["kvm"])

    @REQUIRES_TREE_SITTER
    def test_scan_kernel_version_mk_unsupported():
        """
        A construct the scanner does not evaluate, or that tree-sitter-make
        misreads, is an error naming its line.
        """
        for construct in [
            "ifdef HV\nendif",
            'ifeq "$(HV)" "k"\nendif',
            "ifeq ( $(HV),k)\nendif",
            "ifeq ($(HV),k )\nendif",
            "KERNEL_VERSION=$(strip v6.18.55)",
            "KERNEL_VERSION=$(shell echo v6.18.55)",
            "KERNEL_VERSION=$(HOSTARCH)",
            "KERNEL_VERSION=v6.18.55 # comment",
            "KERNEL_VERSION=v6.18 \\\n    .55",
            "KERNEL_VERSION?=v6.18.55",
            "KERNEL_VERSION+=v6.18.55",
            "KERNEL_VERSION += v6.18.55",
            "define KERNEL_VERSION\nv6.18.55\nendef",
            "export KERNEL_VERSION=v6.18.55",
            "$(info amd64)",
            "PLATFORM=generic",
        ]:
            source = (
                "ARCHS=amd64\nPLATFORMS_amd64=generic\n"
                f"{construct}\n"
                "include kernel-commits.mk\n"
                "KERNEL_COMMIT=$(KERNEL_COMMIT_$(ZARCH)_$(KERNEL_VERSION)_generic)\n"
            )
            with pytest.raises(KernelVersionScanError, match=r"kernel-version.mk:3: "):
                scan_kernel_version_mk(source, ["kvm"])

    @REQUIRES_TREE_SITTER
    def test_scan_kernel_version_mk_repo():
        """
        The repository's kernel-version.mk, combined with the Makefile's
        HV_SUPPORTED, selects exactly the kernels and flavours EVE builds.
        """
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(os.path.join(root, "Makefile"), "r", encoding="utf-8") as file:
            hypervisors = read_hv_supported(file.read())
        assert hypervisors == ["kvm", "k", "mini"]
        path = os.path.join(root, "kernel-version.mk")
        with open(path, "r", encoding="utf-8") as file:
            assert scan_kernel_version_mk(file.read(), hypervisors) == (
                {
                    "KERNEL_COMMIT_amd64_v6.18.55_generic": {"core", "rt", "hwe", "ai"},
                    "KERNEL_COMMIT_arm64_v6.1.155_generic": {""},
                    "KERNEL_COMMIT_arm64_v5.10.192_nvidia-jp5": {""},
                    "KERNEL_COMMIT_arm64_v5.15.136_nvidia-jp6": {""},
                    "KERNEL_COMMIT_arm64_v6.8.12_nvidia-jp7": {""},
                    "KERNEL_COMMIT_riscv64_v6.1.112_generic": {""},
                },
                "gcc",
            )


class KernelSelection(NamedTuple):
    """The kernels the build uses: the Docker image groups it pulls per branch."""

    images: dict
    compiler: str


def read_kernel_selection(kernel_version_mk="kernel-version.mk", makefile="Makefile"):
    """
    Evaluates kernel-version.mk for every ZARCH, PLATFORM and HV in the Makefile's
    HV_SUPPORTED. Exits with an error if that is not possible.

    Returns:
    - KernelSelection: {branch: names of the Docker images the build pulls for
      it} and the compiler of those images.
    """
    if not TREE_SITTER_AVAILABLE:
        sys.exit(
            "Error: reading kernel-version.mk needs tree-sitter 0.23 or later: "
            "pip install 'tree-sitter>=0.23' tree-sitter-make"
        )
    try:
        with open(makefile, "r", encoding="utf-8") as file:
            hypervisors = read_hv_supported(file.read(), makefile)
        with open(kernel_version_mk, "r", encoding="utf-8") as file:
            config_flavours, compiler = scan_kernel_version_mk(
                file.read(), hypervisors, kernel_version_mk
            )
    except KernelVersionScanError as error:
        sys.exit(f"Error: {error}")
    # kernel-version.mk tags the images
    # $(KERNEL_BRANCH)-$(KERNEL_CONFIG_FLAVOR)-<commit>-$(KERNEL_COMPILER), without
    # the flavour part when KERNEL_CONFIG_FLAVOR is empty
    images = {}
    for variable, flavours in config_flavours.items():
        branch = variable_to_branch_name(variable)
        images[branch] = {
            f"{branch}-{flavour}" if flavour else branch for flavour in flavours
        }
    return KernelSelection(images, compiler)


def reconcile_selected_branches(selected_branches, old_commits, github_commits):
    """
    Matches the branches kernel-version.mk selects with GitHub and kernel-commits.mk.
    GitHub branches the build does not use are skipped and listed in one line.

    Parameters:
    - selected_branches (iterable): The branches kernel-version.mk selects.
    - old_commits (dict): The branches and commits in kernel-commits.mk.
    - github_commits (dict): The branches and latest commits on GitHub.

    Returns:
    - tuple: (the GitHub commits of the selected branches and of the next branches
      already pinned, which no build selects; True if a selected branch is not on
      GitHub, as kernel-commits.mk would then lose a pin the build needs)
    """
    selected = set(selected_branches)
    kept = selected | {branch for branch in old_commits if branch.endswith("-next")}
    skipped = sorted(set(github_commits) - kept - set(old_commits))
    if skipped:
        print(
            f"Skipping branches kernel-version.mk does not select: {', '.join(skipped)}"
        )

    for branch in sorted(set(old_commits) - selected):
        if branch not in kept:
            reason = "no longer selected by kernel-version.mk"
        elif branch not in github_commits:
            reason = "the branch was removed from the repository or protected"
        else:
            continue
        print(Fore.YELLOW + "[warning]" + Style.RESET_ALL + f" :{branch}: {reason}.")

    is_error = False
    for branch in sorted(selected - set(github_commits)):
        is_error = True
        if branch in old_commits:
            reason = (
                f"pinned at {old_commits[branch]}, "
                "but GitHub does not list it (deleted or protected)"
            )
        else:
            reason = "neither pinned in kernel-commits.mk nor on GitHub"
        print(
            Fore.RED
            + "[Error]"
            + Style.RESET_ALL
            + f" :{branch}: selected by kernel-version.mk, {reason}."
        )

    kept_commits = {
        branch: commit for branch, commit in github_commits.items() if branch in kept
    }
    return kept_commits, is_error


if PYTEST_AVAILABLE:

    def test_reconcile_selected_branches(capsys):
        """
        Unselected GitHub branches are skipped, a pinned branch the build no longer
        selects is dropped, and a selected branch missing on GitHub is an error.
        """
        amd64 = "eve-kernel-amd64-v6.18.55-generic"
        jp5 = "eve-kernel-arm64-v5.10.192-nvidia-jp5"
        jp6 = "eve-kernel-arm64-v5.15.136-nvidia-jp6"
        jp7 = "eve-kernel-arm64-v6.8.12-nvidia-jp7"
        old = "eve-kernel-amd64-v6.1.112-generic"
        github_commits = {
            amd64: "a2",
            jp6: "c1",
            old: "o1",
            "eve-kernel-amd64-next": "n1",
            "eve-kernel-amd64-v6.18.46-generic": "b1",
        }
        old_commits = {
            amd64: "a1",
            jp5: "d1",
            old: "o1",
            "eve-kernel-amd64-next": "n1",
            "eve-kernel-arm64-next": "m1",
        }

        assert reconcile_selected_branches(
            [amd64, jp5, jp6, jp7], old_commits, github_commits
        ) == ({amd64: "a2", jp6: "c1", "eve-kernel-amd64-next": "n1"}, True)
        out = capsys.readouterr().out
        assert (
            "Skipping branches kernel-version.mk does not select: "
            "eve-kernel-amd64-v6.18.46-generic\n"
        ) in out
        assert out.count(old) == 1
        assert f":{old}: no longer selected by kernel-version.mk." in out
        assert (
            ":eve-kernel-arm64-next: the branch was removed from the repository"
            " or protected."
        ) in out
        assert f":{jp5}: selected by kernel-version.mk, pinned at d1" in out
        assert f":{jp7}: selected by kernel-version.mk, neither pinned" in out

        assert reconcile_selected_branches([amd64], {amd64: "a1"}, {amd64: "a2"}) == (
            {amd64: "a2"},
            False,
        )


def parse_kernel_version(tag, missing_patch=0):
    """
    Parse the leading vMAJOR.MINOR[.PATCH] of a kernel tag, e.g. v6.18.55,
    v6.17-rc7 or v6.1.111-rt42.

    Parameters:
    - tag (str): The tag name.
    - missing_patch: The patch level of a vMAJOR.MINOR tag. float("inf") makes
      v5.10 an upper bound that every v5.10.x is at or below.

    Returns:
    - tuple: (major, minor, patch) to compare versions numerically, or None if
      the tag does not start with a kernel version.
    """
    match = re.match(r"v(\d+)\.(\d+)(?:\.(\d+))?", tag)
    if not match:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), missing_patch if patch is None else int(patch)


def _fetch_kernel_tags(repo_config, headers, verbose, version_hint=None):
    """
    Helper function to fetch kernel tag names from GitHub: the most recent 100
    tags plus, with a version hint, every tag of its vMAJOR.MINOR line, which
    can be older than those.
    """
    repo_owner, repo_name = repo_config
    api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    queries = [(f"{api_url}/tags?per_page=100&page=1", lambda tag: tag["name"])]
    version = parse_kernel_version(version_hint) if version_hint else None
    if version:
        queries.append(
            (
                # pylint: disable-next=unsubscriptable-object
                f"{api_url}/git/matching-refs/tags/v{version[0]}.{version[1]}",
                lambda ref: ref["ref"].removeprefix("refs/tags/"),
            )
        )

    tags = []
    for url, tag_name in queries:
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                tags += [tag_name(item) for item in response.json()]
            elif verbose:
                print(f"    Failed to fetch tags: {response.status_code}")
        except (requests.RequestException, KeyError, ValueError) as exc:
            if verbose:
                print(f"    Error fetching tags: {exc}")
    return tags


def _below_hint(tag, version_hint):
    """True for a kernel tag other than the hint whose version is not beyond it."""
    version = parse_kernel_version(tag)
    if version is None or tag == version_hint:
        return False
    return not version_hint or version <= parse_kernel_version(
        version_hint, float("inf")
    )


def base_tag_candidates(tags, version_hint=None):
    """
    Order the tags that may be the base of a new branch besides the hint itself:
    the kernel tags at or below the hint's version (all without a hint), newest
    first.

    Parameters:
    - tags (iterable): Tag names. Those without a leading kernel version are dropped.
    - version_hint (str): The kernel version in the branch name (e.g. v6.18.55),
      or None.

    Returns:
    - list: The candidate tag names.
    """
    return sorted(
        (tag for tag in dict.fromkeys(tags) if _below_hint(tag, version_hint)),
        key=parse_kernel_version,
        reverse=True,
    )


def _ancestor_tag_distance(compare):
    """
    Returns how many commits the commit is ahead of the tag, given the GitHub
    compare/{tag}...{commit} result, or None if there is no result or the tag
    is not an ancestor of the commit (the two diverged or the commit is behind
    the tag).
    """
    if not compare or compare.get("status") not in ("ahead", "identical"):
        return None
    if compare.get("behind_by") != 0:
        return None
    return compare.get("ahead_by", float("inf"))


def select_base_tag(distances, version_hint=None):
    """
    Choose the base tag of a new branch: the tag of the kernel version in the
    branch name if it is an ancestor of the branch commit, otherwise the
    ancestor tag at or below that version with the fewest commits ahead.
    Without a version hint any ancestor tag qualifies.

    Parameters:
    - distances (dict): For each compared tag, the commits the branch commit is
      ahead of it, or None if the tag is not an ancestor.
    - version_hint (str): The kernel version in the branch name, or None.

    Returns:
    - str: The base tag, or None if no tag qualifies.
    """
    if version_hint and distances.get(version_hint) is not None:
        return version_hint
    ancestors = {
        tag: distance
        for tag, distance in distances.items()
        if distance is not None and _below_hint(tag, version_hint)
    }
    return min(ancestors, key=ancestors.get) if ancestors else None


if PYTEST_AVAILABLE:

    def test_ancestor_tag_distance():
        """
        Only a tag the commit contains qualifies as its base.
        """
        for compare, expected in [
            ({"status": "ahead", "ahead_by": 42, "behind_by": 0}, 42),
            ({"status": "identical", "ahead_by": 0, "behind_by": 0}, 0),
            ({"status": "diverged", "ahead_by": 12, "behind_by": 345}, None),
            ({"status": "behind", "ahead_by": 0, "behind_by": 7}, None),
            ({"ahead_by": 3}, None),
            (None, None),
        ]:
            assert _ancestor_tag_distance(compare) == expected

    def test_base_tag_candidates():
        """
        Versions compare numerically, tags beyond the hint and tags that are not
        kernel versions are dropped, and a two-part hint covers its patch levels.
        """
        assert parse_kernel_version("v6.18.55") > parse_kernel_version("v6.18.9")
        assert parse_kernel_version("v6.19") > parse_kernel_version("v6.18.55")
        assert parse_kernel_version("v6.1.111-rt42") == (6, 1, 111)
        assert parse_kernel_version("v6.17-rc7") == (6, 17, 0)
        assert parse_kernel_version("v5.10", float("inf")) == (5, 10, float("inf"))
        assert parse_kernel_version("platform-drivers-x86-v4.5-3") is None
        tags = ["v6.18.9", "v6.19", "v6.18.55", "latest", "v6.18.56", "v6.18-rc7"]
        assert base_tag_candidates(tags, "v6.18.55") == ["v6.18.9", "v6.18-rc7"]
        assert base_tag_candidates(tags) == [
            "v6.19",
            "v6.18.56",
            "v6.18.55",
            "v6.18.9",
            "v6.18-rc7",
        ]
        assert base_tag_candidates(
            ["v5.9", "v5.10", "v5.10.186", "v5.11", "v5.10.192"], "v5.10"
        ) == ["v5.10.192", "v5.10.186", "v5.9"]

    def test_select_base_tag():
        """
        The hint tag wins if it is an ancestor; otherwise the nearest ancestor at
        or below the hint, never a newer or a diverged tag.
        """
        distances = {
            "v6.19": 3,
            "v6.18.56": 4,
            "v6.18.55": 500,
            "v6.18.54": None,
            "v6.18.53": 60,
            "v6.18.50": 80,
            "v6.1.111-rt42": 70,
        }

        assert select_base_tag(distances, "v6.18.55") == "v6.18.55"
        assert select_base_tag(distances, "v6.18.54") == "v6.18.53"
        no_hint_tag = {**distances, "v6.18.55": None}
        assert select_base_tag(no_hint_tag, "v6.18.55") == "v6.18.53"
        assert select_base_tag(distances, "v6.1.111") == "v6.1.111-rt42"
        assert select_base_tag(distances) == "v6.19"
        assert select_base_tag(distances, "v6.0") is None
        assert select_base_tag({"v6.18.54": None}) is None
        series = {"v5.10": None, "v5.10.186": 50, "v5.9": 900}
        assert select_base_tag(series, "v5.10") == "v5.10.186"


def _check_single_tag(tag_name, commit_sha, repo_config, headers, verbose):
    """Helper to check a single tag: its ahead_by count, None if not an ancestor."""
    repo_owner, repo_name = repo_config

    api_url = (
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/"
        f"compare/{tag_name}...{commit_sha}"
    )

    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        if response.status_code != 200:
            if verbose:
                print(f"      {tag_name}: not found ({response.status_code})")
            return None
        compare = response.json()
    except (requests.RequestException, ValueError) as exc:
        if verbose:
            print(f"      Error checking {tag_name}: {exc}")
        return None

    ahead_by = _ancestor_tag_distance(compare)
    if verbose:
        if ahead_by is None:
            print(
                f"      {tag_name}: not an ancestor ({compare.get('status')}), skipped"
            )
        else:
            print(f"      {tag_name}: {ahead_by} commits ahead")

    return ahead_by


def find_nearest_kernel_tag(
    commit_sha, repo_config, token=None, verbose=False, version_hint=None
):
    """
    Find the nearest Linux kernel tag that is an ancestor of the given commit.
    This simulates 'git describe --tags' using GitHub API.

    Parameters:
    - commit_sha (str): The commit SHA to find the nearest tag for.
    - repo_config (tuple): (repo_owner, repo_name) for the GitHub repository.
    - token (str): GitHub personal access token for authentication.
    - verbose (bool): Enable verbose output.
    - version_hint (str): The kernel version in the branch name (e.g. v6.18.55),
      or None. That tag is checked first and chosen if it is an ancestor; a tag
      beyond that version never is (see select_base_tag()).

    Returns:
    - str: The nearest kernel tag, or None if not found.
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    if verbose:
        print(f"  Searching for nearest kernel tag for commit {commit_sha[:12]}...")

    distances = {}
    if version_hint:
        distances[version_hint] = _check_single_tag(
            version_hint, commit_sha, repo_config, headers, verbose
        )
    if distances.get(version_hint) is None:
        candidates = base_tag_candidates(
            _fetch_kernel_tags(repo_config, headers, verbose, version_hint),
            version_hint,
        )
        if verbose:
            print(f"    Checking {len(candidates[:20])} candidate kernel tags...")
        # Check only first 20 tags to limit API calls
        for tag in candidates[:20]:
            distances[tag] = _check_single_tag(
                tag, commit_sha, repo_config, headers, verbose
            )
            if distances[tag] is not None and distances[tag] < 100:
                if verbose:
                    print("    Found good match, stopping search early")
                break

    best_tag = select_base_tag(distances, version_hint)

    if best_tag and verbose:
        print(
            f"    Found nearest tag: {best_tag} ({distances[best_tag]} commits ahead)"
        )

    return best_tag


if PYTEST_AVAILABLE:

    def test_find_nearest_kernel_tag(monkeypatch):
        """
        The hint tag is checked first and, if it is an ancestor, no tag list is
        fetched; otherwise the candidates are compared newest first until one is
        less than 100 commits behind the commit.
        """
        compared = []

        def check(tag_name, *_):
            compared.append(tag_name)
            return {"v6.18.46": 13, "v6.18.44": 150, "v6.18.9": 90}.get(tag_name)

        def tags(*_):
            return ["v6.19", "v6.18.45", "v6.18.44", "v6.18.9", "v6.18.8", "latest"]

        monkeypatch.setitem(globals(), "_check_single_tag", check)
        monkeypatch.setitem(globals(), "_fetch_kernel_tags", tags)

        assert find_nearest_kernel_tag("c", ("o", "r"), version_hint="v6.18.46") == (
            "v6.18.46"
        )
        assert compared == ["v6.18.46"]

        compared.clear()
        assert find_nearest_kernel_tag("c", ("o", "r"), version_hint="v6.18.47") == (
            "v6.18.9"
        )
        assert compared == ["v6.18.47", "v6.18.45", "v6.18.44", "v6.18.9"]

        compared.clear()
        assert find_nearest_kernel_tag("c", ("o", "r")) == "v6.18.9"
        assert compared == ["v6.19", "v6.18.45", "v6.18.44", "v6.18.9"]

        compared.clear()
        assert find_nearest_kernel_tag("c", ("o", "r"), version_hint="v6.0") is None
        assert compared == ["v6.0"]


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
    nearest_tag = find_nearest_kernel_tag(next_commit, repo_config, token, verbose)

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
    if parse_kernel_version(old_commit):
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
        print(f"    Searching for tag {tag} or the nearest tag below it...")

    nearest_tag = find_nearest_kernel_tag(
        new_commit, ("lf-edge", "eve-kernel"), token, verbose, version_hint=tag
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


def select_docker_commits(branch_groups, required_images=None):
    """
    Picks for each branch the most recent commit whose image was pushed to every
    group the build pulls: required_images[branch] when given, every group of the
    branch otherwise. A commit dates from its earliest push among those groups,
    so rebuilding an old commit does not make it recent.

    Args:
        branch_groups (dict): The result of group_docker_tags().
        required_images (dict): {branch: group names}, for the branches
        kernel-version.mk selects (one per KERNEL_CONFIG_FLAVOR it uses).

    Returns:
        dict: {branch: commit}. A branch with no commit common to its required
        groups is left out.
    """
    docker_commits = {}
    for branch, groups in branch_groups.items():
        required = (required_images or {}).get(branch) or groups
        pushes = [groups.get(group, {}) for group in required]
        common = set.intersection(*(set(commits) for commits in pushes))
        if common:
            _, docker_commits[branch] = max(
                (min(commits[commit] for commits in pushes), commit)
                for commit in common
            )
    return docker_commits


def fetch_docker_tags(branches, known_branches, selection, verbose=False):
    """
    Fetches kernel commits from docker hub and returns them as a dictionary of
    (branch, commit) pairs.

    Args:
        branches (list): Branch names to look up tags for. Each one is queried
        separately so no single listing runs past the anonymous pagination limit.
        known_branches (iterable): Every branch name, to assign tags to the right one.
        selection (KernelSelection): The images the build pulls.
        verbose (bool): If True, prints all tags with decoded dates and all kernel commits
        from docker hub.

    Returns:
        dict: A dictionary of (branch, commit) pairs.
    """
    branch_groups = group_docker_tags(
        branches,
        known_branches,
        _fetch_tags_per_branch(branches, verbose),
        selection.compiler,
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

    docker_commits = select_docker_commits(branch_groups, selection.images)

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

    def test_docker_commits_required_flavours():
        """
        Only the flavours the build pulls count: a retired flavour or an unused
        plain image neither blocks a commit nor makes it newer.
        """
        branch = "eve-kernel-amd64-v6.18.55-generic"
        flavours = ["core", "rt", "hwe", "ai"]
        tags = [
            (f"{branch}-{flavour}-{commit}-gcc", pushed)
            for commit, pushed in [
                ("111111111111", "2026-01-01T00:00:00.000000Z"),
                ("222222222222", "2026-02-01T00:00:00.000000Z"),
            ]
            for flavour in flavours
        ] + [
            (f"{branch}-111111111111-gcc", "2026-05-01T00:00:00.000000Z"),
            (f"{branch}-legacy-000000000000-gcc", "2025-01-01T00:00:00.000000Z"),
        ]
        branch_groups = group_docker_tags([branch], [branch], tags)
        required = {branch: {f"{branch}-{flavour}" for flavour in flavours}}

        assert not select_docker_commits(branch_groups)
        assert select_docker_commits(branch_groups, required) == {
            branch: "222222222222"
        }
        del branch_groups[branch][f"{branch}-ai"]["222222222222"]
        assert select_docker_commits(branch_groups, required) == {
            branch: "111111111111"
        }


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
    new_commits, updated_branches, docker_tags, pinned_branches, selected_branches=()
):
    """
    Adjusts the branches by comparing the commits from GitHub and Docker Hub.

    Args:
        new_commits (dict): A dictionary containing the new commits.
        updated_branches (dict): A dictionary containing the updated branches.
        docker_tags (dict): A dictionary containing the Docker tags.
        pinned_branches (iterable): The branches in kernel-commits.mk.
        selected_branches (iterable): The branches kernel-version.mk selects.
        Neither these nor the pinned ones may be dropped.

    Returns:
        bool: A boolean value indicating whether an error occurred.
    """
    is_error = False
    for branch, (current_gh_commit, latest_gh_commit) in list(updated_branches.items()):
        if current_gh_commit is None and latest_gh_commit is None:
            # reported by reconcile_selected_branches()
            continue

        docker_commit = docker_tags.get(branch)
        if docker_commit is None and (
            branch in pinned_branches or branch in selected_branches
        ):
            # kernel-commits.mk without it would break the build
            is_error = True
            msg = f" :{branch}: no commit has an image on docker hub for every flavour."
            del updated_branches[branch]
            if branch in pinned_branches:
                msg += (
                    "\n\tKeeping the pinned commit: " + Fore.GREEN + current_gh_commit
                )
                new_commits[branch] = current_gh_commit
            else:
                del new_commits[branch]
            print(Fore.RED + "[Error]" + Style.RESET_ALL + msg)
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

    def test_adjust_branches_by_docker_tags_needs_selected(capsys):
        """
        A branch kernel-version.mk selects but kernel-commits.mk does not pin yet,
        without a commit whose images cover every flavour, is an error rather than
        a new branch to drop.
        """
        new = "eve-kernel-amd64-v6.18.60-generic"
        new_commits = {new: "e1"}
        updated_branches = {new: ("v6.18.60", "e1")}

        assert adjust_branches_by_docker_tags(
            new_commits, updated_branches, {}, [], [new]
        )
        assert not updated_branches and not new_commits
        out = capsys.readouterr().out
        assert f":{new}: no commit has an image" in out
        assert "Is this a new branch" not in out


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


def print_fix_and_rerun():
    """Prints the last line of a run that found errors and wrote nothing."""
    print(
        Fore.RED
        + "[Error]"
        + Style.RESET_ALL
        + ": Please fix the issues and rerun the script."
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
    old_commits = parse_kernel_commits_file(kernel_commits_mk_file)
    selection = read_kernel_selection()
    github_commits = fetch_latest_commits_from_github(
        gh_user, get_github_token(args.token), args.verbose
    )
    new_commits, is_error = reconcile_selected_branches(
        selection.images, old_commits, github_commits
    )
    if is_error:
        print_fix_and_rerun()
        return
    updated_branches = find_updated_branches(
        old_commits, new_commits, get_github_token(args.token), args.verbose
    )

    if not updated_branches:
        print("No kernel updates available.")
        return

    print_updated_branches(updated_branches)

    # fetch tags from docker hub and convert them to branch names
    if adjust_branches_by_docker_tags(
        new_commits,
        updated_branches,
        fetch_docker_tags(
            list(new_commits),
            set(github_commits) | set(old_commits),
            selection,
            args.verbose,
        ),
        old_commits,
        selection.images,
    ):
        print_fix_and_rerun()
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
