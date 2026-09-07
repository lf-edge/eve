"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from tools.ci.dockerfile_linter import DockerfileTreeSitterLinter
import pytest

# Skip entire suite if tree-sitter isn't installed (the tool requires it)
treesitter = pytest.importorskip("tree_sitter")
ts_docker = pytest.importorskip("tree_sitter_dockerfile")

@pytest.fixture
def linter_factory():
    def make(**kwargs):
        return DockerfileTreeSitterLinter(
            ci_mode=kwargs.get("ci_mode", False),
            reformat=kwargs.get("reformat", False),
            json_output=kwargs.get("json_output", False),
            github_actions=kwargs.get("github_actions", False),
            wrap_width=kwargs.get("wrap_width", 100),
            cont_indent=kwargs.get("cont_indent", 4),
        )
    return make


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def read(p):
    return p.read_text(encoding="utf-8")


def run_on_text(tmp_path, content, *, linter_kwargs=None):
    """
    Helper: writes a Dockerfile, runs the linter on the directory,
    returns (final_content, linter_instance, dockerfile_path).
    """
    dockerfile = write(tmp_path, "Dockerfile", content)
    kwargs = linter_kwargs or {}
    linter = DockerfileTreeSitterLinter(**kwargs)
    ok = linter.process_directory(tmp_path)
    assert ok is True
    return read(dockerfile), linter, dockerfile
