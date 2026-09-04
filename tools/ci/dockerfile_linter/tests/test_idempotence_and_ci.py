"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0
"""

def test_idempotence_roundtrip(tmp_path, linter_factory):
    content = """FROM busybox
ENV FOO val1 val2 \\
    val3
ARG BAR default
"""
    # First pass modifies file
    l1 = linter_factory(ci_mode=False)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l1.process_directory(tmp_path)
    out1 = (tmp_path / "Dockerfile").read_text(encoding="utf-8")

    # Second pass should find no further issues and produce no changes
    l2 = linter_factory(ci_mode=False)
    l2.process_directory(tmp_path)
    out2 = (tmp_path / "Dockerfile").read_text(encoding="utf-8")
    assert out1 == out2
    assert l2.summary_data["total_issues"] == 0

def test_github_annotations_in_ci(tmp_path, capsys, linter_factory):
    content = "FROM busybox\nENV FOO bar baz\n"
    # CI mode: no writes, but annotations emitted
    l = linter_factory(ci_mode=True, github_actions=True)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)

    captured = capsys.readouterr().out
    assert "::warning" in captured
    assert "Obsolete ENV syntax" in captured
    # File unchanged in CI
    assert (tmp_path / "Dockerfile").read_text(encoding="utf-8") == content
