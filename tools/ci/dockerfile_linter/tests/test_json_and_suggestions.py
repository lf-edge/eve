"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0
"""

def test_suggestion_matches_emitter(tmp_path, linter_factory):
    content = "FROM busybox\nENV GREETING hello world\n"
    l = linter_factory(ci_mode=True)  # lint-only
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)

    assert l.issues, "Expected at least one issue"
    suggestion = l.issues[0]["suggestion"]
    # Expected normalized, quoted suggestion
    assert suggestion.startswith('ENV GREETING="hello world"') or suggestion.startswith('ENV GREETING="hello ')
    # No backslash escaping or dollar escaping regressions
    assert "\\\\" not in suggestion
    assert "\\$" not in suggestion
