"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0
"""

def test_env_single_word(tmp_path, linter_factory):
    content = "FROM busybox\nENV FOO bar\n"
    linter = linter_factory(ci_mode=False)
    df = tmp_path / "Dockerfile"
    df.write_text(content, encoding="utf-8")

    assert linter.process_directory(tmp_path) is True
    out = df.read_text(encoding="utf-8")

    assert "ENV FOO=bar" in out
    # No extra quotes for single word
    assert 'ENV FOO="bar"' not in out
    # Idempotent re-run:
    l2 = linter_factory(ci_mode=False)
    assert l2.process_directory(tmp_path) is True
    assert out == df.read_text(encoding="utf-8")

def test_env_with_spaces_quotes_and_dollar(tmp_path, linter_factory):
    content = 'FROM busybox\nENV TITLE say "hello"\nENV PATH $PATH:/usr/local/bin\n'
    linter = linter_factory(ci_mode=False)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    linter.process_directory(tmp_path)
    out = (tmp_path / "Dockerfile").read_text(encoding="utf-8")

    # Quotes inside value are escaped and overall value is quoted
    assert 'ENV TITLE="say \\"hello\\""' in out

    # PATH line may be quoted or not (both are valid). But `$` must NOT be escaped.
    assert "$PATH:/usr/local/bin" in out
    assert "\\$PATH" not in out

def test_env_already_modern_multi_pairs_unchanged(tmp_path, linter_factory):
    content = "FROM busybox\nENV A=1 B=2\n"
    l = linter_factory(ci_mode=True)  # lint-only
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)
    out = (tmp_path / "Dockerfile").read_text(encoding="utf-8")
    assert out == content  # unchanged
    assert l.summary_data["total_issues"] == 0

def test_arg_rules(tmp_path, linter_factory):
    content = "FROM busybox\nARG FOO\nARG BAR default\n"
    l = linter_factory(ci_mode=False)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)
    out = (tmp_path / "Dockerfile").read_text(encoding="utf-8")

    # Bare ARG stays as-is (no '=' appended)
    assert "\nARG FOO\n" in out
    # ARG with default gets modernized
    assert "\nARG BAR=default\n" in out

def test_env_no_value_stays(tmp_path, linter_factory):
    content = "FROM busybox\nENV EMPTY\n"
    l = linter_factory(ci_mode=False)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)
    out = (tmp_path / "Dockerfile").read_text(encoding="utf-8")
    assert out == content
    assert l.summary_data["total_issues"] == 0
