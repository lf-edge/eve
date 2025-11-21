"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0
"""

def test_env_multiline_continuation_collapses(tmp_path, linter_factory):
    content = """FROM busybox
ENV MYENV val1 val2 \\
    val3
"""
    l = linter_factory(ci_mode=False)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)
    out = (tmp_path / "Dockerfile").read_text(encoding="utf-8")

    # Collapsed to a single logical value; since spaces exist -> quoted
    assert 'ENV MYENV="val1 val2 val3"' in out

def test_long_value_wrapping(tmp_path, linter_factory):
    long_words = " ".join(["word"] * 30)  # long enough to force wrap under width=40
    content = f"FROM busybox\nENV BIG {long_words}\n"
    l = linter_factory(ci_mode=False, wrap_width=40)
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    l.process_directory(tmp_path)
    out = (tmp_path / "Dockerfile").read_text(encoding="utf-8")

    # Ensure wrapped form exists and all physical lines are <= 40 chars
    for line in out.splitlines():
        if line.startswith("ENV BIG=") or line.startswith("    "):
            assert len(line) <= 40

    # Continuation style: non-last lines end with " \", last line ends with a double quote
    lines = [ln for ln in out.splitlines() if ln.startswith("ENV BIG=") or ln.startswith("    ")]
    assert len(lines) >= 2  # actually wrapped
    for ln in lines[:-1]:
        assert ln.endswith(" \\")
    assert lines[-1].endswith('"')
    assert not lines[-1].endswith(' \\"')  # no trailing backslash on last
