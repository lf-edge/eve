# Dockerfile Linter — Tree-sitter

Grammar-based linter/fixer for Dockerfiles. It converts **old style** ENV/ARG to **modern** `KEY=value` form with correct quoting and line wrapping.

## What it does
- Converts:
  - `ENV HOME /home/user` → `ENV HOME=/home/user`
  - `ARG VERSION 1.2.3` → `ARG VERSION=1.2.3`
- Adds quotes only when needed (whitespace or quotes in value). Escapes inner `"` only.
- Preserves existing modern forms (`ENV A=1 B=2` unchanged).
- **Does not** add `=` to bare `ARG NAME` or `ENV NAME` (no value).
- Flattens multi-line old style values and wraps the emitted line(s) to **≤ 100 cols** using Docker continuation:
  ```
  ENV BIG="part1 part2       part3"
  ```
- Idempotent. Tree-sitter only.

## Quick install (venv)
```bash
cd tools/ci/dockerfile_linter
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## Run
```bash
# From repo root

# Lint & fix in-place
python -m tools.ci.dockerfile_linter .

# CI mode: lint only (exit 1 on issues), no writes
python -m tools.ci.dockerfile_linter --ci .

# Specific files (useful in CI with changed files)
python -m tools.ci.dockerfile_linter --ci --files path/to/Dockerfile path/to/Other.Dockerfile.in

# Reformat: collapse multi-line values before wrapping
python -m tools.ci.dockerfile_linter --reformat .
```

## Tests
```bash
# From repo root
PYTHONPATH=. pytest tools/ci/dockerfile_linter/tests -q
```

## CLI (help)
```bash
python -m tools.ci.dockerfile_linter --help
```

**Exit codes:** 0 = ok; 1 = issues in `--ci` or processing error; 2 = tree-sitter not available.
