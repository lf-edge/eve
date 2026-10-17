#!/usr/bin/env python3
"""
Copyright (c) 2025 Zededa, Inc.
SPDX-License-Identifier: Apache-2.0

Dockerfile Linter Tool — Tree-sitter Only

Modernizes old-style ENV/ARG:
  - "ENV KEY val1 val2 \"
  - "ARG KEY default"
into modern:
  - ENV KEY="val1 val2"
  - ARG KEY=default

Rules:
- Never add '=' to "ARG NAME" (no default) or "ENV NAME" (no value).
- Quote only when needed (whitespace or quotes). Do NOT escape backslashes.
- After conversion, wrap physical lines to width <= 100 using Docker-idiomatic
  continuation with backslashes inside a single quoted assignment:
    ENV KEY="segment1 segment2 \
        segment3"
- Idempotent: running again produces no changes.

Exit codes:
- 0: success, no issues (or fixed in non-CI).
- 1: issues in CI mode or processing errors.
- 2: tree-sitter not available.

Usage:
    python dockerfile_linter.py [directory]
    python dockerfile_linter.py --ci --files file1 file2...
"""

import os
import sys
import argparse
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Set
import shutil
import json
import warnings

# --- Tree-sitter setup (required) -------------------------------------------

try:
    import tree_sitter  # noqa: F401
    from tree_sitter import Language, Parser
    import tree_sitter_dockerfile as ts_dockerfile
    TS_AVAILABLE = True
except Exception:
    TS_AVAILABLE = False


class DockerfileTreeSitterLinter:
    """Tree-sitter based Dockerfile linter for modernizing ENV/ARG syntax."""

    def __init__(self, ci_mode: bool = False, reformat: bool = False,
                 json_output: bool = False, github_actions: bool = False,
                 wrap_width: int = 100, cont_indent: int = 4):
        if not TS_AVAILABLE:
            print("ERROR: tree-sitter Dockerfile grammar is required.\n"
                  "Install: pip install tree-sitter tree-sitter-dockerfile", file=sys.stderr)
            raise SystemExit(2)

        self.ci_mode = ci_mode
        self.reformat = reformat
        self.json_output = json_output
        self.github_actions = github_actions
        self.wrap_width = wrap_width
        self.cont_indent = cont_indent

        self.issues: List[Dict] = []
        self.summary_data: Dict = {
            'files_processed': 0,
            'files_with_issues': 0,
            'total_issues': 0,
            'issues_by_type': {}
        }

        # Init parser
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self.language = Language(ts_dockerfile.language())
        self.parser = Parser()
        self.parser.language = self.language

    # --- Discovery ----------------------------------------------------------

    def find_dockerfiles(self, directory: Path, specific_files: Optional[List[str]] = None) -> List[Path]:
        """Find all Dockerfile and Dockerfile.in files (recursively unless files are specified)."""
        if specific_files:
            out: List[Path] = []
            for fp in specific_files:
                p = Path(fp)
                if p.exists() and (p.name == "Dockerfile" or p.name == "Dockerfile.in"):
                    out.append(p)
            return out

        dockerfiles: List[Path] = []
        for root, dirs, files in os.walk(directory):
            # prune
            dirs[:] = [d for d in dirs if not d.startswith('.git') and
                       d not in {'.go', '.venv', 'node_modules', '__pycache__',
                                 '.pytest_cache', 'target', 'build', '.cache'} and
                       not d.startswith('.')]
            for f in files:
                if f == "Dockerfile" or f == "Dockerfile.in":
                    dockerfiles.append(Path(root) / f)
        return sorted(dockerfiles)

    # --- Quoting + Wrapping -------------------------------------------------

    def needs_quoting(self, value: str) -> bool:
        """Quote if value has whitespace or quotes. Don't force-quote on $."""
        if value == "":
            return False
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            return False
        return any(ch.isspace() for ch in value) or ('"' in value) or ("'" in value)

    def quote_value(self, value: str) -> str:
        """Wrap in double quotes and escape only inner double-quotes. Do not touch backslashes or $."""
        if not self.needs_quoting(value):
            return value
        return '"' + value.replace('"', '\\"') + '"'

    def _wrap_env_assignment(self, instr: str, key: str, quoted_value: str) -> str:
        """
        Emit ENV/ARG assignment with wrapping <= wrap_width.
        If not quoted and too long, force quote then wrap.
        """
        width = self.wrap_width
        indent = self.cont_indent
        prefix = f"{instr} {key}="

        # If unquoted: keep single line unless too long, then quote and continue.
        if not (quoted_value.startswith('"') and quoted_value.endswith('"')):
            one = f"{prefix}{quoted_value}"
            if len(one) <= width:
                return one
            # force quote
            quoted_value = self.quote_value(quoted_value)

        inner = quoted_value[1:-1]  # inside quotes
        # Budgets (account for quotes)
        first_budget = max(0, width - len(prefix) - 2)
        cont_budget = max(0, width - indent)

        words = inner.split(" ")
        lines: List[str] = []
        buf = ""
        for w in words:
            cand = w if buf == "" else f"{buf} {w}"
            limit = first_budget if not lines else cont_budget
            if len(cand) <= limit or buf == "":
                buf = cand
            else:
                lines.append(buf)
                buf = w
        if buf:
            lines.append(buf)

        if len(lines) == 1:
            return f'{prefix}"{lines[0]}"'

        cont_prefix = " " * indent
        # build wrapped with continuations (backslash at end of non-last lines, final line closes quote)
        out = f'{prefix}"{lines[0]} \\'
        for i, seg in enumerate(lines[1:], 1):
            if i == len(lines) - 1:
                out += f'\n{cont_prefix}{seg}"'
            else:
                out += f'\n{cont_prefix}{seg} \\'
        return out

    # --- Parsing helpers (TS AST + ERROR spans) -----------------------------

    def extract_text(self, node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def _collect_oldstyle_in_span(self, start_line: int, end_line: int, all_lines: List[str]) -> List[Dict]:
        """
        Scan a given [start_line, end_line] **inclusive** for old-style ENV/ARG
        with proper handling of backslash continuations. Return list of instructions.
        """
        instrs: List[Dict] = []
        i = start_line
        n = min(end_line, len(all_lines) - 1)
        while i <= n:
            raw = all_lines[i]
            line = raw.strip()
            if not line or line.startswith('#'):
                i += 1
                continue

            # Starts with ENV/ARG (support tabs)
            if line.startswith('ENV ') or line.startswith('ARG ') or line.startswith('ENV\t') or line.startswith('ARG\t'):
                start_i = i
                agg_lines = [line]
                # follow continuations within span
                while agg_lines[-1].rstrip().endswith('\\') and (i + 1) <= n:
                    i += 1
                    nxt = all_lines[i].strip()
                    agg_lines.append(nxt)
                # done; parse the logical instruction
                logical = " ".join(l.rstrip("\\").strip() for l in agg_lines if not l.strip().startswith('#')).strip()
                # tokens: INSTR KEY [VALUE...], but skip already-modern "KEY=..." or multi-pair ENV
                parts = logical.split(None, 2)
                if len(parts) >= 2:
                    instr = parts[0]
                    key = parts[1]
                    # If second token contains '=', it's already modern OR multi-pair scenario -> skip
                    if '=' in key:
                        i += 1
                        continue

                    rest = parts[2].strip() if len(parts) > 2 else ""
                    # If rest starts like KEY=..., this is already modern multi-pair -> skip
                    if rest and (("=" in rest.split()[0]) or rest.startswith('=')):
                        i += 1
                        continue

                    # Skip no-value ENV/ARG entirely (must not add '=')
                    if rest == "":
                        i += 1
                        continue

                    # We have old-style VALUE (possibly spaced)
                    value = rest
                    instrs.append({
                        'type': instr,            # 'ENV' or 'ARG'
                        'key': key,
                        'value': value,
                        'line': start_i + 1,      # 1-based
                        'needs_modernization': True,
                        'original_text': "\n".join(agg_lines)
                    })
                i += 1
            else:
                i += 1
        return instrs

    def find_env_arg_instructions(self, tree, source: bytes) -> List[Dict]:
        """Traverse AST; for env/arg or error spans, collect old-style ENV/ARG safely."""
        text = source.decode('utf-8', errors='replace')
        all_lines = text.split('\n')

        out: List[Dict] = []
        seen: Set[Tuple[int, str, str]] = set()  # (line, key, type)

        def scan_span(node):
            s = node.start_point[0]
            e = node.end_point[0]
            for ins in self._collect_oldstyle_in_span(s, e, all_lines):
                sig = (ins['line'], ins['key'], ins['type'])
                if sig not in seen:
                    seen.add(sig)
                    out.append(ins)

        def walk(node):
            # For explicit nodes, scan their spans. Old-style ENV/ARG tends to live in ERROR spans,
            # but we scan explicit env/arg nodes too (safe; the filter skips modern syntax).
            if node.type in ('env_instruction', 'arg_instruction', 'ERROR'):
                scan_span(node)
            for ch in node.children:
                walk(ch)

        walk(tree.root_node)
        return out

    # --- Modernization + application ---------------------------------------

    def modernize_instruction(self, instruction: Dict, source_lines: List[str]) -> str:
        instr = instruction['type']  # 'ENV' or 'ARG'
        key = instruction['key']
        raw_value = instruction['value'].strip()

        # If no value (ENV NAME / ARG NAME): return original line untouched
        if raw_value == "":
            first_line = instruction.get('original_text', '').split('\n', 1)[0].strip() or f"{instr} {key}"
            return first_line

        # Normalize whitespace; --reformat collapses aggressively, else still collapse continuation whitespace
        if self.reformat:
            v = raw_value.replace('\\\n', ' ').replace('\n', ' ')
            v = ' '.join(v.split())
        else:
            v = raw_value.replace('\\\n', ' ').replace('\n', ' ')
            v = ' '.join(v.split())

        quoted = self.quote_value(v)
        return self._wrap_env_assignment(instr, key, quoted)

    def add_github_annotation(self, file_path: Path, line: int, message: str, level: str = "warning"):
        if self.github_actions:
            print(f"::{level} file={file_path},line={line}::{message}")

    def add_to_summary(self, issue_type: str):
        self.summary_data['issues_by_type'][issue_type] = self.summary_data['issues_by_type'].get(issue_type, 0) + 1
        self.summary_data['total_issues'] += 1

    def generate_github_summary(self):
        if not self.github_actions:
            return
        summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
        if not summary_file:
            return
        with open(summary_file, 'a', encoding='utf-8') as f:
            f.write("## Dockerfile Linter Results\n\n")
            f.write(f"- **Files Processed:** {self.summary_data['files_processed']}\n")
            f.write(f"- **Files with Issues:** {self.summary_data['files_with_issues']}\n")
            f.write(f"- **Total Issues:** {self.summary_data['total_issues']}\n\n")
            if self.summary_data['issues_by_type']:
                f.write("### Issues by Type\n\n")
                for t, c in self.summary_data['issues_by_type'].items():
                    f.write(f"- **{t}:** {c}\n")
                f.write("\n")

    def output_json_results(self):
        if self.json_output:
            result = {
                'summary': self.summary_data,
                'issues': self.issues
            }
            print(json.dumps(result, indent=2))

    def process_dockerfile(self, dockerfile_path: Path) -> bool:
        """Process a single Dockerfile using tree-sitter parsing only."""
        self.summary_data['files_processed'] += 1
        try:
            source = dockerfile_path.read_bytes()
            source_text = source.decode('utf-8', errors='replace')
            source_lines = source_text.splitlines()

            tree = self.parser.parse(source)
            if tree.root_node.has_error and not self.json_output:
                msg = f"Parse warning in {dockerfile_path} - continuing with partial parsing"
                self.add_github_annotation(dockerfile_path, 1, msg, "warning")
                print(f"WARNING: {msg}")

            instructions = self.find_env_arg_instructions(tree, source)

            if not instructions:
                return True

            file_has_issues = False
            # Build issues and use the same emitter for suggestion text
            for ins in instructions:
                new_line = self.modernize_instruction(ins, source_lines)
                issue = {
                    'file': str(dockerfile_path),
                    'line': ins['line'],
                    'type': f"obsolete_{ins['type'].lower()}_syntax",
                    'message': f"Obsolete {ins['type']} syntax: use {ins['type']} {ins['key']}=value format",
                    'suggestion': new_line
                }
                self.issues.append(issue)
                self.add_to_summary(issue['type'])
                file_has_issues = True
                self.add_github_annotation(dockerfile_path, ins['line'], issue['message'])
                if not self.json_output:
                    print(f"{dockerfile_path}:{ins['line']}: {issue['message']}")
                    print(f"  Suggestion: {issue['suggestion']}")

            if not self.ci_mode and instructions:
                self._apply_fixes(dockerfile_path, instructions, source_lines)

            if file_has_issues:
                self.summary_data['files_with_issues'] += 1
            return True

        except SystemExit:
            raise
        except Exception as e:
            error_msg = f"Error processing {dockerfile_path}: {e}"
            self.add_github_annotation(dockerfile_path, 1, error_msg, "error")
            if not self.json_output:
                print(f"ERROR: {error_msg}", file=sys.stderr)
            return False

    def _apply_fixes(self, dockerfile_path: Path, instructions: List[Dict], source_lines: List[str]):
        """Apply modernization fixes in-place (bottom-to-top to keep indices valid)."""
        backup_path = dockerfile_path.with_suffix(dockerfile_path.suffix + '.backup')
        shutil.copy2(dockerfile_path, backup_path)
        try:
            modified_lines = source_lines.copy()
            # Sort by starting line descending
            for ins in sorted(instructions, key=lambda x: x['line'], reverse=True):
                idx0 = ins['line'] - 1
                if idx0 < 0 or idx0 >= len(modified_lines):
                    if not self.json_output:
                        print(f"Warning: Invalid line {ins['line']} for key {ins.get('key','?')}")
                    continue

                new_text = self.modernize_instruction(ins, source_lines)
                original_text = ins.get('original_text', '')
                if '\n' in original_text:
                    # remove N original lines
                    n_remove = len(original_text.split('\n'))
                    for _ in range(n_remove):
                        if idx0 < len(modified_lines):
                            modified_lines.pop(idx0)
                    # insert possibly multi-line replacement as a single element; final join will expand it
                    modified_lines.insert(idx0, new_text)
                else:
                    modified_lines[idx0] = new_text

            dockerfile_path.write_text('\n'.join(modified_lines) + '\n', encoding='utf-8')
            if not self.json_output:
                print(f"Fixed {dockerfile_path}")
        except Exception:
            shutil.copy2(backup_path, dockerfile_path)
            raise
        finally:
            if backup_path.exists():
                backup_path.unlink()

    def process_directory(self, directory: Path, specific_files: Optional[List[str]] = None) -> bool:
        dockerfiles = self.find_dockerfiles(directory, specific_files)
        if not dockerfiles:
            if not self.json_output:
                print("No Dockerfiles found.")
            return True

        ok = True
        for df in dockerfiles:
            if not self.process_dockerfile(df):
                ok = False
        return ok


def main():
    ap = argparse.ArgumentParser(description="Dockerfile linter (Tree-sitter only) for modernizing ENV/ARG.")
    ap.add_argument('directory', nargs='?', default='.', help='Directory to process (default: .)')
    ap.add_argument('--ci', action='store_true', help='CI mode: lint only, do not modify files; nonzero exit on issues')
    ap.add_argument('--reformat', action='store_true', help='Collapse multi-line values into one logical value before wrapping')
    ap.add_argument('--json', action='store_true', help='Output results in JSON')
    ap.add_argument('--github-actions', action='store_true', help='Enable GitHub Actions annotations and summary')
    ap.add_argument('--files', nargs='*', help='Process specific files (use with CI changed files)')
    ap.add_argument('--width', type=int, default=100, help='Max output line width (default: 100)')
    ap.add_argument('--indent', type=int, default=4, help='Continuation indent spaces (default: 4)')
    args = ap.parse_args()

    # Auto-detect GHA
    if not args.github_actions and os.environ.get('GITHUB_ACTIONS') == 'true':
        args.github_actions = True

    # Create linter
    try:
        linter = DockerfileTreeSitterLinter(
            ci_mode=args.ci,
            reformat=args.reformat,
            json_output=args.json,
            github_actions=args.github_actions,
            wrap_width=args.width,
            cont_indent=args.indent,
        )
    except SystemExit as e:
        # Tree-sitter missing -> exit(2)
        sys.exit(int(str(e)))

    directory = Path(args.directory)
    if not directory.exists():
        print(f"ERROR: Directory {directory} does not exist", file=sys.stderr)
        sys.exit(1)

    success = linter.process_directory(directory, args.files)

    linter.generate_github_summary()
    linter.output_json_results()

    if not success:
        sys.exit(1)
    elif linter.summary_data['total_issues'] > 0 and args.ci:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
