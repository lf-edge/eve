#!/usr/bin/env python3
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

"""inject-junit-analysis.py <junit-xml> <live-investigation.md> <suite-name>

Rewrites the failure messages in a gotestsum-generated JUnit XML file
(in place) with the real failure message and Claude's conclusion that
live-investigation-watcher.sh recorded for each failing test, so the
Allure report's test overview shows those instead of gotestsum's generic
"Failed". The suite-level testcase (named <suite-name>) fails whenever any
of its subtests do, so it gets every recorded analysis, each prefixed with
the subtest's name.

live-investigation.md is a sequence of per-test blocks:
  # <test name>
  ## Failure
  ```
  <failure message>
  ```
  ## Claude's conclusion
  <markdown text>
"""

# The kebab-case file name matches this action's other scripts.
# pylint: disable=invalid-name

import re
import sys
import xml.etree.ElementTree as ET


def parse_sections(md_path):
    """Return [(test name, failure message, conclusion), ...]."""
    with open(md_path, encoding='utf-8') as f:
        lines = f.read().splitlines()

    raw = []  # (test name, {subsection heading: [lines]})
    fence = False
    subsections = None
    sub = None
    for line in lines:
        if re.match(r'^ *(```|~~~)', line):
            fence = not fence
            # The Failure subsection is nothing but one fenced block; strip
            # its markers. Fences elsewhere (e.g. inside the conclusion) are
            # real content.
            if sub == 'Failure':
                continue
        elif not fence:
            m = re.match(r'^(#{1,6}) (.*)$', line)
            if m and len(m.group(1)) == 1:
                subsections = {}
                sub = None
                raw.append((m.group(2).strip(), subsections))
                continue
            if m and len(m.group(1)) == 2 and subsections is not None:
                sub = m.group(2).strip()
                subsections[sub] = []
                continue
        if subsections is not None and sub is not None:
            subsections[sub].append(line)

    sections = []
    for test, subsections in raw:
        failure = '\n'.join(subsections.get('Failure', [])).strip()
        conclusion = '\n'.join(
            subsections.get("Claude's conclusion", [])).strip()
        if failure or conclusion:
            sections.append((test, failure, conclusion))
    return sections


def compose(failure, conclusion):
    """Format one test's failure message and conclusion as plain text."""
    parts = []
    if failure:
        parts.append(failure)
    if conclusion:
        parts.append("Claude's conclusion:\n" + conclusion)
    return '\n\n'.join(parts)


def main():
    """Inject recorded analyses into the JUnit XML's failure messages."""
    xml_path, md_path, suite = sys.argv[1:4]
    sections = parse_sections(md_path)
    if not sections:
        print('No recorded analyses to inject.')
        return

    tree = ET.parse(xml_path)
    changed = 0
    for tc in tree.getroot().iter('testcase'):
        elem = tc.find('failure')
        if elem is None:
            elem = tc.find('error')
        if elem is None:
            continue
        name = tc.get('name', '')
        # The watcher records a subtest's own name; gotestsum names its
        # testcase <suite>/<subtest> (a standalone test matches exactly).
        matched = [s for s in sections
                   if name == s[0] or name.endswith('/' + s[0])]
        if matched:
            msg = compose(matched[0][1], matched[0][2])
        elif name == suite:
            msg = '\n\n'.join(f'--- {t} ---\n{compose(f, c)}'
                              for t, f, c in sections)
        else:
            continue
        if msg:
            elem.set('message', msg)
            changed += 1

    tree.write(xml_path, encoding='UTF-8', xml_declaration=True)
    print(f'Injected analyses into {changed} testcase(s) in {xml_path}.')


if __name__ == '__main__':
    main()
