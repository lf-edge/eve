# Description

Provide a clear and concise description of the changes in this PR and
explain why they are necessary.

If the PR contains only one commit, you will see the commit message above:
fill free to use it under the description section here, if it is good enough.

For **Backport PRs**, a full description is optional, but please clearly state
the original PR number(s). Use the #{NUMBER} format for that, it makes it easier
to handle with the scripts later. For example:

> Backport of #1234, #5678, #91011

Title of a backport PR must also follow the following format:

> "[x.y-stable] Original PR title".

where `x.y-stable` is the name of the target stable branch, and
`Original PR title` is the title of the original PR.

For example, for a PR that backports a PR with title `Fix the nasty bug` to
branch `13.4-stable` the title should be:
`[13.4-stable] Fix the nasty bug`.

## PR dependencies

List all dependencies of this PR (when applicable, otherwise remove this
section).

## How to test and validate this PR

Please describe how the changes in this PR can be validated or verified. For
example:

- If your PR fixes a bug, outline the steps to confirm the issue is resolved.
- If your PR introduces a new feature, explain how to test and validate it.

This will be used

1. to provide test scenarios for the QA team
1. by a reviewer to validate the changes in this PR.

The first is especially important, so, please make sure to provide as much
detail as possible.

If it's covered by an automated test, please mention it here.

## Changelog notes

Text in this section will be used to generate the changelog entry for
release notes. The consumers of this are end users, not developers.
So, provide a clear and short description of what is changed in the PR from
the end user perspective. If it changes only tooling or some internal
implementation, put a note like "No user-facing changes" or "None".

## PR Backports

For all current LTS branches, please state explicitly if this PR should be
backported or not. This section is used by our scripts to track the backports,
so, please, do not omit it.

Here is the list of current LTS branches (it should be always up to date):

- 14.5-stable
- 13.4-stable

For example, if this PR fixes a bug in a feature that was introduced in 14.5,
you can write:

```text
- 14.5-stable: To be backported.
- 13.4-stable: No, as the feature is not available there.
```

Also, to the PRs that should be backported into any stable branch, please
add a label `stable`.

## Checklist

- [ ] I've provided a proper description
- [ ] I've added the proper documentation
- [ ] I've tested my PR on amd64 device
- [ ] I've tested my PR on arm64 device
- [ ] I've written the test verification instructions
- [ ] I've set the proper labels to this PR

For backport PRs (remove it if it's not a backport):

- [ ] I've added a reference link to the original PR
- [ ] PR's title follows the template

And the last but not least:

- [ ] I've checked the boxes above, or I've provided a good reason why I didn't
  check them.

Please, check the boxes above after submitting the PR in interactive mode.
