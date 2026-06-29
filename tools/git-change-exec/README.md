# git-change-exec

This new tool detects if in your git tree files changed
compared to:

* master branch
* stable branches

also local-only files are considered.

Here it is used to run pillar's go-tests only if something
changed there, same for this tool itself and the get-deps tool.

## Add new Action

To add a new action, it is best to start with one of the already
existing ones, f.e. with `verbose.gce`.
