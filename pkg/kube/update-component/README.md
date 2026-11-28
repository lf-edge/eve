# Kube "update-component" helper tool

update-component is a utility, short lived process which provides a convenience interface for kubernetes
component upgrades and status information.

The interface specifies a series of generalized upgrade methods and backend handlers are implemented for
currently used "infrastructure" components which the kube service installs in HV=kubevirt eve builds.

Supported Components: cdi, kubevirt, longhorn, multus

Upgrade Interface:

1. GetVersion - returns a string version
1. UpgradeSupported - accepts source and destination version, checks component backend to determine
    if the upgrade is supported.  Some components have strict version max distance upgrade rules.
    eg. v1.0.0->v3.1.0 not supported.
1. Uptime - returns the time a component has been ready at a given version
1. Ready - returns nil if the component is online
1. UpgradeStart - initiates a component upgrade to requested version.

## Options

### General Arguments

--component : string component name
--versions-file : path to a single level yaml file defining a list of `<component> : "<expected version>"`

### Optional Arguments

-f  Force: ignore component version constraints

### Check Kubernetes API Ready "--check-api-ready"

Check if api is responding, (rc 0 for success)
eg.
`$ /usr/bin/update-component --check-api-ready
$ echo $?
0`

### Check Component Ready "--check-comp-ready"

Check if component is ready at its expected version, the one listed for it in
--versions-file (rc 0 for success). During an upgrade this only passes once the
component has fully converged on the new version. When it is not ready, the
reason is printed on stderr.
eg.
`$ /usr/bin/update-component --versions-file /etc/expected_versions.yaml --component longhorn --check-comp-ready
$ echo $?
0`

### Check Upgrade Can Start "--check-upgrade-ready"

Check once, without waiting, whether `--upgrade` would get past its readiness
check now: rc 0 if the component is ready at its running version or an
interrupted upgrade already applied the expected one, rc 2 otherwise, with the
reason on stderr. kube-init asks this before it retries a deferred pass.

### Check Component Uptime "--get-uptime"

Print component uptime in seconds
eg.
`$ /usr/bin/update-component --versions-file /etc/expected_versions.yaml --component longhorn --get-uptime
623011`

### Compare Component Version Against Expected "--compare"

Just compare current version, return 0 for matching, 1 for not matching
eg.
`$ /usr/bin/update-component --versions-file /etc/expected_versions.yaml --component longhorn --compare
$ echo $?
0`

### Execute Component Upgrade "--upgrade"

Begin component upgrade to the version listed for it in --versions-file
eg.
`$ /usr/bin/update-component --versions-file /etc/expected_versions.yaml --component "$comp" --upgrade
$ echo $?
0`

An upgrade that stops before changing anything, for a reason that can clear
up on its own, exits 2 and can be run again later: the component is not ready
at its current version within 10 minutes, the cluster cannot be read, or, for
Longhorn, a volume is faulted or an engine upgrade is still under way. An
upgrade the component's version constraints deny, or that fails once it has
started changing the cluster, exits 1. The reason is on stderr.

Once the manifest is applied, the run waits up to 20 minutes for the component
to report the new version, then exits 0 either way: images are pulled at this
point, and the caller's `--check-comp-ready` decides. If an earlier run was
interrupted after applying Longhorn's manifest, the next run applies it again
instead of waiting for the old version to be ready.

Longhorn is upgraded from the manifest the kube container ships for the
expected version, `/etc/lh-cfg-<version>.yaml`. It may move up by one minor
version at a time, or along an exact pair of versions listed as a validated
large step in `longhorn_upgrade.go`. A large step applies the manifest with
`--upgrade-version-check` removed from longhorn-manager.

### Finish Component Upgrade "--finalize"

Run the component's post-upgrade step, if it has one. For Longhorn it restores
`--upgrade-version-check` on longhorn-manager after a large step and waits for
the manager to roll out. Until Longhorn is ready at the expected version, with
every volume on its engine, it exits 2 and changes nothing: restoring the check
restarts every manager. A no-op in every other case.
eg.
`$ /usr/bin/update-component --versions-file /etc/expected_versions.yaml --component longhorn --finalize
$ echo $?
0`

## Logging

By default this tool logs to /persist/kubelog/upgrade-component.log

Example Output:
2024/11/19 19:44:30 Component:multus ready:true running:v3.9.3 expected_version:v3.9.3 uptime_seconds:569.930566
2024/11/19 19:44:32 Component:kubevirt ready:true running:v1.1.0-dirty expected_version:v1.1.0-dirty uptime_seconds:478.254250
2024/11/19 19:44:33 Component:cdi ready:true running:v1.57.1 expected_version:v1.57.1 uptime_seconds:499.523674
2024/11/19 19:44:34 Component:longhorn ready:true running:v1.6.3 expected_version:v1.6.3 uptime_seconds:553.801213

## EVE Runtime Usage

After k3s is ready, kube-init runs the component update pass
(`CheckClusterComponents` in `pkg/kube/kube-init/update`) if:

- the applied overall kube version (integer in /var/lib/applied-kube-version) is less than the version of this image, `KubeVersion` in `pkg/kube/kube-init/update/version.go`
- a previous update to that version has not failed

For each component in turn the pass compares the running version with the
expected one and, if they differ, runs `--upgrade`, polls `--check-comp-ready`
and then runs `--finalize`. After all component upgrades are complete the
applied overall kube version is set to that of the image.
