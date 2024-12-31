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

-f  Force: skip uptime checks and version constraints

### Check Kubernetes API Ready "--check-api-ready"

Check if api is responding, (rc 0 for success)
eg.
`$ /usr/bin/update-component --check-api-ready
$ echo $?
0`

### Check Component Ready "--check-comp-ready"

Check if component is ready, according to its daemonsets (rc 0 for success)
eg.
`$ /usr/bin/update-component --versions-file /etc/expected_versions.yaml --component longhorn --check-comp-ready
$ echo $?
0`

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

## Logging

By default this tool logs to /persist/kubelog/upgrade-component.log

Example Output:
2024/11/19 19:44:30 Component:multus ready:true running:v3.9.3 expected_version:v3.9.3 uptime_seconds:569.930566
2024/11/19 19:44:32 Component:kubevirt ready:true running:v1.1.0-dirty expected_version:v1.1.0-dirty uptime_seconds:478.254250
2024/11/19 19:44:33 Component:cdi ready:true running:v1.57.1 expected_version:v1.57.1 uptime_seconds:499.523674
2024/11/19 19:44:34 Component:longhorn ready:true running:v1.6.3 expected_version:v1.6.3 uptime_seconds:553.801213

## EVE Runtime Usage

After the kube service container has started and k3s has been started, the main run loop will call
Update_CheckClusterComponents which checks a series of prerequisites:

- if applied overall kube version (integer in /var/lib/applied-kube-version) is less than requested version as defined in cluster-update.sh
- if previous update is not failed

If both above checks pass then cluster-update proceeds to check component health and initiate upgrades serially.
After all component upgrades are complete then the applied overall kube version is incremented.
