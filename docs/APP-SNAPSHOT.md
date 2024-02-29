# Application Snapshot, Overview and API Specifications

## Overview

This document aims to provide an overview of the snapshotting feature in EVE,
focusing on its functional aspects and API specifications. It serves as a guide
for users, and developers who are interested in understanding what the feature
does, and how it interacts with other components in the EVE ecosystem. The
document will cover the following key areas:

* **Feature Description**: What snapshotting is.
* **API Specifications**: Detailed explanation of the APIs involved in
  triggering, managing, and restoring snapshots.
* **Maximum Snapshots Limit**: How many snapshots can be stored at a time.
* **Snapshot Storage**: Understanding extra space requirements.

For those interested in the underlying code and implementation details, please
refer to the Implementation Document located in [pkg/pillar/docs/app-snapshot.md](../pkg/pillar/docs/app-snapshot.md).

## What is Application Snapshot

An application snapshot in the context of EVE is a saved state of an individual
application's configuration at a specific point in time. It captures the
configuration of the application and associated storage data. This saved state
can be used to restore the application to the exact configuration it had when
the snapshot was taken. This is particularly useful for rolling back to a
previous state in case of errors or undesired changes.

An application snapshot in EVE consists of two main components:

* **Configuration Snapshot**: This is a snapshot of the application's
  configuration. This configuration snapshot is stored on both the controller
  and the device side. During a rollback, this configuration is reapplied to the
  application, effectively restoring it to the state it had at the time the
  snapshot was taken.
* **Volumes Snapshot**: In addition to the configuration snapshot, a snapshot of
  the application's volumes is also taken on the device side. This ensures that
  the state of the volumes corresponds to the configuration snapshot. During a
  rollback, the volume snapshot is used to restore the volumes to the state they
  had at the time the snapshot was taken.

It is important to note that snapshots in EVE are created on a per-application
basis, not per node. Each application can have its own set of snapshots,
allowing for fine-grained control over the rollback process for individual
applications.

It's important to note that while application snapshots provide a powerful
mechanism for rolling back to a previous state, there are scenarios where it may
not be possible to fully restore the old application configuration. This can
occur if the state of the node has changed significantly since the snapshot was
taken. For example, if certain hardware resources, such as a network interface,
have been removed from the node or allocated to another entity (e.g., another
application) on the same node, it may not be possible to restore the old
application configuration that relied on those resources. In such cases, the
rollback process may encounter difficulties or may not be able to proceed as
expected. Therefore, it is essential to consider the current state of the node
and the availability of resources when planning to use application snapshots for
rollback.

## EVE-Controller Application Snapshot API

This section describes how the controller interacts with the device to manage
snapshots using the EVE API. The API is defined in the following Protocol
Buffers (protobuf) files:

* [proto/config/appconfig.proto](https://github.com/lf-edge/eve-api/blob/main/proto/config/appconfig.proto):
  Defines the messages sent from the controller to the device.
* [proto/info/info.proto](https://github.com/lf-edge/eve-api/blob/main/proto/info/info.proto):
  Defines the messages sent from the device to the controller.

These files are located in the _eve-api_ repository on
GitHub: [github.com/lf-edge/eve-api](https://github.com/lf-edge/eve-api)

### Snapshot Creation API

The snapshot creation process allows the controller to request the creation of a
new snapshot on the device. The device then attempts to create the specified
snapshot and reports the outcome of the creation to the controller.

It is important to note that the number of snapshots stored for an application
instance is managed by the `max_snapshots` field in the `SnapshotConfig`
message. If the number of snapshots exceeds the specified limit as a result of a
new snapshot creation, the oldest snapshot will be automatically deleted, even
if it is the active one.

Currently, a maximum of 1 snapshot is supported. More snapshots are not
supported at this time.

#### Controller Triggering Snapshot Creation

The controller can request the device to create a snapshot by sending
an `AppInstanceConfig` message with the `snapshot` field populated.
The `snapshot` field contains a `SnapshotConfig` message, which includes
the `snapshots` field. The `snapshots` field is a list of `SnapshotDesc`
messages, each describing a snapshot instance. To request a new snapshot, the
controller adds a new `SnapshotDesc` message to the list with the desired id and
type.

* `id`: A unique identifier for the snapshot in the form of a standard UUIDv4.
  It should be unique within the app instance. The ID is generated by the
  controller if the snapshot creation is requested by the controller. Currently,
  only controller-generated UUIDs are supported. If the snapshot creation is
  triggered locally on the device, the device generates the ID and reports it
  back to the controller. However, this functionality is not supported at this
  time.
* `type`: The reason for the snapshot creation, specified using
  the `SnapshotType` enumeration. Currently, the only supported value
  is `SNAPSHOT_TYPE_APP_UPDATE,` which indicates that the snapshot is created as
  a result of an application update. This type of snapshot is used to capture
  the state of the application before an update is applied, allowing the system
  to roll back to the previous state if needed. Other snapshot types are not
  supported at this time.

#### Device Reporting Snapshot Creation

The device reports the creation of a snapshot to the controller by sending
a `ZInfoApp` message with the `snapshots` field populated. The `snapshots` field
is a list of `ZInfoSnapshot` messages, each providing information about a
snapshot. The device adds a new `ZInfoSnapshot` message to the list for each
newly created snapshot.

* `id`: The identifier for the snapshot, as provided by the controller.
* `config_id` and `config_version`: The app instance configuration ID and
  version associated with the snapshot.
* `create_time`: A timestamp indicating when the snapshot was created.
* `type`: The reason for the snapshot creation, as specified in
  the `SnapshotType` enumeration.
* `snap_err`: Information about any errors that occurred during the snapshot
  handling.

### Rollback to a Snapshot API

Rolling back to a snapshot involves reverting the application instance to a
previously captured state. This process is initiated by the controller and
executed by the device. The process consists of two parts: the controller
requesting the rollback and the device reporting the success or error of the
rollback.

#### Controller Requesting a Rollback

The controller can request a rollback to a specific snapshot by sending
an `AppInstanceConfig` message with the `SnapshotConfig` message, which includes
the `active_snapshot` and `rollback_cmd` fields.

* `active_snapshot`: Specifies the ID of the snapshot to which the application
  instance should be rolled back. The ID should correspond to one of the
  snapshots previously reported by the device in the `ZInfoApp` message.
* `rollback_cmd`: Contains an `InstanceOpsCmd` message used to trigger the
  rollback. The counter field inside the InstanceOpsCmd message is incremented
  when a snapshot is used for a rollback. It should not be decreased. It is
  necessary for cases when the state of the device is behind the controller
  because it hasn't yet managed to fetch the latest declarative statement. Only
  increasing the counter will trigger the rollback.

#### Device Reporting Rollback Result

After receiving the rollback request, the device attempts to roll back the
application instance to the specified snapshot. The device then reports the
outcome of the rollback in the `ZInfoApp` message, it’s `ZInfoSnapshot`
sub-message that contains information about the snapshot status.

##### Reporting Rollback Success

The device indicates a successful rollback by setting the `appVersion` field of
the `ZInfoApp` message to the version that corresponds to the requested
snapshot (see the `config_id` and `config_version` fields of the `ZInfoSnapshot`
message). This allows the controller to confirm that the rollback was successful
and that the application instance is now running with the specified config
version. The `snapshots` field in the `ZInfoApp` message will still contain
a `ZInfoSnapshot` message for the snapshot used in the rollback. The `snap_err`
field will be empty, indicating that no errors occurred during the rollback.

##### Reporting Rollback Error

If an error occurs during the rollback process, the device reports the error by
setting the `ErrorInfo` field in the `ZInfoSnapshot` message of the
corresponding snapshot (the snapshots field in the `ZInfoApp` message will still
contain a`ZInfoSnapshot` message for the snapshot used in the rollback)

### Snapshot Deletion API

The snapshot deletion process allows the controller to request the deletion of a
specific snapshot on the device. The device then attempts to delete the
specified snapshot and reports the outcome of the deletion to the controller.

#### Controller Triggering Snapshot Deletion

The controller triggers the deletion of a snapshot by sending
an `AppInstanceConfig` message to the device with the `snapshots` field updated
to exclude the snapshot that needs to be deleted. The `snapshots` field is a
list of `SnapshotDesc` messages, each containing information about a snapshot.
The controller should remove the `SnapshotDesc` message corresponding to the
snapshot that needs to be deleted from the snapshots field.

#### Device Reporting Deletion Result

After receiving the snapshot deletion request, the device attempts to delete the
specified snapshot. The device then reports the outcome of the deletion in
the `ZInfoApp` message, which includes the `snapshots` – a list
of `ZInfoSnapshot` messages, each containing information about a snapshot.

##### Reporting Deletion Success

The device indicates a successful deletion by removing the `ZInfoSnapshot`
message corresponding to the deleted snapshot from the snapshots field in
the `ZInfoApp` message. The absence of the `ZInfoSnapshot` message for the
specified snapshot ID confirms that the snapshot has been successfully deleted.

##### Reporting Deletion Error

Due to the current implementation limitation, the device always reports
successful snapshot deletion and does not report any errors that may occur
during the snapshot deletion process. Nevertheless, the expected logic for error
reporting would be as described below.

If an error occurs during the snapshot deletion process, the device reports the
error by setting the `ErrorInfo field in the ZInfoSnapshot message of the
corresponding snapshot. The snapshots field in the ZInfoApp message will contain
a ZInfoSnapshot message for the snapshot that was attempted to be deleted. The
id field in the ZInfoSnapshot message will match the ID specified in the
deletion request, and the snap_err field will contain the error information.

##### Important Limitation

It is important to note that in the current implementation, EVE reports
successful snapshot deletion immediately after receiving the request without
waiting for the corresponding cleanup actions to be completed on the EVE side.
As a result, EVE currently cannot report any errors that may occur during the
snapshot deletion process.

## Maximum Snapshots Limit

As of now, EVE supports a maximum of only one snapshot, as set by the
controller. EVE automatically manages the number of snapshots to ensure it
doesn't exceed this limit. If a new snapshot is requested when one already
exists, EVE will delete the older snapshot to make room for the new one. This
ensures that you always have the most recent snapshot available for backup and
recovery.

## Snapshot Storage

In EVE, snapshot management is designed to be as storage-efficient as possible.
However, there are scenarios where extra storage space may be required,
particularly when dealing with purgeable volumes. This section delves into the
storage considerations you need to be aware of when working with different types
of snapshots in EVE.

### Copy-on-Write Approach

EVE uses a Copy-on-Write approach for efficient snapshot management. This
means that new snapshots don't immediately take up a lot of storage space.
Instead, they grow over time as changes are made to the system. This approach is
storage-efficient and minimizes the immediate impact on available storage
capacity.

### Handling Purgeable Volumes in EVE

Purgeable volumes in EVE have a unique characteristic: they can be entirely
replaced with new versions during a purge operation. This behavior necessitates
a different approach to snapshot management compared to non-purgeable volumes,
which typically use a Copy-on-Write (CoW) approach to minimize storage impact.

When a snapshot is created for a purgeable volume, EVE retains the entire volume
as a backup, including all the data present at the time of the snapshot. This
means that unlike non-purgeable volumes, which only store the changes (or
deltas) between the current state and the snapshot, purgeable volumes require
additional storage space equal to the entire volume.

## Future Enhancements

* Improve error handling and reporting for snapshot-related operations,
  especially on snapshot deletion.
* Integration tests automation
* Add more tests: more applications per node, rollback error handling.
