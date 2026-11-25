# Application Snapshot, Implementation Details

## Overview

This document is intended for developers and contributors to the EVE project who
are interested in the technical aspects of the snapshotting feature. It delves
into the nitty-gritty details of how the feature is implemented in the EVE
codebase. Topics covered include:

* **Data Structures**: Definitions and explanations of the key data structures
  used.
* **Flow of Operations**: Step-by-step walkthrough of the snapshot creation,
  rollback, and deletion processes.
* **Serialization and Deserialization**: How snapshot data is stored and
  retrieved, including the use of mandatory fields for version compatibility.
* **Low-Level Filesystem Operations**: How the snapshotting feature interacts
  with the filesystem to perform snapshot operations.
* **Error Handling**: How errors are handled and reported during snapshot
  operations.
* **Testing**: How the snapshotting feature is tested, including unit tests and
  integration tests.

This document assumes that the reader is familiar with the general functionality
and API of the snapshotting feature, as described in the Feature API Document in
[docs/APP-SNAPSHOT.md](../../../docs/APP-SNAPSHOT.md).

## EVE Agents

The snapshotting feature is implemented in several agents, including:

* **[zedagent](../cmd/zedagent)**: Parses and reports
  snapshot-related information from/to the controller.
* **[zedmanager](../cmd/zedmanager)**: Manages the application
  lifecycle, including snapshot-related operations during application
  installation, modification, and deletion.
* **[volumemgr](../cmd/volumemgr)**: Handles the creation,
  modification, and deletion of volume snapshots.
* **[utils](../utils)** Package: Contains utility functions for
  serialization and deserialization of snapshot data structures.

## Snapshot-Related Data Flow

The data flow in the system involves interactions between the controller,
zedagent, zedmanager, and volumemgr. The controller is responsible for sending
configuration updates and commands to the device. The zedagent acts as an
intermediary between the controller and the other agents on the device. It
parses the configuration updates and commands received from the controller and
forwards them to the appropriate agents. The zedmanager is responsible for
managing app instances and handling any associated requests. It interacts with
the volumemgr, which manages volumes and handles volume-related requests. The
agents process the requests and send status updates back to the zedagent, which
reports the updated status back to the controller.

1. **Controller to Zedagent**: The controller sends requests to the zedagent,
   which can include requests for snapshot creation, rollback, or deletion, as
   well as other app instance-related requests. The zedagent is responsible for
   parsing these requests and passing the relevant information to the
   zedmanager.
    * [cmd/zedagent/parseconfig.go](../cmd/zedagent/parseconfig.go)
2. **Zedagent to Zedmanager**: The zedagent passes the parsed app instance
   config and any associated requests to the zedmanager. The zedmanager is
   responsible for managing app instances and handling any associated requests,
   including those related to snapshots.
    * [cmd/zedagent/parseconfig.go](../cmd/zedagent/parseconfig.go)
3. **Zedmanager: App Lifecycle And Actions Triggering** \
   The zedmanager processes the requests and updates the `AppInstanceStatus`,
   which includes the `SnapshottingStatus`. The `SnapshottingStatus` contains
   the list of the snapshots of the application and other snapshot-related
   information. The zedmanager handles the
   requests by initiating the appropriate processes, such as the purge process
   for snapshot creation or the rollback process for snapshot rollback.
    * [cmd/zedmanager/zedmanager.go](../cmd/zedmanager/zedmanager.go)
    * [cmd/zedmanager/updatestatus.go](../cmd/zedmanager/updatestatus.go)
4. **Zedmanager to Volumemgr**: For every snapshot that is to exist, the
   zedmanager publishes a VolumesSnapshotConfig to the volumemgr. This config
   includes the snapshot ID, the volume IDs, the app UUID and a rollback
   count. The volumemgr is responsible for managing volumes and handling
   volume-related requests, including those related to snapshots.
    * [cmd/zedmanager/updatestatus.go](../cmd/zedmanager/updatestatus.go)
    * [cmd/zedmanager/handlevolumemgr.go](../cmd/zedmanager/handlevolumemgr.go)
    * [cmd/volumemgr/volumemgr.go](../cmd/volumemgr/volumemgr.go)
5. **Volumemgr**: The volumemgr compares the `VolumesSnapshotConfig` with what
   it has, and creates, rolls back to or deletes the snapshot accordingly. It
   interacts with the file system (FS)-specific handlers to do that and stores
   the relevant information in the VolumesSnapshotStatus.
    * [cmd/volumemgr/handlesnapshot.go](../cmd/volumemgr/handlesnapshot.go)
    * [volumehandlers](../volumehandlers)
    * [diskmetrics/diskmetrics.go](../diskmetrics/diskmetrics.go)
6. **Volumemgr to Zedmanager**: The volumemgr publishes a VolumesSnapshotStatus
   for every snapshot it knows. This status includes information about the
   snapshot, such as the snapshot ID, metadata, time created, app UUID, the
   state, and error information.
    * [cmd/volumemgr/handlesnapshot.go](../cmd/volumemgr/handlesnapshot.go)
7. **Zedmanager: Reaction** \
   The zedmanager receives the VolumesSnapshotStatus from the volumemgr and
   updates the SnapshottingStatus in the AppInstanceStatus. It handles any
   further actions based on the updated status and reports the updated status
   back to the zedagent.
    * [cmd/zedmanager/handlevolumemgr.go](../cmd/zedmanager/handlevolumemgr.go)
    * [cmd/zedmanager/updatestatus.go](../cmd/zedmanager/updatestatus.go)
8. **Zedagent to Controller**: The zedagent receives the updated
   AppInstanceStatus from the zedmanager and reports the updated status,
   including the SnapshottingStatus, back to the controller.
    * [cmd/zedagent/handlemetrics.go](../cmd/zedagent/handlemetrics.go)

This data flow ensures that the requests from the controller are processed and
handled by the appropriate agents and that the controller is informed of the
updated status of the app instance and any associated snapshots. The stored
information in the VolumesSnapshotStatus and SnapshottingStatus can be used for
future operations related to app instances and snapshots.

## Snapshot Data Structures

The snapshot creation process relies on several data structures to manage and
track the status of snapshots for each application instance. These data
structures are part of the `AppInstanceStatus` and are used
to handle snapshot requests, creation, deletion, and rollback.

### SnapshottingStatus

This is the main data structure that manages and tracks all snapshot-related
activities for an app instance. It is included in the AppInstanceStatus
structure. Its `Snapshots` field lists the snapshots of the app instance, which
is what zedagent reports to the controller. It also includes fields that track
the state of snapshot-related actions, such as PreparedVolumesSnapshotConfigs,
SnapshotTakenType, HasRollbackRequest, ActiveSnapshot, and RollbackInProgress.

zedmanager does not decide anything by the `Snapshots` list. It rebuilds the
list from what volumemgr publishes, see
[How Zedmanager Knows the Snapshots](#how-zedmanager-knows-the-snapshots).

Defined
in [types/zedmanagertypes.go](../types/zedmanagertypes.go).

### SnapshotInstanceStatus

This structure represents the status of a snapshot instance at the zedmanager
level. It contains information about the snapshot, such as its ID, type, and
creation time. It also includes fields for tracking the app instance and config
version associated with the snapshot, as well as any errors that may have
occurred during snapshot operations.

This struct is serialized and stored to ensure its persistence across device
restarts. As a result, special care should be taken when updating the struct
definition in future EVE releases. Fields marked with the `mandatory:"true"` tag
are essential and must be present in all versions of the struct to ensure
backward compatibility.

Defined
in [types/zedmanagertypes.go](../types/zedmanagertypes.go).

### SnapshotDesc

This is a concise representation of a snapshot, containing only the essential
information needed to identify the snapshot and its type. It includes the
SnapshotID and SnapshotType fields. This structure is used when we may not have
all the information required to fully populate the SnapshotInstanceStatus
structure, but we still need to identify the snapshot and its type.

Defined
in [types/zedmanagertypes.go](../types/zedmanagertypes.go).

### VolumesSnapshotConfig

With this structure zedmanager tells volumemgr that a snapshot is to exist. It
does not ask for an action. Volumemgr compares it with the
`VolumesSnapshotStatus` of the snapshot and does what is missing:

* a config without a status: the snapshot is created;
* a status without a config: the snapshot is deleted;
* a config with a higher `RollbackCount` than the status: the volumes are
  rolled back to the snapshot.

Its fields are SnapshotID, VolumeIDs, AppUUID, RollbackCount, SnapshotType and
ConfigVersion. `VolumeIDs` are the volumes to take the snapshot of.
`SnapshotType` and `ConfigVersion` describe the snapshot; zedmanager saves them
in its own record once the snapshot exists.

Defined
in [types/volumetypes.go](../types/volumetypes.go).

### VolumesSnapshotStatus

This structure is what volumemgr reports of a snapshot to zedmanager. Its
fields are SnapshotID, VolumeSnapshotMeta, TimeCreated, AppUUID, State,
RollbackCount, RollbackCountKnown and ErrorAndTimeWithSource. The states and
the error are described in
[Volumemgr Worker and Snapshot State](#volumemgr-worker-and-snapshot-state).
The zedmanager uses this information to update the SnapshottingStatus structure
in the AppInstanceStatus structure.

Volumemgr saves every status that it publishes as the record of the snapshot,
to have it after a device restart. As a result, special care should be taken
when updating the struct definition in future EVE releases. Fields marked with
the `mandatory:"true"` tag are essential and must be present in all versions of
the struct to ensure backward compatibility.

Defined
in [types/volumetypes.go](../types/volumetypes.go).

## EVE internals of Snapshot Management

### How Zedmanager Knows the Snapshots

zedmanager keeps no lists of snapshots to take, to keep or to delete. What it
does with a snapshot follows from three things that are published anyway:

* the app instance config, which lists the snapshots that the controller wants;
* the `VolumesSnapshotStatus` of volumemgr, one per snapshot that volumemgr
  knows. It carries the state and the error, see
  [Volumemgr Worker and Snapshot State](#volumemgr-worker-and-snapshot-state);
* the `VolumesSnapshotConfig`, which zedmanager publishes for a snapshot that
  is to exist.

| Config lists it | Status | What zedmanager does |
|-----------------|--------|----------------------|
| yes | none | publishes the `VolumesSnapshotConfig` when the application is down (`pendingSnapshots`, `triggerSnapshots`) |
| yes | any | keeps the `VolumesSnapshotConfig`; a creation that failed is not tried again |
| no | any but `Deleting` | takes the `VolumesSnapshotConfig` away when the application is down (`snapshotsToDelete`, `triggerSnapshotDeletion`) |
| either | `Deleting` | nothing: volumemgr is deleting the snapshot |

The functions are in [snapshots.go](../cmd/zedmanager/snapshots.go).

Neither the statuses nor the configs are kept across a reboot, but volumemgr
saves a record of every snapshot. At boot `restoreVolumesSnapshotStatuses`
publishes a status for each record and then signals that the publication is
complete. At that point volumemgr has the snapshots and zedmanager has
published no config yet, so a missing config cannot mean that a snapshot is to
be deleted. When zedmanager gets the signal, `restoreSnapshotConfigs` publishes
a config for every snapshot that is not being deleted, also for one that the
app config does not list and for one whose application has no config yet, and
zedmanager signals in turn that these are all. Only from then on does volumemgr
delete a snapshot that has no config. This is the restart signal of pubsub,
which zedagent uses in the same way for the app instance configs and the volume
configs.

Until zedmanager got the signal of volumemgr (`snapshotsRestored`), it takes no
snapshot for missing, asks for no deletion and does not start an application:
a rollback may have been cut off, or a deletion may be due.

A config that was saved before a snapshot was created does not list that
snapshot. So zedmanager deletes a snapshot for not being listed only after
zedagent got a config from the controller (`configFromController`).

`refreshSnapshots` builds the `Snapshots` list of the `SnapshottingStatus`
from the statuses. A snapshot that is still being created is not on it, as the
controller would take it for created. A snapshot whose creation, rollback or
deletion failed is on it with the error, as the controller waits for that
outcome. The type and the config version of a snapshot come from the
`SnapshotInstanceStatus` record that zedmanager saves when the snapshot is
created, or from the `VolumesSnapshotConfig` while there is no record.

A snapshot that is to be deleted stays on the list until volumemgr has
deleted it, which can be as late as the next time the application stops.

The controller takes a snapshot that is missing from the report for deleted.
At boot an app is reported before volumemgr has published its snapshots, so
until then `refreshSnapshots` takes the list from the records on disk
(`snapshotsFromRecords`): the `SnapshotInstanceStatus` of zedmanager for a
snapshot that was created, and the record of volumemgr for the error of an
action that failed, which includes a creation that zedmanager has no record
of.

### Snapshot Creation Process

The snapshot creation process in EVE involves several steps and interactions
between different agents. Here's a detailed explanation of how the process works
internally.

#### Zedmanager Initial Handling, creation

1. **Detecting a New Snapshot Request**: The process begins in the handleModify
   function in zedmanager, where EVE detects a new request for a snapshot that
   comes with the app configuration from the controller (already parsed by
   zedagent). This is done within the updateSnapshotsInAIStatus function. If a
   new snapshot is detected, EVE sets the state of the application so that the
   next time it will be purged, it will also create a snapshot.
2. **Preparing for Snapshot Creation**: Since a snapshot can only be initiated
   post the application stoppage, and the volumes list within the configuration
   might have already been modified by the time of application termination,
   leading to inconsistencies, EVE prepares the volumesSnapshotConfig with the
   volumes list that was used when the snapshot was requested. This is done in
   the prepareVolumesSnapshotConfigs function.
3. **Storing the App Instance Config**: After preparing the messages to the
   volumemgr, EVE stores the app instance config. This is done in the
   saveAppInstanceConfigForSnapshot function, where the config is serialized and
   stored in a file. This is necessary so that EVE can use it to roll back to
   the previous version if the upgrade fails.
4. **Waiting for App Deactivation**: After the above steps, EVE is ready to
   trigger snapshot creation at a lower level, but it has to wait until the app
   is deactivated. The deactivation of the app happens as a result of the purge
   command handling. Zedmanager "catches" an event of the app deactivation by
   handling a status message from the domain manager. The functions involved in
   this process are handleDomainStatusImpl, updateAIStatusUUID, and
   removeAIStatus.
5. **Triggering Snapshot Creation**: Within the removeAIStatus function,
   zedmanager understands that it is now reacting to domain deactivation. In the
   case where there is a pending snapshot request, zedmanager triggers a message
   to volumemgr. This is done in the triggerSnapshots function, which publishes
   the prepared VolumeSnapshotConfigs and empties the list. The app instance
   status is then published.

#### Volumemgr Reaction, creation

Volumemgr is not told which action to perform. The handlers of the
`VolumesSnapshotConfig` call `reconcileSnapshot` for the snapshot, which
compares the config with the status in `snapshotActionNeeded` and starts what
is missing. For a config without a status that is the creation.

1. **Publishing the Status**: `reconcileSnapshot` publishes a new
   `VolumesSnapshotStatus` in the state `Creating`, with an empty
   `VolumeSnapshotMeta` map. From it zedmanager sees that the config was taken
   up.
2. **Looking Up Volume Status and Getting the Volume Handler**: For each volume
   ID in the VolumeIDs of the `VolumesSnapshotConfig`, `snapshotVolumes` looks
   up the corresponding volume status. If the volume status is not found, the
   creation fails. The volume handler for
   the volume status is obtained in the worker (see below) using the
   `GetVolumeHandler` function. The
   volume handler is an abstraction that helps to call handlers for any
   filesystem-related action specific to a given filesystem. Currently, only the
   handlers (snapshot ones) for ext4 are implemented.
3. **Creating the Volume Snapshot**: In a worker (see below), the
   `CreateSnapshot` method of the volume handler is called to create a snapshot
   of the volume. This method returns the
   snapshot metadata, the time the snapshot was created, and any error that
   occurred during the snapshot creation.
4. **Storing Snapshot Metadata**: The snapshot metadata is saved in
   the `VolumeSnapshotMeta` map of the `VolumesSnapshotStatus` with the volume
   ID as the key. The time the snapshot was created is also saved in
   the `VolumesSnapshotStatus`. In the case of the ext4 implementation, the
   snapshot metadata is the snapshot name.
5. **Publishing and Saving the Snapshot Status**: `finishSnapshotAction` sets
   the state `Created` and publishes the status, which tells zedmanager that
   the snapshot exists. `publishVolumesSnapshotStatus` saves every status that
   it publishes with `serializeVolumesSnapshotStatus`. That record is what is
   known of the snapshot after a reboot. If the record of a snapshot that was
   just created cannot be saved, the creation counts as failed.
6. **Failure**: A creation that failed leaves the status in the state
   `Creating` with the error. It is not tried again, and is deleted when
   zedmanager takes the config away.

#### Volumemgr Worker and Snapshot State

Creating, rolling back to and deleting a snapshot can take long, so volumemgr
does not run them in its main loop. It keeps a `State` in the
`VolumesSnapshotStatus`:

| State | Meaning |
|-------|---------|
| `Creating` | the snapshot is being created, which includes waiting for a worker |
| `Created` | all volumes have the snapshot, and nothing is being done to it |
| `RollingBack` | the volumes are being rolled back to the snapshot |
| `Deleting` | the snapshot is being deleted. It does not leave this state any more |

A state other than `Created` says what volumemgr does with the snapshot. When
that has worked, the snapshot is `Created` again, or gone after a deletion.
When it fails, the snapshot stays in the state and the error of the status is
set: `Creating` with an error is a creation that failed. The `Busy` method of
the status tells the two apart.

`snapshotActionNeeded` decides what is to be done to a snapshot:

| Config | Status | Action |
|--------|--------|--------|
| present | none | create |
| none | any | delete; a creation that waits for a worker is just dropped |
| `RollbackCount` higher than in the status | `Created`, or `RollingBack` with an error | roll back |
| present | `Creating` or `RollingBack` without an error | start it: it waited, or a reboot cut it off |
| any | `Deleting` without an error | go on deleting |
| any | any with an error | nothing |

An action that failed is not repeated by itself. A creation is never tried
again. A rollback is tried again when zedmanager asks for it with a higher
`RollbackCount`. A deletion is tried again by `retrySnapshotDeletions` when
volumemgr starts another action on a snapshot of the same application, and
after a boot. Volumemgr cannot tell whether an application is down, which a
deletion needs, but it is down at these two points. The deletions that are
tried again run before the action that sets them off: zedmanager starts the
application when that action is over. A volume whose deletion failed is
treated alike: it stays published with its error and is tried again.

The status takes the `RollbackCount` of the config when volumemgr takes up the
rollback. The rollback is over when the state is `Created` again, and has
failed when the error is set.

`reconcileSnapshot` publishes the status in its new state and
`startSnapshotAction` hands the work to the common worker pool. The worker
function `snapshotWorker` calls the volume handlers, and `processSnapshotResult`
publishes the outcome back in the main loop with `finishSnapshotAction`. It
then calls `reconcileSnapshot` again, as the config can have changed while the
worker was busy.

* A state without an error covers the wait as well. Only one snapshot action
  runs per application at a time, as they need the same disk images, the pool
  can be full, and after a boot the volumes are not there before zedagent has
  published them. `driveSnapshots` starts what waits when a job of the pool
  finishes, and periodically from the main loop.
* A snapshot knows its volumes by their UUID. A purge has two generations of
  a volume for a while, and `lookupSnapshotVolume` takes the one that has an
  image.
* A volume that is gone or has no image cannot be rolled back and makes a
  creation fail. For a deletion it counts as done: the snapshot went with the
  image. Such a volume is not waited for, as zedmanager does not ask for it
  while a snapshot of the application is busy. A volume that volumemgr could
  not take up because of an error may still have its image, so any action on
  it fails and a deletion keeps what it knows of the snapshot.
* A creation that fails on one volume deletes what the other volumes got.
  A rollback that fails half way cannot be undone; its error says how many
  volumes are rolled back.

`publishVolumesSnapshotStatus` saves every status as the record of the
snapshot, and `unpublishVolumesSnapshotStatus` removes the record with the
status. So the record says what volumemgr was doing when the device went down.
At boot `restoreSnapshotState` turns each record into the status to start with:

* `Created` is published as it was saved.
* `Creating` or `RollingBack` with an error is published as it was saved, so a
  creation or rollback that failed is still known as failed, and with
  `Verifying` set. The action can have left an image that cannot be used, and
  the error that kept the application off it is gone with the reboot. So
  volumemgr checks the images of the snapshot again, see
  [Time Limit, Repair and Check for ext4](#time-limit-repair-and-check-for-ext4),
  and the status counts as busy until that is done. The failed action is not
  run again.
* `RollingBack` without an error is a rollback that the reboot cut off. It goes
  on once zedmanager has published the config of the snapshot again.
* `Deleting` is a deletion that was cut off or that failed. It is tried again,
  and is published without the error so that zedmanager keeps the application
  down for it.
* `Creating` without an error is a creation that was cut off. What the volumes
  got of it is not known, so it is published as failed.
* A record without a state was saved by an older version, for a snapshot that
  was created. It is published as `Created`, with `RollbackCountKnown` not
  set.

#### Zedmanager Reaction, creation

1. **Receiving the Snapshot Status**: When zedmanager receives a
   `volumesSnapshotStatus` message, it calls the
   `handleVolumesSnapshotStatusImpl` function, which looks up the
   `AppInstanceStatus` of the `AppUUID`. A status that ends a rollback is
   handled by `reactToSnapshotRollback`.
2. **Keeping the Record**: For a snapshot in the state `Created` that has no
   record yet, `keepSnapshotRecord` saves a `SnapshotInstanceStatus` with the
   type and the config version from the `VolumesSnapshotConfig` and the
   creation time from the status. The config is gone after a reboot, the
   record is not.
3. **Updating the List**: `refreshSnapshots` rebuilds the `Snapshots` list. A
   snapshot whose creation failed is on it with its error. Its status stays for
   as long as the config lists the snapshot, and the creation is not tried
   again.
4. **Publishing AppInstanceStatus and Going On**: The `AppInstanceStatus` is
   published, and `updateAIStatusUUID` takes the application up again.
5. **Zedagent Handling**: Zedagent reports the `Snapshots` list to the
   controller. A failed snapshot is reported with its error, so that the
   controller learns that the creation failed.

### Snapshot Rollback Process

#### Local Application Instance Config

During the rollback process, zedmanager needs to ensure that it uses the correct
version of the app instance config. This is crucial because the rollback is
intended to revert the app instance to a specific state that existed at the time
the snapshot was taken. Using the config just arrived from the controller, which
may not contain the necessary version or fixups, could result in inconsistencies
or errors in the rollback process.

To achieve this, zedmanager uses a local app instance config, which is a copy of
the app instance config that was in use at the time the snapshot was taken. This
local config is stored on the device and has a higher priority than the regular
app instance config received from the controller. Zedmanager always checks the
local config first, ensuring that it uses the correct version of the config
during the rollback process. The local config contains the version of the config
to which the rollback is happening, along with any necessary fixups or
adjustments that may be required for a successful rollback.

The local app instance config is serialized and stored in persistent storage
(`/persist/snapshots` directory). This ensures that the system can handle device
restarts at any point during the snapshot and rollback processes, maintaining
data integrity and operational consistency.

#### Zedmanager Initial Handling, rollback

1. **Detecting a Rollback Request**: The process begins in the `handleModify`
   function in zedmanager, where EVE detects a new request for a snapshot
   rollback by analyzing the `RollbackCmd.Counter` field in the `Snapshot`
   section of the app instance config. If a rollback request is detected, EVE
   sets the state of the application to initiate a rollback to the specified
   snapshot.
2. **Restoring App Instance Config**: EVE restores the app instance config from
   the snapshot by calling the `restoreAppInstanceConfigFromSnapshot` function.
   This function checks that the snapshot is on the `Snapshots` list and
   restores the app instance config from the snapshot.
   The `deserializeAppInstanceConfigFromSnapshot` function is used to read the
   app instance config from the snapshot file.
3. **Fixing Up App Instance Config**: The `fixupAppInstanceConfig` function is
   called to add fixes to the restored app instance config. The fixes are the
   information that should be taken from the current app instance config, not
   from the snapshot. This function syncs the information about available
   snapshots, restores the restart and purge command counters, and updates the
   app instance config with the fixes. It is important to note that the fixes
   applied here should correspond to the fixes done on the controller side.
4. **Removing Unused Volume Ref Statuses**: The `removeUnusedVolumeRefStatuses`
   function is called to remove the volume ref statuses that are not in the
   snapshot. This is necessary to replace the volumes properly, as the list
   updated in this function is used later by the domain manager to create a VM
   config file.
5. **Switching to Restored Config**: The line  \
   `config = *snappedAppInstanceConfig` \
   indicates that EVE should not use the config received from the controller but
   instead work with the restored config. The `publishLocalAppInstanceConfig`
   function is called to publish the restored config to a dedicated pubsub. This
   pubsub is always checked first by zedmanager to see if there is a local copy
   of the config with higher priority than the one from the controller.
6. **Restarting the Process**: After publishing the local app config,
   the `handleModify` function returns, as the process needs to be restarted
   with the new config. The restart is done from
   the `handleLocalAppInstanceConfigCreate` handler, which is called immediately
   after the local config is published. Now, the `handleModify` function is
   called again with the restored and fixed-up config. This time in
   the `handleModify` function, the condition that previously triggered the
   start of the rollback request handling will be false due to the fixups, and
   the process continues.
7. **Marking the Application for Purge**: Later in the same `handleModify`
   function, EVE checks the `needPurge` flag and the `HasRollbackRequest` flag.
   The `needPurge` flag is returned as true after the `quantifyChanges` function
   due to the fact that the list of volumes has been previously changed (either
   by an explicit purge command or by replacing a volume with a new version as a
   result of an app upgrade). And the `hasRollbackRequst` is set to true on step
   one. So, both flags are true, and EVE marks the application for purge. This is
   necessary because the application needs to be inactive in order to replace
   the volumes, and such volume replacement is technically equivalent to an
   application purge.
8. **Waiting for App Deactivation**: After marking the application for purge,
   zedmanager waits for the application to be deactivated. The detection of the
   application deactivation is done in the `doUpdate` function, which is called
   as part of the process that handles status changes from the domain manager.
   An application that has no `DomainStatus`, because it was not started since
   boot, counts as deactivated unless zedmanager has activated it or is
   activating it.
9. **Triggering Rollback**: The `triggerRollback` function asks volumemgr for
   the rollback by raising the `RollbackCount` in the `VolumesSnapshotConfig`
   of the active snapshot above the count of its status. The count is the
   `RollbackCmd.Counter` of the request, or one more than the count of the
   status if that is not higher: a controller can use a counter again. If the
   snapshot is not one that can be rolled back to, because it is gone, its
   creation failed or it is being deleted, the rollback ends here and the
   application goes on with the config from the controller. `startRollback`
   refuses such a snapshot already when the request comes in.

#### Volumemgr Reaction, rollback

1. **Taking Up the Rollback**: `reconcileSnapshot` finds a config with a higher
   `RollbackCount` than the status of a snapshot that is `Created`, or
   `RollingBack` with the error of an earlier attempt. It sets the state
   `RollingBack`, takes over the count, clears the error and publishes the
   status. From it zedmanager sees that the rollback was taken up. The status
   is saved as the record, so a reboot from here on finds a rollback that was
   cut off.
2. **Getting the Volume Handler**: For each volume in the `VolumeSnapshotMeta`
   of the `volumesSnapshotStatus`, the function retrieves the
   corresponding `volumeStatus` using the `lookupVolumeStatusByUUID` function.
   If the `volumeStatus` is not found, the rollback fails. The volume status
   is used in the worker to get
   the proper volume handler that keeps the low-level FS-specific handlers for
   the volume operations.
3. **Rolling Back the Volume Snapshot**: In a worker, the `RollbackToSnapshot`
   method of the volume handler is called with the snapshot metadata
   (`snapMeta`) to perform the rollback. The worker stops at the first volume
   that fails.
4. **Publishing the Snapshot Status**: If the rollback worked,
   `finishSnapshotAction` publishes the status in the state `Created`. If it
   failed, the status stays `RollingBack` with the error. Either way it keeps
   the count, which tells zedmanager that this is the answer to its request.

A config with a higher count for a snapshot in the state `Creating` or
`Deleting` is left alone: not all volumes have such a snapshot.

#### Zedmanager Reaction, rollback

1. **Receiving the Snapshot Status and Handling Snapshot Rollback**: When
   zedmanager receives a `volumesSnapshotStatus` message, it calls
   the `handleVolumesSnapshotStatusImpl` function. If the application is in a
   rollback that zedmanager has asked volumemgr for (`RollbackInProgress` is
   set and `HasRollbackRequest` is not), the status is of the active snapshot,
   and `rollbackAnswered` says that volumemgr is through with it, the
   `reactToSnapshotRollback` function is called. Volumemgr is through when the
   `RollbackCount` of the status has reached that of the config and the status
   is not busy.
2. **Looking Up AppInstanceStatus**: The `reactToSnapshotRollback` function
   begins by looking up the `AppInstanceStatus` object associated with
   the `AppUUID` field of the `volumesSnapshotStatus` object. If
   the `AppInstanceStatus` object is not found, an error is logged, and the
   function returns. The `AppInstanceStatus` object is necessary for updating
   the status of the snapshot, which is done in the next step.
3. **Handling Errors**: If the `volumesSnapshotStatus` object has an error (as
   indicated by the `HasError` function), the function logs the error.
   `refreshSnapshots` puts it on the snapshot in the `Snapshots` list. The
   application itself gets no error. A successful rollback leaves a status
   without an error, so the error of the snapshot is gone as well.
4. **Rollback Completion**: Whether the rollback worked or failed, the function
   sets the `RollbackInProgress` field of the `SnapStatus` field of
   the `AppInstanceStatus` object to false and unpublishes the local app
   instance config: any subsequent operations should use the latest app
   instance config received from the controller. The `AppInstanceStatus` object
   is then published. After a failure the application goes on with the volumes
   as they are. If the app instance config was deleted meanwhile, the function
   calls `removeAIStatus` to finish the removal of the application. Otherwise
   it calls `doUpdate` to start the application again and publishes what that
   changed.
5. **Zedagent Handling**: After the publication of the AppInstanceStatus, the
   updated status is sent to zedagent. Zedagent then parses the list of
   snapshots in the AppInstanceStatus and forms a reply to the
   controller with the updated snapshot information. This allows the controller
   to be aware of the current state of the snapshots on the device.

#### Reporting Successful Rollback to the Controller

Successful rollback is reported back to the controller in an app instance status
that includes the version of the app instance config that corresponds to the
snapshotted config version used during the rollback.

The process of setting up the version in the app instance status happens in
the `doUpdate` function. This function is responsible for updating the app
instance status with the appropriate version information that matches the
snapshotted config version used in the rollback.

Once the version is set in the app instance status, zedmanager sends the updated
app instance status back to the controller. The very first app instance status
report sent to the controller that contains the version corresponding to the
snapshotted config version serves as an indication of a successful rollback. The
controller receives this report and becomes aware of the successful rollback and
the current state of the app instance on the device.

#### Rollback and Reboot

`handleModify` sees a rollback request as a `RollbackCmd.Counter` that is
higher than in the config before. After a reboot there is no config before.
What tells then is the status of the snapshot, which volumemgr restores from
its record with the `RollbackCount` of the last rollback that it took up.

* **Volumemgr had taken up the rollback.** Its record is in the state
  `RollingBack` without an error, and volumemgr goes on with the rollback once
  zedmanager has published the config of the snapshot again and the volumes
  are there. zedmanager only keeps the application down meanwhile.
* **Volumemgr never got the rollback**, as the device went down between the
  request of the controller and the application being down. `rollbackLeftOver`
  compares the counter of the app config with the `RollbackCount` of the
  status of its `ActiveSnapshot`. If the config has the higher one,
  `askForRollbackLeftOver` raises the `RollbackCount` of the
  `VolumesSnapshotConfig`. That is done from `restoreSnapshotConfigs` or from
  `handleCreateAppInstanceStatus`, whichever comes when both the app config
  and the status are there, and before the application is started.

In both cases the application then starts on the config from the controller:
the local app instance config is not published again after a reboot.

A rollback that was cut off is therefore run again. That is safe, as applying
the same snapshot twice gives the same volumes. A rollback that failed has its
count in the status and is not repeated, and its error is still reported.

A record that an older version saved has no count (`RollbackCountKnown` is
not set). The config can name such a snapshot with the counter of a rollback
that was done long ago, so nothing is rolled back for it. It gets a count with
the next rollback to it.

### Snapshot Deletion Process

#### Zedmanager Initial Handling, deletion

1. **Identifying Snapshots for Deletion**: `snapshotsToDelete` returns the
   snapshots that exist and have to go: those that the config does not list.
   A config that lists more snapshots than the limit is left out (see
   [Ensuring Maximum Snapshots Limit](#ensuring-maximum-snapshots-limit)).
   Nothing is stored for this. A config that lists the snapshot again before
   it was deleted keeps it.
2. **Wait For Deferred Deactivation**: Snapshot removal requires the VM to be
   down, and zedmanager does not bring it down for that. The deletion waits for
   the next app deactivation:

    1. **Regular App Reactivation**: In the `doUpdate` function, zedmanager
       checks if the VM is already shut down. If it is, it triggers the
       deletion.
    2. **Handling of Purge**: In the removeAIStatus function, zedmanager handles
       the case where an app is deactivated due to a purge command. It triggers
       the deletion first, to ensure compliance with the maximum limit of
       snapshots, and then the creation of the prepared snapshots.

   In both cases, the `triggerSnapshotDeletion` function is called.
3. **Asking Volumemgr**: For each snapshot to be deleted,
   `triggerSnapshotDeletion` takes its `VolumesSnapshotConfig` away. That is
   all zedmanager does: a deletion that failed is tried again by volumemgr.

#### Volumemgr Reaction, deletion

1. **Taking Up the Deletion**: `reconcileSnapshot` finds a status without a
   config, and publishes it in the state `Deleting`. The status is saved as the
   record, so the snapshot is not whole again after a reboot. A creation that
   still waits for a worker is dropped instead: there is nothing to delete.
2. **Iterating Over Volumes and Retrieving Volume Handlers**: The volumes of
   the snapshot are those in the `VolumeSnapshotMeta` field of the
   `VolumesSnapshotStatus`. For each volume, the function looks up the
   `VolumeStatus`, from which the worker retrieves the volume handler. A
   volume that is gone has nothing to delete.
3. **Deleting the Snapshot for Each Volume**: In a worker, the
   `DeleteSnapshot` method of the volume handler is called. If an error occurs,
   it is set in the `VolumesSnapshotStatus` and the worker goes on with the
   remaining volumes. A volume that lost the snapshot is taken out of the
   `VolumeSnapshotMeta`.
4. **Answering**: If the deletion worked, `finishSnapshotAction` removes the
   record of the snapshot and unpublishes the `VolumesSnapshotStatus`: a
   snapshot that is deleted has no status. If the deletion failed, the status
   stays in the state `Deleting` with the error, and volumemgr tries again
   later, see
   [Volumemgr Worker and Snapshot State](#volumemgr-worker-and-snapshot-state).

A snapshot in the state `Deleting` does not come back. A config that
zedmanager publishes for it again changes nothing.

#### Zedmanager Reaction, deletion

1. **Snapshot Is Gone**: `handleVolumesSnapshotStatusDelete` is called when
   volumemgr takes the status away. It
   deletes the snapshot directory with `DeleteSnapshotFiles`, rebuilds the
   `Snapshots` list, publishes the `AppInstanceStatus` and calls
   `updateAIStatusUUID`.
2. **Deletion Failed**: `handleVolumesSnapshotStatusImpl` gets the status with
   the error. `refreshSnapshots` puts the error on the snapshot, which stays on
   the `Snapshots` list and is reported to the controller. The application
   goes on.

#### Uninstalling the Application

The snapshots of an application go with it, whatever volumemgr is doing with
them at that moment. `doUninstall` first takes the `VolumeRefConfig`s away.
When volumemgr has unpublished the `VolumeRefStatus` of each, it has let go of
the volumes, and `doUninstall` takes the `VolumesSnapshotConfig`s of the
application away.

To volumemgr these are snapshots to delete, but a volume that is being
destroyed takes its snapshots along: nothing is done to its image, and the
status and the record are removed. A volume that a worker has in use for a
snapshot is not destroyed under it. `deferDestroyForSnapshot` holds the
destruction back until the worker returns, and the outcome of that action is
dropped with the snapshot.

### Waiting for Volumemgr

zedmanager does not start the application while volumemgr works on one of its
snapshots, as `qemu-img` needs the disk images to itself. The
`snapshotOpInProgress` function tells this from what is published:

* volumemgr has not yet told which snapshots exist after a boot;
* a `VolumesSnapshotConfig` without a `VolumesSnapshotStatus`: volumemgr has
  not taken up the creation yet;
* a `VolumesSnapshotConfig` with a higher `RollbackCount` than the status of a
  snapshot that can be rolled back to: volumemgr has not taken up the rollback
  yet;
* a `VolumesSnapshotStatus` without a `VolumesSnapshotConfig` that is not in
  the state `Deleting`: volumemgr has not taken up the deletion yet;
* a `VolumesSnapshotStatus` that is busy, which is a state other than `Created`
  without an error;
* the error of a status that names a volume whose `VolumeRefStatus` does not
  show an error yet, see
  [Time Limit, Repair and Check for ext4](#time-limit-repair-and-check-for-ext4).

An action that failed leaves the snapshot in its state with the error. That
does not hold the application back.

In these cases `doUpdate` does not activate the application, and a purge does not
go on from bringing the application down to recreating its volumes. The answer
from volumemgr takes the application up again: `handleVolumesSnapshotStatusImpl`
and `handleVolumesSnapshotStatusDelete` call `updateAIStatusUUID`.

## Low-Level Snapshot Management for ext4

In EVE, managing snapshots for ext4 file systems involves interactions with the
application lifecycle and low-level operations using the `qemu-img` tool. Due to
the nature of disk image snapshots, certain operations can only be performed
when the application is not actively using the volume. This section explains how
EVE handles snapshot operations in conjunction with the application lifecycle
and the low-level details of snapshot management.

### Snapshot Creation for ext4

When creating a new snapshot, EVE must stop the application to ensure that the
volume is not in use. The need to stop the application arises from the fact that
the snapshot request is now triggered during the handling of a purge command,
and an application reboot is part of this handling process. After stopping the
application, EVE performs the snapshot operation using the qemu-img tool with
the command

```bash
qemu-img snapshot -c snapshot_name /path/to/base_image.qcow2
```

The tool creates the snapshot implicitly, and the associated files are not
exposed to EVE. EVE operates only with the snapshot IDs and stores them as
metadata. Once the snapshot operation is complete, EVE explicitly reactivates
the application. This process ensures that the snapshot is created in a
consistent and safe manner.

### Snapshot Rollback for ext4

Similar to snapshot creation, performing a rollback to a previous snapshot
requires stopping the application. But in this case, EVE triggers it explicitly.
EVE uses the qemu-img tool with the command

```bash
qemu-img snapshot -a snapshot_name /path/to/base_image.qcow2
```

to apply the snapshot. After the rollback operation is complete, EVE reactivates
the application.

### Snapshot Deletion for ext4

Unlike snapshot creation and rollback, snapshot deletion does not require an
immediate application reboot. When the controller stops listing a snapshot,
the actual deletion of the snapshot and the associated files is deferred until
the next time the application is down. This approach avoids disrupting the
application's operation for snapshot deletion. EVE uses the qemu-img tool with
the command

```bash
qemu-img snapshot -d snapshot_name /path/to/base_image.qcow2
```

to delete the snapshot. The snapshot stays in the report to the controller
until it is deleted, with the error if the deletion failed.

EVE manages snapshots for ext4 file systems by coordinating snapshot operations
with the application lifecycle and performing low-level snapshot operations
using the qemu-img tool. Snapshot creation and rollback require stopping and
reactivating the application to ensure data consistency. Snapshot deletion is
deferred until the next time the application is down. This
approach allows EVE to efficiently manage snapshots while minimizing disruptions
to the application's operation.

### Time Limit, Repair and Check for ext4

Applying and deleting a snapshot release every block that differs between the
snapshot and the disk, so they take longer the more the disk has changed since
the snapshot. Creating a snapshot goes through all blocks in use. EVE gives each
`qemu-img snapshot` command one hour.

A `qemu-img` that is stopped half way leaves the image inconsistent: writes to
it can then corrupt its snapshots. After a failed command EVE therefore repairs
the image with

```bash
qemu-img check -r all /path/to/base_image.qcow2
```

and then looks whether the command had done its part: the snapshot is there
after a creation, or gone after a deletion. If not, and always for a rollback,
the command is run once more. If EVE cannot read the list of snapshots, the
command is not repeated and counts as failed.

Whatever the outcome, the image is checked with `qemu-img check` in the end,
and repaired if the check finds something. An image is reported as not verified
if the check still finds it corrupt after the repair, or if the check cannot be
run. A check that cannot be run is tried three times, as a `qemu-img` that was
stopped can hold the lock on the image a moment longer. Leaked blocks alone
only waste space and are not an error.

The check also follows a command that worked. It is what finds an image that
an earlier `qemu-img` left damaged, for example one that a version of EVE
without the repair stopped after its two minutes. Without the check the
application would be started on such an image and damage it further. The
check reads the metadata of the image, not its data, and runs while the
application is down anyway.

An action that fails and leaves an image that passes the check puts no error
on the volume. The snapshot carries the error of the action, and the
application starts on the volumes as they are.

EVE does not start the application on an image that is reported as not
verified. Volumemgr puts the error on the `VolumeStatus` of that volume, from
where it reaches the `VolumeRefStatus` and stops zedmanager in `doInstall`, as
any other error of a volume does. The error stays on the volume whatever
happens to the snapshot. There are two ways to get rid of it:

* A later snapshot action on the volume ends with an image that passes its
  check. A rollback to a healthy snapshot is the usual one. An action that
  fails on an image which then passes the check counts as well; `diskmetrics`
  returns a `SoundImageError` for it.
* A purge replaces the volume. The error of a volume that the purge is about to
  replace does not stop the purge.

The error of the volume and the status of the snapshot reach zedmanager in two
publications, in any order. A snapshot status without an error means that the
application can start. A status with an error names the volumes of the snapshot
that have such an error, in the `ErrorEntities` of the error, and
`snapshotOpInProgress` holds the application back until the `VolumeRefStatus`
of each of them carries its error. Volumemgr removes a volume from the errors
of the other snapshots when it takes the error off the volume.

The error of the volume is not kept across a reboot, and nothing is saved to
bring it back: the image itself tells. After a boot volumemgr checks the images
of every snapshot whose creation or rollback had failed, before the
application may start, and puts the error on a volume whose image does not
pass. A deletion that had failed is tried again at boot and ends with the
same check. `restoreSnapshotState` sets this up.

## Low-Level Snapshot Management for ZFS

In the EVE project, managing snapshots for ZFS file systems is conducted through
direct interaction with the ZFS filesystem via the libzfs library. This approach
enables EVE to perform snapshot operations such as creation, rollback, and
deletion with high efficiency and reliability. Despite the fact that ZFS
supports creation and usage of snapshots while the file system is in use, we
still want to wait for the application to be inactive before performing any
snapshot operations. This is done to make the code consistent with the ext4 file
based snapshots and to avoid any potential issues that may arise from the
application's active use of the volume.

### Snapshot Creation for ZFS

For creating snapshots, EVE employs the `libzfs.DatasetSnapshot` function. This
function is instrumental in generating a snapshot of the specified ZFS volume.
The process begins with EVE generating a unique, timestamped snapshot name to
ensure distinguishability. The DatasetSnapshot function is then called with the
dataset name and the generated snapshot name. The operation's success,
including the snapshot name and timestamp, is logged for transparency and
auditability.

### Snapshot Rollback for ZFS

To roll a ZFS volume back to a previous state, EVE uses the
`libzfs.DatasetRollback` function. EVE initiates the rollback by first
identifying the specific snapshot and dataset targeted for rollback. The
`DatasetRollback` function in libzfs takes the dataset object and the snapshot
object as arguments. The process is thoroughly logged, indicating the dataset
and snapshot involved,  to ensure the operation's success is recorded.

### Snapshot Deletion for ZFS

For snapshot deletion, EVE leverages the `libzfs.DestroyDataset` function. This
step involves validating the snapshot's existence and association with the
correct volume before proceeding with deletion. Once validated, the
`DestroyDataset` function is called with the name of the snapshot to be deleted.
The deletion operation is also logged, providing a record of the action for
auditing purposes.

A deletion that a reboot cut off is tried again, see
[Volumemgr Worker and Snapshot State](#volumemgr-worker-and-snapshot-state),
and can then meet a snapshot that was destroyed already. If the dataset of the
volume is there and the snapshot is not, the snapshot counts as deleted. If the
dataset cannot be opened either, the deletion fails: ZFS not answering is no
proof that the snapshot is gone.

## Copy-on-Write (CoW) Approach

Both the qemu-img tool and ZFS utilize the Copy-on-Write (CoW) approach for
efficient snapshot management. This technique is foundational in ensuring
snapshots are created without requiring immediate additional storage space
proportional to the dataset or disk image size.

In the CoW model, when a snapshot is initiated, the system does not duplicate
the entire file system or disk image. Instead, it maintains references to the
existing data blocks. As modifications occur, new data is written to different
locations, preserving the original data blocks as they were at the snapshot's
creation time. This mechanism ensures that snapshots initially have a minimal
storage footprint, only increasing as changes accrue in the file system or disk
image over time.

## Handling Purgeable Volumes in EVE

Purgeable volumes in EVE are unique in that they can be entirely replaced with
new versions during the execution of a purge command. This behavior requires a
different approach to snapshot management compared to non-purgeable volumes.

### Snapshot Creation for Purgeable Volumes

When a snapshot is created for a purgeable volume, EVE retains the entire old
volume as a backup. This backup includes all the data in the volume at the time
of the snapshot. Unlike non-purgeable volumes, where a delta file is typically
created, purgeable volumes require the entire volume to be preserved. During the
snapshot creation, EVE retains the original volume file in its existing
location, ensuring that the old volume is preserved in its entirety.

### Rollback Operation for Purgable Volumes

In the event of a rollback to a previous snapshot, EVE restores the purgeable
volume by using the original volume file that was retained during the snapshot
creation. The process involves updating the volume ID in the domain config to
point to the original volume file, effectively restoring the volume to its state
at the time of the snapshot.

### Snapshot Deletion for Purgable Volumes

When a snapshot of a purgeable volume is deleted, EVE removes any references to
the original volume file associated with the snapshot ID.

## Serialization and Deserialization

The snapshotting feature relies on robust serialization and deserialization
functionality to ensure that the snapshots are known after the system
reboots. Volumemgr saves and removes the `VolumesSnapshotStatus` record;
zedmanager saves the `SnapshotInstanceStatus` record and the
`AppInstanceConfig`, and removes the directory of a snapshot that is deleted. The serialization process converts snapshot data structures into a
format that can be stored on disk, while deserialization restores the data
structures from the stored format.

Key Points:

* Serialization and deserialization functions have been implemented
  for `VolumesSnapshotStatus`, and `SnapshotInstanceStatus`.
* Comprehensive field checks are performed during deserialization to ensure data
  integrity.
* Critical fields essential for snapshot restoration are checked during
  deserialization.
* The `AppInstanceConfig` is stored using a simple conversion to JSON format
  without checking extra fields. This storage is necessary not only for system
  reboots but also for snapshotting the configuration.

The inclusion of AppInstanceConfig storage is important as it ensures that the
application's configuration is preserved and can be restored as part of the
snapshotting process.

### Mandatory Tag in Struct Fields

In the deserialization process, the `extractFields` function inspects the
struct's fields and checks for a mandatory tag. If a field
has `mandatory="true"`, it is considered a critical field. The absence of any
critical field in the JSON file will result in an error during the
deserialization process.

Consider the `SnapshotInstanceStatus` struct:

```go
type SnapshotInstanceStatus struct {
  Snapshot      SnapshotDesc `mandatory:"true"`
  Reported      bool
  TimeTriggered time.Time
  TimeCreated   time.Time
  AppInstanceID uuid.UUID `mandatory:"true"`
  ConfigVersion UUIDandVersion `mandatory:"true"`
  Error         ErrorDescription
}
```

In this struct, the fields `Snapshot`, `AppInstanceID`, and `ConfigVersion` are
marked as mandatory with `mandatory:"true"`. During deserialization, if any of
these fields are missing in the JSON file, an error will be triggered. This
ensures that all essential data is present before the deserialization process
completes, thereby maintaining data integrity.

The mandatory tag serves a critical role in ensuring forward and backward
compatibility between different versions of EVE. When a field in a struct is
tagged as mandatory, it signifies that this field must be present in all
serialized instances of the struct, across all versions of EVE. This is crucial
for maintaining compatibility and ensuring that deserialization will succeed
even if the struct has been modified in a newer version of EVE.

The serialized snapshot data is stored in the `/persist/snapshots` directory on
the device. This ensures that the snapshot information is preserved across
system reboots and can be easily accessed for deserialization and further
processing. The constants that define the names of the files and the directory
are located in the
[types/locationconsts.go](../types/locationconsts.go)
file.

## Ensuring Maximum Snapshots Limit

EVE ensures that the number of snapshots does not exceed the maximum limit set
by the controller:

1. A config that lists more snapshots than the limit is invalid. It is the
   controller that decides which snapshot gives way to a new one, by not
   listing it any more.
2. For such a config `pendingSnapshots` and `snapshotsToDelete` return nothing:
   no snapshot is created and none is deleted until a valid config arrives.
3. `updateSnapshotsInAIStatus` sets a warning on the app instance that says so.

EVE triggers the deletions before the creations, see
[Snapshot Deletion Process](#snapshot-deletion-process).

Currently, the controller only supports a maximum of 1 snapshot, so this
functionality is not extensively tested. However, it is designed to handle
scenarios where the maximum limit is set to a higher value.

## Error Handling

The snapshotting feature includes comprehensive error handling to ensure
robustness and reliability. Key points:

* Errors are set and propagated to the status sent to the controller.
* Error handling includes checking for missing critical fields during
  deserialization.
* Errors during rollback are reported with additional details such as time and
  severity.

## Testing

The snapshotting feature has been thoroughly tested to ensure its robustness and
reliability. It contains several types of tests.

### Unit Tests

A suite of unit tests has been introduced for the `DeserializeToStruct` function
in the utils package. The tests cover various scenarios, including simple
struct, error conditions, mandatory field logic, extra field in file, missing
non-mandatory field in file, struct with anonymous field, nested structs, array
of structs, and anonymous structs.

### Integration Tests

The snapshot integration testing in EVE is currently performed manually. Each
test case is executed step-by-step by a tester to verify the functionality of
the snapshot feature. Automation of the test cases would streamline the testing
process and enable more frequent and consistent testing.

#### Environment

The testing environment is set up with a KVM-based VM as the application
instance, which has two attached volumes: both are encrypted HDD disks, one is
purgeable, and the other is not. The EVE build used for testing supports ext4
volumes (no ZFS).

#### Test Cases

The test cases cover a wide range of scenarios, including:

* **Snapshot Creation**: Verifying the successful creation of snapshots.
* **Rollback to Snapshot**: Testing the rollback functionality to a previously
  created snapshot, including scenarios with non-purgeable volumes and purgeable
  volumes.
* **Delete Snapshot**: Testing the deletion of a snapshot under different
  conditions, such as without restarting the system and after a system restart.
* **System Restart Impact**: Assessing the impact of a system restart on
  snapshot creation and rollback.
* **Create a New Snapshot**: Testing the creation of new snapshots under various
  conditions, including when a previous snapshot has been deleted or still
  exists.
* **Node Deletion**: Testing the impact of deleting a node with a VM that had a
  snapshot.
* **App Instance Deletion**: Testing the deletion of an application instance
  after a rollback and verifying cleanups.
