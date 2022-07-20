# Inter-Process Communications

EVE's control plane is composed of several independent processes: `zedmanager`, `zedagent`, `downloader`, etc. These services often have two
requirements:

1. State storage: store state, normally as go objects, in memory, and possibly persisted across service restart or eve-os reboot.
1. Communications: be notified that some of the state of other services has changed.

For example, if the config of eve-os has changed, multiple services may need to know about that change. The volumemgr may need to know
about additions, removals or changes of volumes; downloader may need to know to create or download volumes; networkmgr may need to know
to change the state of various networks or interfaces.

While each process could simply send a local RPC call of some kind or another, that would tie up many threads for a long time in a synchronous backlog, as well as eliminating much flexibility. In addition, it would require each process to know all of its downstream clients.

EVE uses a custom library called [pubsub](../pkg/pillar/pubsub/) - for "publish subscribe" - to solve all of these problems:

* communicate changes in current or desired state with other processes
* keep track of current state
* persist state to survive the loss of a process

Note that "persistence" here means surviving the loss of a _process_, not a node. The desired state of a _node_ is handled via the node configuration received from the controller.

## PubSub

PubSub is a library that implements a simple in-memory key-value store, with notifications for changes.

### Publishing

Each process that wants to store state, and possibly share it with other processes, includes the library. It then creates a publishing "table", which is simply a named space for records to be stored. It then "publishes" updates to the table using the library.

A publishing process can create as many tables as it wants. Each table is uniquely identified using the following:

* `AgentName`: The name of the publishing process. This makes it possible for other processes to know whose publications to follow.
* `AgentScope`: (optional) A unique string that lets the publisher further create scope around the table.
* `TopicType`: The type of object that is published in this table.

Once the table has been created, the publishing process can `Publish()` as many records as it wants, using a unique string key. It then
can get the records using `Get()` by unique key, `GetAll()` to get all records, `Iterate()` to iterate over the keys,
or `Unpublish()` to remove a record by key.

From the publishing process's perspective, this is nothing more than:

* a well-scoped
* in-memory
* key-value database
* with optional persistence
* that other processes can read
* or subscribe to change notifications

### Subscribing

Each process that wants to consume the shared state also includes the library. It then "subscribes" to the desired table, identifying it by:

* `AgentName`: The name of the publishing process.
* `AgentScope`: (optional) The unique scope of the table within the publishing process's tables.
* `TopicType`: The type of object expected to be received from the table.

It then can get the data from the table in the same ways as the publisher, using `Get()` by unique key, `GetAll()` to get all records,
`Iterate()` to iterate over the keys.

Additionally, it can subscribe to changes by calling `MsgChan()`, which will deliver a message on the channel for each changed object.

There are no ACLs or other security controls; any process can subscribe to any publisher's tables.

## How It Works

When the publisher saves updates - creating a new record, changing an existing record, or deleting a record - by making the single call to
`Publish()` or `Unpublish()` - that update is:

1. saved to the in-memory version of the table in the publisher's process
1. persisted, allowing a replay if needed
1. replicated to all subscribers

Each subscriber's library:

1. receives the updates
1. updates the replicated copy of the state in its own in-memory version of the table, synchronizing it with the publisher's version
1. triggers any registered handlers on that table

Thus, with a single call to "save updates" on one process (publisher), one or more other processes (subscribers) automatically receive updates, synchronize their in-memory copy, and trigger event handlers.

The following diagram describes the structure

**TODO:** diagram here

## Architecture

pubsub is composed of several layers and components.

* [PubSub](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#PubSub): a high level structure, initialized with a [Driver](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Driver), that is used as a factory to create [Publication](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Publication) and [Subscription](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Subscription).
* [Publication](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Publication): an interface for an implementation, returned by the `PubSub` factory, that enables a process to "publish", or store and announce, state information.
* [Subscription](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Subscription): an interface for an implementation, returned by the `PubSub` factory, that enables a process to "subscribe", or receive the published state of and all updates to such state, from another process.
* [Driver](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Driver): an interface for a specific implementation, passed to the `PubSub` factory, that is capable of handling persistence of data, and notification of updates to subscribers.

You should have one `PubSub` per eve-os process, and they all should use the same `Driver`, if they are to communicate with each other.

### Publisher

When a process wants to store information, it does the following:

1. Use the `PubSub` factory to [create a  new `Publication`](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#PubSub.NewPublication), passing it the `AgentName`, `AgentScope`, `TopicType`, and if the data should be persisted.
1. Use the returned [Publication](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Publication) to save (`Publish`), delete (`Unpublish`), and retrieve objects based on keys.

Upon publishing changes, the [Publication](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Publication) is responsible for:

1. [Validating that the topic and types fit the `Publication`](https://github.com/lf-edge/eve/blob/23f5ce4eb5ee/pkg/pillar/pubsub/publish.go#L100-L110)
1. [Saving the data in memory](https://github.com/lf-edge/eve/blob/23f5ce4eb5ee/pkg/pillar/pubsub/publish.go#L134)
1. [Marshaling the go object into json bytes](https://github.com/lf-edge/eve/blob/23f5ce4eb5ee/pkg/pillar/pubsub/publish.go#L141).
1. [Updating the driver with the key and updated bytes](https://github.com/lf-edge/eve/blob/23f5ce4eb5ee/pkg/pillar/pubsub/publish.go#L148)

Note that there is nothing about notifications, subscriptions, or persistence. The `Publication` is solely responsible for
validation, storing in memory, marshaling to json, and updating the `Driver` with the json bytes.

It is the `Driver` that handles notification and persistence.

When the `Driver` receives the update, it:

1. If the table is marked as persistent, store the data using whatever storage is appropriate for the driver.
1. Notifies any subscribers of changes, using whatever notification mechanism is appropriate for the driver.

All persistence and notification - the publish-subscribe part of pubsub - happens entirely within the driver.
The driver could be memory, network communication, socket communications, polled files, anything at all. The
`Publication` does not care.

The publishing process can retrieve data using `Get()`, `GetAll()` and `Iterate()`. These work entirely on the local
in-memory copy of the `Publisher`.

### Subscriber

When a process wants to retrieve information stored by a publishing process, it does the following:

1. Use the `PubSub` factory to [create a new Subscription](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#PubSub.NewSubscription), passing it the `AgentName`, `AgentScope`, `TopicType`, as well as whether the table is `persistent`. In addition, pass it handlers that should be called for modifications of data, such as creating a new entry, updating an entry, or deleting an entry.
1. Activate the returned [Subscription](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Subscription).
1. Use the returned [Subscription](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Subscription) to retrieve data:
   * get all objects
   * get specific objects based on keys
   * asynchronously invoke handlers that were registered

The [Subscription](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Subscription) is responsible for:

1. Being informed of updates from the driver.
1. Unmarshaling the raw json bytes into the correct object type.
1. Saving the data to its own in-memory copy of the table.
1. Calling appropriate handlers for state changes.

Note that there is nothing about notifications, publications, or persistence. The `Subscription` is solely responsible for
receiving updates from the `Driver`, validation, storing in memory, and calling handlers.

The `Subscription` also knows if the specific table is "persistent". It does not engage with the persistence directly, as that is the responsibility
of the driver. It uses it primarily for initial loading.

When the `Subscription` is [activated](https://github.com/lf-edge/eve/blob/dee0c391e23f40e08b7e7eacf2e532c03086c846/pkg/pillar/pubsub/subscribe.go#L52-L57):

1. Start the `DriverSubscriber`, which will cause it to get information from the `DriverPublisher`
1. If the table is "persistent", [populate](https://github.com/lf-edge/eve/blob/dee0c391e23f40e08b7e7eacf2e532c03086c846/pkg/pillar/pubsub/subscribe.go#L84-L103)
its table. It does so by calling `DriverSubscriber.Load()`, which loads the entire set of data from persistence. The specific implementation of `Load()`
is the driver responsibility.

### Driver

The `Driver` handles persistence and notification. It has the following key structures:

* [DriverPublisher](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#DriverPublisher): an interface that all `Driver` must implement. It provides the methods that will be called by the `pubsub.Publication` to persist data and notify of state changes.
* [DriverSubscriber](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#DriverSubscriber): an interface that all `Driver` must implement. It provides the methods that will be called by the `pubsub.Subscription` to be notified of state changes.

#### `DriverPublisher`

The [DriverPublisher](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#DriverPublisher) is the part of the `Driver` that is responsible for handling publisher events, specifically
persisting what should be persisted and notifying subscribers.

When creating a `pubsub.Publication` instance, the `pubsub.Publication` creates a `DriverPublisher`.

The `DriverPublisher` is expected to retrieve any persisted state for the calling `pubsub.Publication`, store any future updates from the calling
process `pubsub.Publication`, and to inform any subscribers of the current state and any changes.

### `DriverSubscriber`

The [DriverSubscriber](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#DriverSubscriber) is the part of the `Driver` that is responsible for subscribing to events for a specific table.

It maintains a copy in memory of the publisher's table, listens for updates, and then updates its local-copy table. Finally,
it calls any handlers registered for changes.

When a `pubsub.Subscription` wants to receive the state of, and notifications for changes to, another process's table,
it creates a `DriverSubscriber`, passing it sufficient information to identify the table. It also passes it
a channel for [Change](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Change).

Each change in the table is expected to be updated via an update in the channel.

The `DriverSubscriber` is expected to retrieve the current state of the table, and update the calling
`pubsub.Subscription` of all changes by sending updates on a channel passed during the `DriverSubscriber`
initialization.

## Driver Implementations

eve-os currently has one primary driver [socketdriver](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub/socketdriver).
In addition, an [emptydriver](https://github.com/lf-edge/eve/blob/8c6d4ddecf5fec004d4e188f9abc03644c2746aa/pkg/pillar/pubsub/emptydriver.go)
provides a zero-functionality implementation, which is useful for working with services that require a pubsub but will not be exercising it at all.

Additional implementations may exist in testing, e.g. in-memory drivers.

### `socketdriver`

The primary `Driver` implemented in eve-os is the [socketdriver](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub/socketdriver), which uses:

* data storage via files, one directory per table, one file per key-value entry; it does not use in-memory storage.
* notification via Unix-domain sockets, one socket per table.

Note that in eve, `/var/run` and `/run` are the same. For simplicity's sake,
we use `/run` exclusively here.

#### Data Storage

The socketdriver stores all data for one table in a specific directory. It does not use in-memory storage.
This file mechanism is used both for persistent and for non-persistent data. For persistent data,
it stores files in a directory that will be persisted beyond reboot, whereas for non-persistent data, it stores
files in an ephemeral directory that will be deleted on reboot.

The root directory upon which socketdriver operates is passed to the socketdriver
instance upon creation. In the case of normal eve-os operation, that defaults to `/`, but it can be changed upon initialization.
All other directories are subsidiary to the root directory.

The specific subdirectory used inside the root directory is determined based on the options [here](https://github.com/lf-edge/eve/blob/6160d0e96c72a1954db2a8bdfd99c2fec1972341/pkg/pillar/pubsub/socketdriver/driver.go#L88-L99).

The directory to use and the type of file depends on 2 options:

* `persistent`: whether or not this table should persist, and therefore if files should be in a persisted-beyond-reboot directory or not.
* `publishToDir`: whether or not this table should publish its data to a directory.

It also includes the "name" of the publication, where `<name>` is calculated:

* global table: `global`
* `agentScope == ""`: `<agentName>/<topic>`
* otherwise: `<agentName>/<agentScope>/<topic>`

The above combine to create the location:

|persistent?|publishToDir?|directory|
|---|---|---|
| Y | Y | `/persist/config/<name>` |
| Y | N | `/persist/status/<name>` |
| N | Y | `/run/global/<name>` |
| N | N | `/run/<name>` |

Examples:

|persistent|publish|agentScope|agentName|topic|directory|
|---|---|---|---|---|---|
|Y|Y|tester|configmgr|inputs|`/persist/config/tester/configmgr/inputs/`|
|Y|N|tester|configmgr|inputs|`/persist/tester/configmgr/inputs/`|
|Y|N||configmgr|inputs|`/persist/configmgr/inputs/`|
|N|N|||inputs|`/run/global/inputs`|

The specific implementations of the `DriverPublisher` interface and `DriverSubscriber` interface, for socketdriver, are, respectively,
[socketdriver.Publisher](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub/socketdriver#Publisher) and [socketdriver.Subscriber](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub/socketdriver#Subscriber).

##### `socketdriver.Publisher` Updates

When `socketdriver.Publisher` receives updates from its calling `pubsub.Publication`, it saves the data in a file, whose name is determined
as `<dirName>/<key>.json`. Key must not contain slashes and should fit max filesize limit (not exceed 255 symbols).

For example, if the `<dirName>` from above was `/persist/tester/configmgr/inputs/`, and the `Publish()` used the key `important`, then
the filename is `/persist/tester/configmgr/inputs/important.json`.

This is completely independent of whether or not it is persistent. `socketdriver` _always_ writes its information to files.
_Where_ those files are, i.e. which directory, is determined by whether or not the table is persistent.

* persistent: write to a directory that persists past reboots.
* not persistent: write to an ephemeral directory.

##### `socketdriver.Publisher` Actions

As described above, `socketdriver.Publisher` _always_ writes to a file, whose name is `<dirName>/<key>.json`, whether the `<dirName>` is determined by the
algorithm above. `persistent` determines where that directory will be placed.

When `socketdriver.Publisher` receives a [`Publish()` call](https://github.com/lf-edge/eve/blob/6160d0e96c72a1954db2a8bdfd99c2fec1972341/pkg/pillar/pubsub/socketdriver/publish.go#L45-L54), it determines the file name
and then saves the raw data in the file.

When `socketdriver.Publisher` receives an [`Unpublish()` call](https://github.com/lf-edge/eve/blob/6160d0e96c72a1954db2a8bdfd99c2fec1972341/pkg/pillar/pubsub/socketdriver/publish.go#L56-L64), it determines the file name
and then removes the file.

### Publishing to Subscribers

`socketdriver` uses Unix-domain sockets and a server on that connection to publish notifications.

* `socketdriver.Publisher` creates the socket file, listens on the socket, and handles requests.
* `socketdriver.Subscriber` connects to the socket file and makes a connection request.

`socketdriver.Publisher` has one listener on the socket file; for each connection, representing each `socketdriver.Publisher`,
it starts [a new goroutine](https://github.com/lf-edge/eve/blob/71a6ed0790a8f786859c76172bed521c774f57ec/pkg/pillar/pubsub/socketdriver/publish.go#L220)
to handle the requests. Each subscriber has a long-running connection, over the socket, to the publisher, with a dedicated long-running goroutine.

The `socketdriver.Subscriber` sends requests to the publisher, primarily to do one of:

* send the entire data set
* send updates

Note that this is completely distinct from the part of the process that receives updates, i.e. `socketdriver.Publisher.Update()`.
Writing of persistent files, and notifying of updates, happens in two different paths.

* persisting, including the actual data: `DriverPublisher.Update()`
* notifications of changed data: set of [Updaters](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Updaters) passed to `Driver` on initialization of `DriverPublisher`.

The updates do not contain the raw data; rather they are informed of changes.

The actual name for the socket file is:

```shell
/run/<name>.sock
```

This uses the same `<name>` algorithm as above.

This socket is unique to this table; each table has its own socket.

#### `socketdriver.Subscriber` Subscriptions

Upon receiving a request to subscribe to a table, `socketdriver.Subscriber` determines the filename for the Unix domain socket using the same
algorithm as `socketdriver.Publisher`.

When the `pubsub.Subscription` calls `Start()` on `socketdriver.Subscriber`, it:

1. Opens a connection to the socket.
1. Gets a download of the entire current state of the table, which it returns to `pubsub.Subscription`.
1. Waits for any further updates, which it sends to the channel of [Change](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar@v0.0.0-20220603153046-23f5ce4eb5ee/pubsub#Change)
