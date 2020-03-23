# Inter-Process Communications

EVE's control plane is composed of several independent processes: `zedmanager`, `zedagent`, `downloader`, etc. These services often need to communicate with each other, for example to discover the state of a managed artifact, or to initiate a change in state.

In addition, each process needs to track and know its current state.

While each process could simply send a local RPC call of some kind or another, that would tie up many threads for a long time in a synchronous backlog, as well as eliminating much flexiiblity. In addition, it would require each process to know all of its downstream clients.

EVE uses a custom library called `pubsub` - for "publish subscribe" - to solve all of these problems:

* communicate changes in current or desired state with other processes
* keep track of current state
* persist state to survive the loss of a process

Note that "persistence" here means surviving the loss of a _process_, not a node. The desired state of a _node_ is handled via the node configuration received from the controller.

## PubSub

PubSub is a library that implements a simple in-memory key-value store, with notifications for changes.

Each process that wants to share state with other processes includes the library. It then creates a publishing "table", which is simply a named space for records to be stored. It then "publishes" updates to the table using the library.

Each process that wants to consume the shared state also includes the library. It then "subscribes" to the same named table, and registers handlers for changes.

When the publisher saves updates - creating a new record, changing an existing record, or deleting a record - by making the single call to publish, that update is:

1. saved to the in-memory version of the table in the publisher's process
1. saved to disk, allowing a replay if needed
1. replicated to all subscribers

Each subscriber's library:

1. receives the update
1. updates the replicated copy of the state in its own in-memory version of the table, synchronizing it with the publisher's version
1. triggers any registered handlers on that table

Thus, with a single call to "save updates" on one process (publisher), one or more other processes (subscribers) automatically receive updates, synchronize their in-memory copy, and trigger event handlers.
