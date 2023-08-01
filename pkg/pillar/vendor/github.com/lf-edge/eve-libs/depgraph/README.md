# Dependency Graph (depgraph)

## Use-case

This package implements a [dependency graph](https://en.wikipedia.org/wiki/Dependency_graph).
The main use-case is to represent configuration items (network interfaces, routes,
volumes, etc.) or any managed stateful objects (incl. processes, containers, files, etc.)
as graph nodes, here called *items*, and their dependencies as directed graph edges.

For example, if there are items `A` and `B` with edge (dependency) `A->B`,
it means that `B` should be created before `A`. Conversely, the removal of these
two items should proceed in the opposite order, i.e. `A` should be removed first
(think of the dependency as "`A` cannot exist without `B`"). Edges of this dependency
graph slightly diverge from the standard definition as it is allowed for an edge
to point to an item which is not present in the graph, representing a scenario
of a missing dependency.

The graph can be for example used to model the intended or the current state
of a managed system. Note that depgraph alone only provides a data structure
to store the modeled state. However, in combination with the [Reconciler](../reconciler/README.md),
it can help to solve the challenge of state reconciliation. A management
agent will typically maintain two graphs, one for the intended state, updated
based on the input from a user/controller, and the other for the current state.
The agent will use APIs of the managed system to learn the actual state
and will update the graph accordingly. The reconciler will take both of these
graphs as an input and will perform all state transitions needed to reach
the intended state, updating the graph representing the current state
in the process. For more information on the topic of state reconciliation,
please refer to the [readme file of the Reconciler](../reconciler/README.md).

## Subgraphs

Apart from items and edges, the graph also supports a notion of subgraphs.
A subgraph is a subset of graph items, including all edges that originate or point
from/to any of these items (again, a slight deviation from the standard definition).
Subgraph is given a name and optionally also a description (just like the top-level
graph). The main use-case is to group related items and allow to select and edit
them together.

Here is a visual depiction of an example graph with some subgraphs:

![Subgraphs](./pics/subgraphs.png)

For example, all components of a virtualized network (bridge, routes, dns server, etc.)
can be grouped into one subgraph with the logical name of the network:

```go
virtNetwork := depgraph.New(
    depgraph.InitArgs{
        Name:  virtNetworkName,
        Items: []depgraph.Item{bridge, route1, route2, dnsServer}
    })
```

Then, to add or replace all the components of the network in the graph, only one function
call is needed:

```go
fullStateGraph.PutSubGraph(virtNetwork)
```

Also, the entire content of the subgraph can be removed with just:

```go
fullStateGraph.DelSubGraph(virtNetworkName)
```

Subgraphs can be also nested and thus compose a hierarchical tree structure.
This is very similar to directory structure of a filesystem if you think of subgraphs
as directories and items as files.
Currently, subgraphs are not related to and does not affect dependencies.

Note that in terms of API, subgraph is also a graph - it implements the `Graph`
interface. Single item can also be viewed as a subgraph - `Graph.ItemAsSubGraph(item)`
returns a (read-only) graph handle.

## API & Usage

Configuration items modeled as graph nodes (in API simply called items) should
implement the `Item` interface.
This means that for every distinct item type, there needs to be a structure
with methods as required by the interface. For example, it is required to provide
a name for every item instance (based on the item configuration) through the method
`Name() string`. Two distinct items of the same type should have different names.
Distinct here means that the manifestation of these items are two separate objects
in the managed system. A graph-wide unique item identifier/reference is therefore
a combination of the type (returned by `Type() string`) and the name. This is captured
by the `ItemRef` structure. To obtain a reference for an item (which is needed for
several graph methods), call `Reference(Item)`.
Another notable method defined by the `Item` interface is `Dependencies()`. It lists
all the dependencies of an item and therefore determines the outgoing edges of the item.

Here is a simplified example for Items representing Linux interfaces and routes.
Only `Name()`, `Type()` and `Dependencies()` methods are shown here. For other
required methods, please see the `Item` interface definition.

```go
import "github.com/lf-edge/eve-libs/depgraph"

type LinuxInterface struct {
    name string
}

func (intf LinuxInterface) Name() string {
    return intf.name
}

func (intf LinuxInterface) Type() string {
    return "Linux interface"
}

func (intf LinuxInterface) Dependencies() []depgraph.Dependency {
    // no dependencies
    return nil
}

// Other Item methods for LinuxInterface are omitted.

type LinuxRoute struct {
    via    string
    dst    string
    metric int
}

func (route LinuxRoute) Name() string {
    // Both dst and via should be included to uniquely identify the route
    // among all the routes.
    return route.dst + " via " + route.via
}

func (route LinuxRoute) Type() string {
    return "Linux route"
}

func (route LinuxRoute) Dependencies() []depgraph.Dependency {
    return []depgraph.Dependency{
        {
            Item: depgraph.RequiredItem{
                Type: "Linux interface", // can also use LinuxInterface{}.Type()
                Name: route.via, // can also use LinuxInterface{name: route.via}.Name()
            },
            Description: "Route requires outgoing interface to be configured first",
        },
    }
}

// Other Item methods for LinuxRoute are omitted.
```

With each item instance the graph also allows to store some state data, implementing
the `ItemState` interface. This can be for example used to store information about the last
state transition performed for the item and any errors that resulted from it.
Think of `Item` as the configuration and `ItemState` as a run-time state.
State data are mostly transparent to the graph with only few methods defined to help to enhance
the [visualization of the graph](#visualization).
Item state data are completely optional and can be passed as nil. They are typically omitted
when the graph is used to model the intended state and provided when the currently running
state is modeled.

Once all needed `Item` (and possibly `ItemState`) implementations are available, you are ready
to build a dependency graph to model some kind of system state.
Graph with some initial content is created using `New()`:

```go
import "github.com/lf-edge/eve-libs/depgraph"

// using LinuxRoute and LinuxInterface defined above

g := depgraph.New(depgraph.InitArgs{
    Name:           "MyGraph",
    Description:    "This is my example graph",
    ItemsWithState: []ItemWithState{
        {Item: LinuxInterface{name: "eth0"}, State: LinuxInterfaceState{lastOpErr: nil}},
    },
    // For items without state data you can use Items, avoiding to pass ItemState as nil
    // and therefore making the code shorter and easier to read.
    // But do not put the same Item into both Items and ItemsWithState.
    Items: []Item{
        LinuxRoute{via: "eth0", dst: "10.10.0.0/16", metric: 10},
        LinuxRoute{via: "eth0", dst: "192.168.16.0/24", metric: 10},
    }
})
```

Graph will automatically build edges for all items based on their dependencies.
In the example above, there will be one edge from each route pointing to the `eth0` interface.
`InitArgs` can also contain the initial content of subgraphs.

A single item is manipulated using `Item()`, `PutItem()` and `DelItem()` methods:

```go
import (
    "fmt"
    "github.com/lf-edge/eve-libs/depgraph"
)

// Add new Linux route (nil ItemState).
item := LinuxRoute{via: "eth0", dst: "10.20.0.0/16", metric: 100}
g.PutItem(item, nil)

// Update the item.
item.routeMetric = 50
g.PutItem(item, nil)

// Delete the item.
itemRef := Reference(item)
g.DelItem(itemRef)

// Read single graph item.
item, found := g.Item(itemRef)
if found {
    fmt.Printf("Linux interface %+v\n", item)
}
```

To iterate all items in the graph:

```go
inclSubGraphs := true
iter := g.Items(inclSubGraphs)
for iter.Next() {
    item, state := iter.Item()
    fmt.Printf("Item: %+v, with state: %+v\n", item, state)
}
```

To iterate all edges originating from an item:

```go
iter := g.OutgoingEdges(itemRef)
for iter.Next() {
    e := iter.Edge()
    fmt.Printf("Edge from %s to %s for dep: %+v\n",
        e.FromItem, e.ToItem, e.Dependency)
}
```

Lastly, sub-graphs are manipulated using `SubGraph()`, `PutSubGraph()`, `DelSubGraph()`
and `EditSubGraph()` methods:

```go
item1 := LinuxInterface{name: "eth0.1"}
item2 := LinuxInterface{name: "eth0.2"}
subG := depgraph.New(depgraph.InitArgs{
    Name:        "MySubGraph",
    Description: "This is my example sub-graph",
    Items:       []Items{item1, item2},
})

// Add new subgraph
g.PutSubGraph(subG)

// Can use the same handle to edit the subgraph...
subG.DelItem(Reference(item1))

// ... or a read-write handle can be retrieved:
readSubG := g.SubGraph("MySubGraph") // can only read nodes, edges, etc.
subG = g.EditSubGraph(readSubG) // elevate to read-write
subG.Putitem(item1, nil)

// Remove the subgraph:
g.DelSubGraph("MySubGraph")
```

## Visualization

The graph content can be exported into [DOT](https://en.wikipedia.org/wiki/DOT_(graph_description_language))
using `DotExporter` and then visualized for example using [Graphviz](https://graphviz.org/).
Subgraphs are drawn as [clusters](https://graphviz.org/Gallery/directed/cluster.html),
i.e. items they contain are plotted near each other and contained within a rectangle.

Example usage (incl. Graphviz with a wrapper for Go):

```go
// import "github.com/goccy/go-graphviz"

// Initialize DOT exporter
exporter := &DotExporter{CheckDeps: true}

// Render DOT representation of the dependency graph.
dot, err := exporter.Export(graph)
if err != nil {
    log.Fatalf("depgraph DOT rendering failed: %v", err)
}

// Use go-graphviz - a Graphviz wrapper for Go.
gvizGraph, err := graphviz.ParseBytes([]byte(dot))
if err != nil {
    log.Fatalf("failed to parse DOT: %v", err)
}
gviz := graphviz.New()
err = gviz.RenderFilename(gvizGraph, graphviz.PNG, "/path/to/graph.png")
if err != nil {
    log.Fatal(err)
}
```

Example of a rendered depgraph:

![graph visualization example](./pics/graph-example.png)
