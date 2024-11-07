# Watcher

The **watcher** component is the part of our system responsible for
monitoring and managing system resources to ensure optimal performance and
stability. It oversees various aspects such as memory usage, disk space, and the
number of active goroutines. By keeping track of these metrics, the watcher can
detect anomalies, trigger garbage collection, and alert us to potential issues
like resource exhaustion or leaks.

## Manual Garbage Collection

The watcher component includes a mechanism to handle memory pressure events by
explicitly invoking the Go garbage collector. This functionality is crucial for
efficient memory management and helps prevent the system from running out of
memory.

We monitor memory pressure events using the `handleMemoryPressureEvents`
function. This function listens for memory pressure notifications from the
system's cgroups at a medium pressure level. By doing so, we can respond
promptly when the system experiences memory constraints.

When a memory pressure event is detected, the `handleMemoryPressureEvents`
function checks if certain conditions are met before triggering garbage
collection:

- **Time Interval Check**: It ensures that a minimum time interval has passed
  since the last garbage collection to avoid frequent invocations. This interval
  is obtained from the `getForcedGOGCParams` function.
- **Memory Growth Check**: It verifies that the allocated memory has increased
  significantly since the last garbage collection. This is determined by
  comparing current memory usage with previous usage and considering
  configurable growth parameters also retrieved by `getForcedGOGCParams`.

If these conditions are satisfied, we explicitly invoke the garbage collector
using `runtime.GC()`. Before and after the garbage collection, we use
`runtime.ReadMemStats()` to record memory statistics. This allows us to
calculate the amount of memory reclaimed and set the threshold for the next
invocation.

By adaptively triggering garbage collection based on actual memory pressure and
allocation patterns, we ensure efficient memory usage and maintain system
performance. This approach helps prevent potential memory-related issues by
proactively managing resources.
