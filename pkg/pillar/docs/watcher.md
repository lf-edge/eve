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

## Goroutine Leak Detector

We have implemented a system to detect potential goroutine leaks by monitoring
the number of active goroutines over time. This proactive approach helps us
identify unusual increases that may indicate a leak.

To achieve this, we collect data on the number of goroutines at regular
intervals within the `goroutinesMonitor` function. However, raw data can be
noisy due to normal fluctuations in goroutine usage. To mitigate this, we apply
a moving average to the collected data using the `movingAverage` function. This
smoothing process reduces short-term variations and highlights longer-term
trends, making it easier to detect significant changes in the goroutine count.

After smoothing the data, we calculate the rate of change by determining the
difference between consecutive smoothed values. This rate of change reflects how
quickly the number of goroutines is increasing or decreasing over time. To
analyze this effectively, we compute the mean and standard deviation of the rate
of change using the `calculateMeanStdDev` function. These statistical measures
provide insights into the typical behavior and variability within our system.

Using the standard deviation, we set a dynamic threshold that adapts to the
system's normal operating conditions within the `detectGoroutineLeaks` function.
If both the mean rate of change and the latest observed rate exceed this
threshold, it indicates an abnormal increase in goroutine count, signaling a
potential leak. This method reduces false positives by accounting for natural
fluctuations and focusing on significant deviations from expected patterns.

When a potential leak is detected, we respond by dumping the stack traces of all
goroutines using the `handlePotentialGoroutineLeak` function. This action
provides detailed information that can help diagnose the source of the leak, as
it reveals where goroutines are being created and potentially not terminated
properly.

The goroutines stacks are collected and stored in a file for further analysis.
The file is stored in `/persist/agentdebug/watcher/sigusr1`. Also, a warning
message is logged to alert the user about the potential goroutine leak. To
search for relevant log messages, grep for `Potential goroutine leak` or
`Number of goroutines exceeds threshold`.

To prevent repeated handling of the same issue within a short time frame, we
incorporate a cooldown period in the `goroutinesMonitor` function. This ensures
that resources are not wasted on redundant operations and that the monitoring
system remains efficient.

The goroutine leak detector is dynamically configurable via global configuration
parameters. They are documented in the
[CONFIG-PROPERTIES.md](../../../docs/CONFIG-PROPERTIES.md) and all have
`goroutine.leak.detection` prefix.
