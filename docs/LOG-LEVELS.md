# EVE LOG LEVELS

The various services in EVE use logging with levels and a specified source which are all sent to the [log API](../api/proto/logs/log.proto).

There are settings specified in [config properties](./CONFIG-PROPERTIES.md) to set the minimum log level which is reported over the API. This currently defaults to the info level.

In addition, much of the code in pkg/pillar directories use additional internal "levels" with associated functions such as Notice and Metric plus a mapping from Notice, Metric, Info, and Debug.
The reason for the additional levels is to:

- distinguish between different forms logs e.g., separate functions to log changes to periodically reported metrics
- handle the fact that there is no Notice level in the log packages

The current mapping is confusing since the log.Info set of functions are mapped to logrus.DebugLevel and the log.Debug functions are mapped to logrus.TraceLevel. This will be rectified soon.

The mapping is compiled into the code - see [base/log.go](../pkg/pillar/base/log.go).

## Log level conventions

The conventions in pkg/pillar code for log levels is as follows:

- Fatal - cases where we really need to restart the agent
- Error - some cases of errors with the objects to be deployed but also internal errors which are not reported using the API
- Warning - could be resource-related issues
- Notice - all of the pubsub object type logging except for periodic metrics plus additional noticable events. Mapped to logrus.InfoLevel
- Metric - the pubsub object type logs for periodic metric changes. Mapped to logrus.DebugLevel
- Info (currently mapped to logrus.DebugLevel) for internal function-level logs.
- Debug (currently mapped to logrus.TraceLevel) for more voluminous function-level logs.

## Future cleanup

The plan is to reduce the confusion by introducing a new Function pseudo-level and then replace the use of log.Info with log.Function and also replace the log.Debug with log.Trace.
