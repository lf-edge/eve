# EVE LOG LEVELS

The various services in EVE use logging with levels and a specified source which are all sent to the [log API](../api/proto/logs/log.proto).

There are settings specified in [config properties](./CONFIG-PROPERTIES.md) to set the minimum log level which is reported over the API. This currently defaults to the info level.

In addition, much of the code in pkg/pillar directories use additional internal "levels" with associated functions such as Notice, Metric, and Function with a mapping from those to the logrus levels.
The reason for the additional levels is to:

- Distinguish between different forms logs e.g., use separate calls to log changes to periodically reported metrics, since those are quite voluminous.
- Handle the fact that there is no Notice level in the log packages.

The mapping is compiled into the code - see [base/log.go](../pkg/pillar/base/log.go).

## Log level conventions

The current conventions in pkg/pillar code for log levels is as follows:

- Fatal - cases where we really need to restart the agent.
- Error - some cases of errors with the objects to be deployed but also internal errors which are not reported using the API.
- Warning - could be resource-related issues.
- Notice - all of the pubsub object type logging except for periodic metrics plus additional noticeable events. Mapped to logrus.InfoLevel.
- Metric - the pubsub object type logs for periodic metric changes. Mapped to logrus.DebugLevel.
- Function for internal function-level logs. Mapped to logrus.DebugLevel.
- Trace for more voluminous function-level logs.

## Future cleanup

Once we do not have any pending PRs it makes sense to rename the odd "Function" functions to "Debug" and remove that mapping. However, we'd still have the pseudo-levels "Notice" and "Metric".

In some case one might desire the Debug and even Trace entries without the voluminous and periodic Metric ones. TBD whether we need to be able to control that using an API.
