## Intro
`gostats` is a simple, self contained package that collects runtime statistics from `runtime.MemStats` and sends them over UDP to [statsd](https://github.com/statsd/statsd) as a set of gauges.

### Usage

You need graphite and statsd running in your preferred way, for example using Docker:

```
docker pull graphiteapp/graphite-statsd
docker run -p 8080:80 -p 8125:8125/udp --rm --name statsd graphiteapp/graphite-statsd
```

Then simply, collect the data:

```
package main

import (
	"fmt"
	"github.com/shjala/gostats"
)

func main() {
  // Endpoint is statsd endpoint address
  var Endpoint = "localhost:2125"

  // Tag is bucket tag
  var Tag = "your_tag"

  // collect stats every 5 seconds
  err := gostats.Collect(Endpoint, Tag, 5, true, true, true)
  if err != nil {
    fmt.Printf("Failed to start collecting runtime stats : %v\n", err)
    return
  }

  // Rest of the code
}
```




