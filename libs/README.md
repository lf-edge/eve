# eve libs

This directory contains the libraries used by various other packages in eve, and can be
imported by others outside of eve. It forms a single go module, and can be imported via the
usual [go module](https://go.dev/blog/using-go-modules) facilities.

Several eve packages explicitly depend upon these libraries, notably [pillar](../pkg/pillar/).

The libraries in here should depend on nothing else in eve, except other packages
inside this module. These should not assume that they are running on a live eve
platform, or have access to the more advanced and complex features like pubsub or hypervisors.

The purpose of `libs/` is to isolate standalone functionality, making it both easy to reuse and,
perhaps more importantly, easy to test.

## Using the libraries

These libraries should be imported explicitly in other packages using the full path, and should
**not** use the go.mod `replace` directive to import them from a local path. This is to ensure
that we always have an explicit chain of dependencies, that we can always build the code,
and that compiled binaries always contain full package names.

For example, package pillar's [go.mod](../pkg/pillar/go.mod) file contains:

```go
	github.com/jaypipes/ghw v0.8.0
	github.com/lf-edge/edge-containers v0.0.0-20221025050409-93c34bebadd2
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/lf-edge/eve/libs v0.0.0-20230303013136-e890ce9ee8a3
	github.com/linuxkit/linuxkit/src/cmd/linuxkit v0.0.0-20220913135124-e532e7310810
```

These libs are imported as `github.com/lf-edge/eve/libs v0.0.0-20230303013136-e890ce9ee8a3` just like
all other libraries; they receive no special import treatment.

## Developing Locally

If you need to update the libraries _and_ simultaneously test their impact on other packages,
you can use a `replace` clause in `go.mod`, but only temporarily. For example:

```go
replace github.com/lf-edge/eve/libs => ../../libs
```

When you are done and it works, do **not** commit the `go.mod` with the `replace` clause.
Instead:

1. Remove the replace clause from `go.mod`
1. Commit _just_ the `libs` changes, open a PR, and merge it in
1. In your dependent package, e.g. `pkg/pillar`, update it like any other external dependency, e.g. `go get github.com/lf-edge/eve/libs@master`
