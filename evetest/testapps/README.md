# Test Applications

Applications deployed as EVE app workloads by evetest tests. Every app here today
is a container image, but this directory may also hold VM app sources in the
future -- the only requirement is that each subdirectory's `Makefile` expose
a `build` target (see below). Some of these apps are also useful as
general-purpose EVE workloads outside of evetest, not just as test fixtures.

## Adding a new test app

Create a new subdirectory here with its own `Makefile` exposing a `build`
target. For a container app, add a `Dockerfile` and a `Makefile` modeled on
an existing one (`ubuntu-ctr/Makefile` or `lps/Makefile`), following this
convention:

  ```makefile
  EVETEST_ORG ?= lfedge
  IMAGE = $(EVETEST_ORG)/evetest-<name>
  # Update VERSION whenever there is a change made to this app.
  VERSION ?= 1.0

  DOCKER_TARGET ?= load
  DOCKER_PLATFORM ?= $(shell uname -s | tr '[A-Z]' '[a-z]')/$(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))

  build:
      docker buildx build \
          --$(DOCKER_TARGET) \
          --platform $(DOCKER_PLATFORM) \
          -t $(IMAGE):$(VERSION) .
  ```

That's it -- no other file needs to change. `testapps/Makefile`'s `build`
target iterates every subdirectory here and runs its `build` target, so a new
app is automatically picked up by:

- `make build-test-apps` (from `evetest/`, for local builds), and
- `.github/workflows/publish-evetest.yml` (for publishing to Docker Hub on
  every push to `master`), which just invokes `make build` here with
  `DOCKER_TARGET=push DOCKER_PLATFORM=linux/amd64,linux/arm64`.

Bump `VERSION` in your app's own `Makefile` whenever you change it -- each
app is versioned and published independently.

## Referencing a test app image in a test

Use `lfedge/evetest-<name>:<version>` as the `ImageName` (see existing tests
under `evetest/tests/` for examples with `ImageName: "lfedge/evetest-ubuntu-ctr"`
or `"lfedge/evetest-lps"`).
