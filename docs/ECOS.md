# Edge Containers

## Introduction

While EVE provides a lot of sophisticated device management functionality, at the end of the day its success depends on a diverse and growing ecosystem of applications that it can support. EVE is *not* a traditional operating system in that it doesn't support applications packaged as executables. Instead EVE expects its applications to be:

* [Traditional Virtual Machines](https://en.wikipedia.org/wiki/Virtual_machine)
* [Unikernels](http://unikernel.org/)
* [Docker/OCI container](https://www.opencontainers.org)

Edge Container is a novel concept that allows an effective packaging and lifecycle management of all these types of applications and it consists of two parts:

* Edge Container Image (ECI) - a self-contained, binary representation of an Edge Container
* Edge Container Object (ECO) - a live copy of an Edge Container

ECOs are created by users binding a single ECI to a set of hardware and software resources (e.g. memory, CPU, I/O and networks). In other words: ECOs are live, running entities that are derived from an ECI image and a set of resources given (or bound) to it. A single ECI can be used to start multiple ECOs. The primary purpose of EVE, then, is to provide the best resource abstraction and an execution environment to a set of ECOs.

ECI is an application packaging and distribution mechanism that provides support for all 3 types of EVE applications while seamlessly integrating with Docker/OCI container specification and toolchains. The latter part is especially important, since Docker tooling (e.g. Docker Desktop, Docker Registry, CI/CD integrations, etc.) has become a de-facto standard in modern, cloud-native application development. ECI format is a foundation for everything else in the Edge Containers workflow. This format defines the very notion of an ECO binary the same way that [ELF format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) defines what it means to be an application on most traditional Operating Systems today. And just like with ELF, it is the job of an operating system to load (L in ELF) and execute (E in ELF) these turning them into running ECOs.

EVE TSC plans to submit ECO and ECI standards for broad Linux Foundation adoption once this document reaches the state of a formal specification. At the current stage, however, we are still collecting product requirements and recording them (together with implementation details) below.

Working with ECOs will typically go through multiple stages, each with its own expectations around standardization and how they interact with the rest of the cloud-native developer and DevOps toolchains. We expect EVE users to...

   1. ...build an Edge Container Image (ECI) using the usual tools typically available on developer's desktop. The final build artifact may either be hidden in a local cache of some kind (along the lines of Docker image repository, local Maven cache, etc.) or be immediately available as a self-contained binary file
   2. ...instantiate ECOs based on a given ECI in a simulated environment that can easily run on developer's desktop (unlike a real EVE instance that typically runs on an Edge Node). Input to this stage could either be a reference to an ECI hidden in a local cache or a URL (including a local URL) for a self-contained binary file
   3. ...share ECIs with other developers and users
   4. ...deploy ECI on a fleet of Edge Nodes running EVE
   5. ...manage a rich life-cycle of an ECO (creation, stopping, re-starting, etc.)

In the following sections we define semantics of all these actions and expectations around how they dovetail into each other.

## ECO Runtime Specification

ECO Runtime Specification aims to specify the binding of ECI to Edge Node's hardware and software resources, configuration, execution environment, and lifecycle of an Edge Container. Note that unlike most of the runtimes covered by OCI specification, EVE is a self-contained execution engine. This allows us to skip a lot of details (around on-disk container runtime formats, configuration schema, etc.) that otherwise would have to be standardized.

Since there is always a one-to-many mapping between ECI and ECOs (one immutable ECI can be used to create multiple running ECOs) it is important to define how a seed ECI is referenced for any ECO operation requiring it (like creating an ECO from an ECI). There are two methods that are covered in the following section: you can reference an immutable ECI via a content-addressable handle or you can reference an ECI via a human readable name that maps to an immutable one. Since the later kind of mapping can be updated at will, it is very important to understand how various transitions in the ECO state transition diagram react to an ECI mapping changing while transition is in flight.

Since nothing happens with EVE unless initiated by a Controller through a certain set of configuration directives, this section focuses on:

   1. ECO state transition diagram
   2. configuration directives utilized by an EVE controller to move through the states
   3. metrics and events communicated back by EVE to the controller after any transition is attempted

### ECO Runtime State Transition Diagram

We will try to align with [OCI Lifecycle](https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#lifecycle) where possible, but we may need some extra states as well.

### Detailed description of states

Currently we support the following states for the ECOs:

* ECI has been transferred to EVE's storage area
* Resources (CPU, memory, networking, I/O) have been committed to an ECO but the container has not been started yet
* ECO is running
* ECO is stopped (the resources are still pinned and mutable resources such as R/W storage remain in the state they were when ECO was running)
* ECO is restarted
* ECO resources are purged (TBD)
* ECO is deleted (all the resources are released)

### Controller config ECO schema

As part of a regular config that EVE receives from its controller, each ECO gets configured by an entry in an array having:

* displayname
* uuidandversion
* activate
* purge
* restart
* fixedresources
  * virtualizationMode
    * memory
    * maxmem
    * vcpus
    * rootdev
  * interfaces
    * name
    * acls
    * networkId
  * drives
    * drvtype
    * target
    * maxsizebytes
    * readonly
    * preserve
    * image
      * name
      * uuidandversion
        * iformat
        * sizeBytes
        * sha256
        * dsId
        * siginfo

EVE periodically pulls the configuration from the controller. The configuration specifies the desired end state. EVE implements "eventual consistency" model. To reach the desired state from the current state of the system, EVE computes the required operations to be performed. EVE then executes those operations. At the end of each operation, EVE reports the state of the system back to the controller.

The picture below provides simplified view of states and transitions for an ECO.

```text
                                                    restart
                                    +----------+<-----------------+
                        start       |          |                  |
                                    |          |    stop          |
                      +------------>+  online  +-------------+    |
                      |             |          |             v    |
             +--------+             |          |          +--+----+-----+
  Prepare    |        |             +-----+----+          |             |
+----------->+ Init   |                   |    stop/purge |   stopped   |
             |        |                   +-------------->+             |
             +------+-+                                   +------+------+
                    |               +----------+                 |
                    |               |          |                 |
                    +-------------->+  deleted +<----------------+
                         delete     |          |     delete
                                    +----------+
```

The controller drives the ECO state transitions via the configuration. These state transitions are described below. Due to the eventual consistency model, a new configuration may result in zero or more state transitions for a given ECO.

* Prepare an ECO
  * The ECI(s) is transferred to EVE's storage area and resources required for the ECO are reserved.
  * EVE performs the operations to "prepare an ECO" for each entry in the array of ECO's in the new configuration and not present in older configuration.

* Start an ECO
  * A previously stopped ECO or an ECO that has never been started, will be started. At the end of this, ECO will transition to Running state. For an ECO which is already Running, this is a no-op.
  * EVE performs the operation if the 'activate' flag is set to 'true' in the configuration.

* Stop an ECO
  * An ECO which is either running or transitioning to running state will be stopped. However, the mutated run time state is preserved. At the end of this stage, ECO will transition to Stopped state. A subsequent start of the ECO will start the ECO with the previously mutated runtime state.
  * EVE performs the operation if the 'activate' flag is set to 'false' in the configuration.

* Purge an ECO
  * An ECO which is either running or transitioning to running state will be stopped and the mutated run time state of the ECO is deleted. A subsequent action to start the ECO will start the ECO with a pristine runtime state.
  * EVE performs this operation if the 'purge' counter in the configuration is greater than the 'purge' counter in the previous configuration.
  * Purge of an application instance can be also requested locally from a [Local Profile Server](../api/PROFILE.md).

* Restart an ECO
  * The action of stopping an ECO and starting it again is combined in a single action of restart. Restart supports a flag which indicates whether the mutated runtime state is to be purged after stopping it.
  * EVE performs this operation if the 'restart' counter in the configuration is greater than the 'restart' counter in the previous configuration.
  * Restart of an application instance can be also requested locally from a [Local Profile Server](../api/PROFILE.md).

* Delete an ECO
  * An ECO will be deleted. The resources previously reserved for the ECO are released. The storage for the ECI may or may not be released depending on whether there are other ECO's referencing it. If there is no ECO referencing the ECI, the storage is released as part of periodic garbage collection.
  * EVE performs this operation if there is an entry for an ECO was present in the previous configuration and absent in the new configuration.

## Edge Container Image Format

This specification defines an ECI, consisting of a:

* manifest
* a set of binary layers
* a configuration

Both binary layers and configuration are represented as opaque binary blobs and referenced in a [CAS manner](https://en.wikipedia.org/wiki/Content-addressable_storage) by a ``<algo>:<content hash value>``. This allows us to have a structure similar to a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) with every element in the structure (starting from leaves) presumed immutable. The root of this tree is always a configuration object that in turn references other components of the tree. Binary content of the ECI, then, becomes synonymous with the ``<algo>:<content hash value>`` handle for the configuration object and thus is presumed to be immutable and content addressable.

You can always reference an ECI by ``<algo>:<content hash>`` handle. Human readable names are possible by binding ``<ECI repository>/<ECI name>:<ECI tag>`` strings to ``<algo>:<content hash value>``. Those symbolic names are then presumed to be mutable (you can freely change the target ``<algo>:<content hash value>``) and they are maintained at the level of ECI Distribution Specification. This later point means that whenever you encounter a self-contained, binary ECI file you never know all the symbolic names that may be associated with it. There may be a few of those symbolic names stashed away in the repositories.json file, but this is by now means an exhaustive nor a complete list. In fact, you can provide your own symbolic name to the ECI file when you make it available via various transport mechanisms.

ECO Image Format is aiming at becoming a true extension to an [OCI Image Format Specification](https://github.com/opencontainers/image-spec/blob/master/spec.md). The good news is that OCI Image Spec is structured in an open-ended enough fashion to allow it. The bad news is that it mandates certain aspects of the binary Image Format to be very specific to only containers. The biggest obstacle in from of us is extending [OCI Image Media Types](https://github.com/opencontainers/image-spec/blob/master/media-types.md#oci-image-media-types) to account for binary blobs that are specific to ECI. For example, we would like to have a media type that would correspond to bootable binaries directly (kernels and unikernels) and also initrd binary blobs. Until that happens, we're going to use a workaround that represents these types of objects as binary blobs + metadata wrapped inside of an already supported [Image Layer Filesystem Changeset
](https://github.com/opencontainers/image-spec/blob/master/layer.md#image-layer-filesystem-changeset).

Following this approach brings immediate benefit of all Docker tooling working with ECIs right away. For example, it becomes possible to produce a Unikernel-based ECI by simply capturing the build of it in a multi-stage Dockerfile with the last stage always being FROM scratch and only copying the kernel binary + metadata into the final image.

### ECI Configuration

ECI Configuration is a json file with the following schema:

* ACKind (string -- no equivalent in OCI)
* ACVersion (string -- no equivalent in OCI -- should be moved to manifest)
* Name (string -- no equivalent in OCI -- should be moved to manifest)
* Owner (object -- owner.email owner.user is roughly OCI's author)
* Labels (``map<string, string>`` -- OCI's config.label)
* Desc (object -- no equivalent in OCI)
* ==============
* EnableVnc (boolean -- no equivalent in OCI)
* VmMode (string -- no equivalent in OCI)
* ==============
* Resources (struct -- no equivalent in OCI -- describes CPU, memory, storage requirements)
* Interfaces (struct -- no equivalent in OCI -- describes image interface requirements)
* Images (struct -- OCI's rootfs)
* ==============
* EventHandlers (we may need it for things like offline operations - certain events and what EVE should do if ECO is killed, crashed, etc.)
* Annotations (deprecated)
* Permissions (future work item to have local resources that have been granted access: set of entitlements that allows ECO to perform intended function)

## Configuration of Docker/OCI based ECOs

We use special prepared VMs to run ECOs based on Docker/OCI (if edge-node supports hardware-assistance virtualization).
In this case we start VM with the kernel of EVE and with pre-build [initrd](../pkg/xen-tools/initrd). Inside init we
make needed system mounts, mount rootfs (to /mnt) and block devices attached (to mount points defined in the file
`mountPoints`). Static IP address is assigned to the network interface if the option `ip` defined in the kernel cmdline,
otherwise dhcp is enabled.

We use several files to run application comes from Docker/OCI manifest:

* `environment` - all environment variables defined in Docker/OCI and user data from controller goes here
* `cmdline` - it is concatenation of entrypoint and cmd defined to run in Docker/OCI manifest
* `ug` - file contains user and group to run cmd under

`cmdline` may be overridden by setting of `EVE_ECO_CMD` environment variables. Thus, if defined, `cmdline` will contain
`EVE_ECO_CMD` value. It may help to run specific command inside application without rebuilding and redeploy of it.
Command is executing inside the same behaviour as the command passed from Docker/OCI manifest and can access/modify
files inside rootfs of the ECO (i.e. this way user can print some files to the logs of application or touch/download
file needed for the application), also this way user can run entrypoint with specified arguments (i.e. debugging ones).
Please note, that change of environment variables require restart of the application.

After preparation done we chroot into /mnt and run cmd from cmdline under specified user and group, output goes to
/dev/console and is accessible from log of ECO.

## ECI Distribution Specification

While ECIs are regular, self-contained binary files and can be distributed by any transport (http, ftp, etc.) in certain situations it is advantageous to define an optimized transport protocol that can be used specifically for ECI distribution.

ECI Distribution Specification will closely follow [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/master/spec.md) with the intent to stay compatible with the docker registry specification as much as possible.

The goals for the ECI Distribution Specification is to address the following aspects of ECI distribution:

* Mapping of symbolic names to content-addressable handles
* Standardizing operations on metadata for collection of ECIs stored as a group
* Establishing trust model around managing software supply chain all the way to the final ECI
* Effective download of individual binary blobs corresponding to the ECI components
* Effective upload of individual binary blobs corresponding to the ECI components

While the bulk of this portion of the specification will focus on defining RESTful HTTP API protocol, we will try to make sure that the core of these HTTP endpoints can map easily to other transports as well. After all, if we all agree to have blobs available under ``/<version>/<name>/blobs/<digest>`` the same path could map well to an S3 bucket and sftp -- not just to an HTTP REST end-point.
