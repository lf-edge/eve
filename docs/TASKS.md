# Tasks

With very few exceptions, any running process on EVE has to be part of the [Task](https://godoc.org/github.com/lf-edge/eve/pkg/pillar/types#Task). EVE's tasks map to containerd [Tasks](https://containerd.io/docs/getting-started/#creating-a-running-task) and ultimately to a group of processes running together in a container. Thus, each task is ultimately defined by an [OCI Runtime spec](https://github.com/opencontainers/runtime-spec/blob/master/spec.md) which can be inspected by the `ctr --namespace <name space name> container info <task name>` command. EVE uses two namespaces for its tasks:

* User-defined tasks are scoped under eve-user-apps namespace
* System-level tasks are scoped under services.linuxkit namespace

User-defined tasks are managed by the `domainmgr` while system-level tasks are managed by the Linuxkit's [init infrastructure](https://github.com/linuxkit/linuxkit/tree/master/pkg/init).

User-defined tasks are always started when a full configuration of Volumes and Networks attached to them is available to the `domainmgr`.

## Creating an OCI runtime spec for the task

In order for the task to start, an OCI Runtime spec for it has to be created. For all the system-level tasks, the OCI Runtime specs are built into the EVE image and can be found at `/containers/[onboot|services]/<service name>/config.json`. For user-defined tasks `domainmgr` delegates creation of the initial OCI Runtime spec to the appropriate hypervisor implementation's Task Setup method.

The process of coming up with an OCI Runtime spec for the tasks consist of scavenging for all the relevant bits of the configuration information. Since a task definition always has access to a full Volumes configuration a seed Task configuration may be located in the Volume declared as an OCI root Volume for the task. In that case, the [OCI Image config object](https://github.com/opencontainers/image-spec/blob/master/config.md) is taken as a seed for Task's OCI Runtime spec. Any configuration specified in the OCI Image config object can still be overwritten by the Domain's own configuration settings. Furthermore, if a task doesn't have a root OCI volume attached to it, it relies exclusively on its Domain configuration for the initial OCI runtime spec and requires a Loader to be available.

## EVE Task Loaders

EVE extends OCI architecture by an idea of a *Loader*. Loaders are useful for domains that lack their own runtime configuration and allow EVE to have a sort of a template for the Task's OCI Runtime configuration that is only customized by the volumes that is attached to it. EVE uses Loaders to run hypervisor-isolated Tasks and the loader's Task definition is a single OCI container that expects to be customized by volumes and given an initial hypervisor config to run. Another potential use for Loaders could be a JVM Loader that is customized by containers full of Java classes. In all of these instances there's nothing special about the Loader: it is simply a pre-made OCI container that is used to create a Task.

While EVE has a generic mechanism for requesting a Loader to be used for a given Task, currently we only use a single loader for hypervisor-isolated domains called `xen-tools`. In the future we anticipate expanding Loader's usage all the way to allowing users requesting Loaders through the app configuration.

Currently, the only type of edge applications that can execute as Tasks by themselves are the ones defined with an OCI container as their first volume. By default, though, even OCI container based edge applications are executed through the hypervisor specific loader (unless there is no hypervisor available on the system at all). Short of running EVE deployment without any kind of hypervisor, the only way to really force a bare-metal execution of user defined code is to specify NOHYPER as the VmMode in the application's manifest.

## Tasks and bare-metal containers

EVE makes no distinction between a user-defined container running as a user-defined Task on bare metal and user-defined container isolated into a hypervisor domain through a Loader. In both of these cases there's an EVE user-defined task running on bare metal. The only difference is what code is running on bare metal. In the former case it is user-defined code itself. In the later case it is a Loader's code.
