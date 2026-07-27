# NVIDIA Jetson Platform Package

## Introduction

This package integrates libraries and artifacts from NVIDIA Jetpack to
EVE-OS.

## How it works?

This package fetches the Jetson Linux and extracts all .deb packages
containing all relevant files (libraries, firmwares, etc) needed to run
specific NVIDIA GPU applications, such as CUDA applications.

Then, all provided CDI (Container Device Interface) files are parsed by the
process-cdi.sh script, which will copy all files pointed in the CDI from
the extracted .deb packages.

The output container will provide a directory /opt/vendor/nvidia, where:

* /opt/vendor/nvidia/dist: Contains all files pointed in all CDI files
* /opt/vendor/nvidia/bin/nvidia-ctk and
  /opt/vendor/nvidia/bin/nvidia-cdi-hook: applications needed to process
  libraries files from the CDI spec.
* /opt/vendor/nvidia/bin/ldconfig-glibc: ldconfig tool for GNU libc
* /opt/vendor/nvidia/init.d/nv-init.sh: Script to perform platform setup
  actions, to be executed during pillar's initialization

All supported CDI files will be available at /etc/cdi.

One CDI file is provided per board family, under `cdi/<jetpack version>/`:

| File                      | Jetpack | Devices          | CDI kind              |
|---------------------------|---------|------------------|-----------------------|
| jp5/jetson-xavier-nx.yaml | 5.1.3   | Jetson Xavier NX | nvidia.com/xavier-gpu |
| jp5/jetson-orin-nano.yaml | 5.1.3   | Jetson Orin Nano | nvidia.com/gpu        |
| jp6/jetson-orin.yaml      | 6.0     | Jetson Orin      | nvidia.com/gpu        |
| jp7/jetson-thor.yaml      | 7.2     | Jetson AGX Thor  | nvidia.com/thor-gpu   |

New board families follow the `nvidia.com/<board>-gpu` convention. The bare
nvidia.com/gpu of the jp5 Orin Nano and jp6 Orin specs predates it and is
kept so that deployed device models keep working.

The kind must be unique across every file installed in /etc/cdi. Two specs
declaring the same qualified device name are treated as a conflict by the
CDI registry, which then drops the device from both of them, disabling the
GPU on every board involved.

## CDI generation

The Container Device Interface (CDI) specification is used to support
third-party devices on containers. For the NVIDIA Jetpack, the _nvidia-ctk_
tool (from the _nvidia-container-toolkit_) it's used to generate the CDI
file for a specific device/platform by running it directly in the target
system. The CDI files provided by this package were generated in a
bare-metal Jetson Linux using _nvidia-ctk_. On EVE-OS all the Jetpack
related files will be based at /opt/vendor/nvidia, differently from the
rootfs of a Jetson Linux, that's why the post-processing is required to
adjust pathnames of libraries, firmwares and other binary files.

### Generating the CDI file on a Jetson Linux

#### Install nvidia-container-toolkit

```sh
$ curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg \
  && curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
    sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
$ sudo apt-get update
$ sudo apt-get install -y nvidia-container-toolkit
```

#### Run nvidia-ctk tool

```sh
$ sudo nvidia-ctk cdi generate --output=/var/run/cdi/nvidia.yaml
```

The CDI devices generated can be checked running the _nvidia-ctk cdi list_ command:

```sh
$ nvidia-ctk cdi list
INFO[0000] Found 2 CDI devices
nvidia.com/gpu=0
nvidia.com/gpu=all
```

## Upgrading Jetpack on EVE-OS

In order to upgrade to a new Jetpack version, the following guidelines
should be considered:

1. Ensure EVE's NVIDIA custom kernel is compatible with the new Jetpack version
1. Update NVIDIA firmwares on pkg/fw (if required)
1. Update the Jetpack tarball URL at pkg/nvidia/Dockerfile (JETSON_LINUX)
1. Update the Jetson Linux version in the SBOM registration (JL_VER) at
   pkg/nvidia/Dockerfile
1. Generate the CDI yaml files on a running (bare-metal) Jetpack, using the
   same nvidia-container-toolkit revision as NVIDIA_CONTAINER_TOOLKIT_REV in
   pkg/nvidia/Dockerfile, and keeping the emitted cdiVersion within the range
   supported by the CDI library vendored in pillar
1. Set the kind of each CDI file to `nvidia.com/<board>-gpu`, keeping it unique
   across all the files installed in /etc/cdi
1. If the CDI kind of a board changes, check pkg/kube: the default-kind of
   the nvidia-container-runtime config is derived from the shipped spec, and
   cluster-init.sh maps a board to its CDI file by name
1. From Jetpack 7 on, a single Jetpack release can drive different boards with
   different GPU driver models (Thor uses openrm, Orin uses nvgpu). Those
   boards need their own kernel modules, firmware packages, udev rules,
   module load list and CDI spec, even though they share one Jetpack.

## References

* [Container Device Interface](https://github.com/cncf-tags/container-device-interface)
* [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-container-toolkit)
* [Installation guide for nvidia-container-toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
