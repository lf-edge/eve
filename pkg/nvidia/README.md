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

The following CDI files are provided:

* jetson-xavier-nx.yaml: For devices based on Jetson Xavier NX
* jetson-orin-nano.yaml: For devices based on Jetson Orin Nano

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
1. Generate the CDI yaml files on a running (bare-metal) Jetpack
1. Adjust device names inside each CDI file (e.g., _nvidia.com/gpu_, etc)

## References

* [Container Device Interface](https://github.com/cncf-tags/container-device-interface)
* [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-container-toolkit)
* [Installation guide for nvidia-container-toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
