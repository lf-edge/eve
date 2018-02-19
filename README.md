# Zenbuild

zenbuild is a LinuxKit based builder for Xen-centric platforms.

How to use:

You will need qemu (https://www.qemu.org/), Docker (https://www.docker.com) 
and go 1.9+ (https://golang.org) installed in your system.

Note, that since Linuxkit and manifest-tool are evolving pretty rapidly, we're
vendoring those under build-tools/src. This means you don't have to have them
locally installed, but it also means your first build time will be much longer.

If you're on MacOS the following steps should get you all the dependencies:
   1. Get Docker:
      ```
      https://store.docker.com/editions/community/docker-ce-desktop-mac
      ```
   2. Make sure brew is installed:
      ```
      https://brew.sh/
      ```
   3. Brew install linuxkit, moby and qemu
      ```
      $ brew install qemu
      ```

Type `make supermicro.iso` in the source directory . This will
download the relevant dockers from docker hub and create a bootable
ISO for the supermicro in the file 'supermicro.iso'.

Alternatively, `make supermicro.img` will create a raw disk image of
the same system.

Please note that not all containers will be fetched from the docker
hub. mkimage-raw-efi in particular will be built.

Also, keep in mind that since the initial build fetches a LOT of bits
over the network it may occasionally time out and fail. Typically
re-running make fixes the issue.

Finally run the resulting image by typing `make run`. This will launch
qemu with some default assumptions. Make sure to wait for the GRUB menu
to show up and then pick the 2nd option (otherwise image will hang).

Once the image boots you can interact with it either by using the console
(right there in the terminal window from which make run was executed).
Your shell in the console is connected to the 'host' os. Everything
interesting is actually happening in the zededa-tools container. Use
`zen enter` command to enter it (or if you're comfortable with ctr CLI
from containerd - use that instead).

Once in a container you can run the usual xl commands to start VMs and
interact with Xen.

As an aside, you may be wondering why do we have a container-based
architecture for a Xen-centric environment. First of all, OCI containers
are a key type of a workload for our platform. Which means having
OCI environment to run them is a key requirement. We do plan to run them
via Stage 1 Xen (https://github.com/rkt/stage1-xen) down the road, but 
while that isn't integrated fully we will be simply relying on containerd.
In addition to that, while we plan to build a fully disagregated system 
(with even device drivers running in their separate domains) right now
we are just getting started and having containers as a first step towards
full disagreagation seems like a very convenient stepping stone. 

Let us know what you think by filing GitHub issues, and feel free to 
send us pull requests if something doesn't quite work.
