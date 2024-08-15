# Installer Image

This is the image for installing EVE on a device. It is intended to be run when an EVE image boots. If the image
has `/opt/install/true` set on the root filesystem, the installer will run, else it will not.

This has the advantage of every EVE image having all of the bits necessary to run live or install, and reusing components
from live EVE for install, without duplicating. Although duplication is less of an issue for an installer, as it is normally
run from the network or a USB stick. It is only the final installed image that must be optimized.

When running `make installer-net` or `make installer-raw`, the installer has `/opt/install/true` set, and will run on boot.
It then installs an image without `/opt/install/true` set, so that the installed image will not run the installer on boot.

The installer itself is a lightweight image, containing the necessary utilities, and an install script. The install script
leverages utilities from other parts of EVE.
