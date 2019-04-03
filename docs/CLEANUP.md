# Cleanup

This is a simple list of general "cleanup" items, a "tech debt" to-do list:

* Makefile should not cause `docker pull` until an actual target is invoked. Currently, even `make -n <target>` invokes `parse-pkgs.sh` which pulls down images.
* Making an existing target image should not rebuild it unless explicitly told to. Currently, `make fallback.img` will _always_ rebuild it, as opposed to seeing that it exists.
