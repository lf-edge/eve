# Dockerfile ADD Scanner

This is a simple tool that scans Dockerfiles for `ADD` commands and reports all remote URLs
from which data is being downloaded. This is useful for security auditing purposes.

It understands the `git` syntax, and is capable of interpolating variables inside the `ADD`
command.

Simple example:

```sh
$ go run -tags dfaddgit . scan ../../pkg/acrn/Dockerfile ../../pkg/grub/Dockerfile
git://github.com/ulfalizer/Kconfiglib.git#v12.14.1
https://github.com/projectacrn/acrn-hypervisor/archive/v1.3.tar.gz
https://git.savannah.gnu.org/cgit/grub.git/snapshot/grub-2.06.tar.gz
git://git.sv.gnu.org/gnulib#d271f868a8df9bbec29049d01e056481b7a1a263
```

This should be built, and run when using `go run`, with the `dfaddgit` tag,
i.e. `go build -tags dfaddgit` or `go run -tags dfaddgit`.

## Building

A [Makefile](./Makefile) is provided to build the tool. Just run:

```sh
make build
```

and it will deposit the built file in the `bin/` directory as `bin/dockerfile-add-scanner`.

You can change the target outfile with `make build OUTFILE=/tmp/foo`, or just the output directory
while keeping the filename with `make build OUTDIR=/tmp`.

Note that the directory [bin/](./bin/) is already in the `.gitignore` file.
