C code in this package came from libpac: https://github.com/ldx/libpac
    commit b1eedd6670e10f93c6640d1700ef69703a20caef

Original README.md follows:

Libpac
======

This is a C library for handling proxy autoconfiguration files. You can also use it to test your PAC files.

Libpac is non-blocking and was created with non-blocking, event-based applications in mind. Since several PAC javascript functions might block, it uses a threadpool to execute your PAC javascript code. You supply a notification function to `pac_init`, and it will be called when a worker thread finished executing your PAC code. You can then schedule an event for your main event loop with the result.

Build
-----

You need `autoconf` and `automake`. For the first time, you need to generate `configure`:

    $ autoreconf -i

Then build libpac:

    $ ./configure
    $ make

To run tests:

    $ make check

Note: with old versions, you needed `--enable-deep-c-stack` for the javascript engine be able to handle deeply recursive stacks (large PAC files with complex checks might require this).

Example
-------

See `tests/test_pac.c` for an example on how to use `libpac`.

Testing your PAC file
---------------------

You can use `tests/test_pac` to test your PAC file. It takes the path for your PAC file as its first parameter, then an URL and a hostname. E.g.:

    $ ./tests/test_pac ~/pac.js http://mysite.com mysite.com
    Found proxy PROXY 4.5.6.7:8080; PROXY 7.8.9.10:8080

PAC files can return one or more proxies, or "DIRECT" for a direct connection.

You can also call `test_pac` with multiple URL/hostname pairs:

    $ ./tests/test_pac ~/pac.js http://mysite.com mysite.com http://mysite.net mysite.net
    Found proxy PROXY 4.5.6.7:8080
    Found proxy PROXY 7.8.9.10:8080
