# escript

`escript` is a custom
[Domain-Specific Language (DSL)](https://en.wikipedia.org/wiki/Domain-specific_language)
which provides support for defining filesystem-based tests by creating
compliant scripts in a directory.

`escript` is implemented by a single binary, `eden.escript.test`, which is an
adaptation to `eden` of the original
[Go testscript machinery](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript).

## Running an escript

The easiest way to run a script from the test's `testdata` directory is to use the '-e' option:

```console
eden test tests/escript -e message
```

This is the short form of:

```console
eden test tests/escript -p eden.escript.test -r TestEdenScripts/message
```

To invoke the tests from /tmp directory, for example, call the such command:

```console
    eden test tests/escript/ -a '-testdata /tmp/'
```

A testdata directory ([tests/escript/testdata](testdata) by default) holds test scripts
*.txt run test-binary. Each script defines a subtest; the exact set of
allowable commands in a script are defined by the parameters passed to the
Run function. To run a specific script foo.txt

```console
eden test tests/escript/ --run=TestEdenScripts/^foo$
```

where `TestEdenScripts` is the name of the test that Run is called from.

The rest of this section is a nearly (not not quite) identical copy of
the
[testscript overview](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript#pkg-overview).

The primary differences are:

* creation of a new predefined command called `eden`, which is nearly identical to `exec`, except with modified `PATH`
* automatic creation of scripts for each `.txt` file in `test/dir/testdata/` as `TestEdenScript/<filename-without-txt-extension>`

The goal eventually is to make this all 100% compatible and remove duplicated
documentation.

## escript Commands

In general script files should have short names: a few words, not whole
sentences. The first word should be the general category of behavior being
tested, often the name of a subcommand to be tested or a concept (vendor,
pattern).

Each script is a text archive (`go doc
github.com/lf-edge/eden/tests/escripts/go-internal/txtar`). The script begins
with an actual command script to run followed by the content of zero or more
supporting files to create in the script's temporary file system before it
starts executing.

For example:

```code
# hello world
exec cat hello.text
stdout 'hello world\n'
! stderr .

-- hello.text --
hello world

-- world.sh --
#!/bin/sh
echo "hello world"
```

The above has one comment line:

```code
# hello world
```

followed by three escript command lines:

```code
exec cat hello.text
stdout 'hello world\n'
! stderr .
```

Followed by two files to create: `hello.text` and `world.sh`.

Each script runs in a fresh temporary work directory tree, available to
scripts as $WORK. Scripts have access to these environment variables:

```console
HOME=/no-home
PATH=<actual PATH>
TMPDIR=$WORK/tmp
devnull=<value of os.DevNull>
```

The environment variable `$exe` (lowercase) is an empty string on most
systems, `".exe"` on Windows.

The script's supporting files are unpacked relative to `$WORK` and then the
script begins execution in that directory as well. Thus the example above
runs in $WORK with $WORK/hello.txt containing the listed contents.

The lines at the top of the script are a sequence of commands to be executed
by a small script engine in the testscript package (not the system shell).
The script stops and the overall test fails if any particular command fails.

Each line is parsed into a sequence of space-separated command words, with
environment variable expansion and # marking an end-of-line comment. Adding
single quotes around text keeps spaces in that text from being treated as
word separators and also disables environment variable expansion. Inside a
single-quoted block of text, a repeated single quote indicates a literal
single quote, as in:

```'Don''t communicate by sharing memory.'```

A line beginning with # is a comment and conventionally explains what is
being done or tested at the start of a new phase in the script.

A special form of environment variable syntax can be used to quote regexp
metacharacters inside environment variables. The "@R" suffix is special, and
indicates that the variable should be quoted.

```${VAR@R}```

The command prefix ! indicates that the command on the rest of the line
(typically go or a matching predicate) must fail, not succeed. Only certain
commands support this prefix. They are indicated below by [!] in the
synopsis.

The command prefix [cond] indicates that the command on the rest of the line
should only run when the condition is satisfied. The predefined conditions
are:

```console
- [short] for testing.Short()
- [net] for whether the external network can be used
- [link] for whether the OS has hard link support
- [symlink] for whether the OS has symbolic link support
- [exec:prog] for whether prog is available for execution (found by exec.LookPath)
```

A condition can be negated: [!short] means to run the rest of the line when
testing.Short() is false.

Additional conditions can be added by passing a function to
Params.Condition.

The predefined commands are:

* arg name env

    Set environment variable (env) with value from argument (name) passed into script
    You can define arguments in top tests file:
    `eden.escript.test -test.run TestEdenScripts/arg -args="test1=123,test2=456"`

    You can override provided args by run:
    `./eden test tests/escript/ -v debug -a="test1=789"`

* cd dir

    Change to the given directory for future commands.

* chmod mode file

    Change the permissions of file or directory to the given octal mode (000 to 777).

* [!] cmp file1 file2

    Check that the named files have the same content.
    By convention, file1 is the actual data and file2 the expected data.
    File1 can be "stdout" or "stderr" to use the standard output or standard error
    from the most recent exec or wait command.
    (If the files have differing content, the failure prints a diff.)

* [!] cmpenv file1 file2

    Like cmp, but environment variables in file2 are substituted before the
    comparison. For example, $GOOS is replaced by the target GOOS.

* cp src... dst

    Copy the listed files to the target file or existing directory.
    src can include "stdout" or "stderr" to use the standard output or standard error
    from the most recent exec, eden or test command.

* [!] eden [args...] [&]

    Run the given 'eden' executable program with the arguments.
    Behaves the same way as an 'exec'.

* env [key=value...]

    With no arguments, print the environment (useful for debugging).
    Otherwise add the listed key=value pairs to the environment.

* source file...

    Parse file and set environment variables from it.

* [!] exec program [args...] [&]

    Run the given executable program with the arguments.
    It must (or must not) succeed.
    Note that 'exec' does not terminate the script (unlike in Unix shells).

    If the last token is '&', the program executes in the background. The standard
    output and standard error of the previous command is cleared, but the output
    of the background process is buffered — and checking of its exit status is
    delayed — until the next call to 'wait', 'skip', or 'stop' or the end of the
    test. At the end of the test, any remaining background processes are
    terminated using os.Interrupt (if supported) or os.Kill.

    Standard input can be provided using the stdin command; this will be
    cleared after exec has been called.

* [!] exists [-readonly] file...

    Each of the listed files or directories must (or must not) exist.
    If -readonly is given, the files or directories must be unwritable.

* [!] grep [-count=N] pattern file

    The file's content must (or must not) match the regular expression pattern.
    For positive matches, -count=N specifies an exact number of matches to require.

* message message

    Print message.

* mkdir path...

    Create the listed directories, if they do not already exists.

* unquote file...

    Rewrite each file by replacing any leading ">" characters from
    each line. This enables a file to contain substrings that look like
    txtar file markers.
    See also [Unquote](https://godoc.org/github.com/rogpeppe/go-internal/txtar#Unquote).

* rm file...

    Remove the listed files or directories.

* skip [message]

    Mark the test skipped, including the message if given.

* stdin file

    Set the standard input for the next exec command
    to the contents of the given file.

* [!] stderr [-count=N] pattern

    Apply the grep command (see above) to the standard error
    from the most recent exec or wait command.

* [!] stdout [-count=N] pattern

    Apply the grep command (see above) to the standard output
    from the most recent exec or wait command.

* stop [message]

    Stop the test early (marking it as passing), including the message if given.

* symlink file -> target

    Create file as a symlink to target. The -> (like in ls -l output) is required.

* [!] test [args...] [&]

    Run the given 'eden' test executable program with the arguments.
    Behaves the same way as an 'exec'.

* wait

    Wait for all 'exec', 'eden' and 'test' commands started in
    the background (with the '&' token) to exit, and display success
    or failure status for them.
    After a call to wait, the 'stderr' and 'stdout' commands will apply to the
    concatenation of the corresponding streams of the background commands,
    in the order in which those commands were started.

When TestEdenScripts runs a script and the script fails, by default TestEdenScripts
shows the execution of the most recent phase of the script (since the last # comment)
and only shows the # comments for earlier phases.
For example, here is a multi-phase script with a bug in it:

```console
    [!exec:cat] stop

    cp test.txt TEST.TXT

    exec cat TOST.TXT
    stdout 'text for bug test'
    ! stderr .

    -- test.txt --
    text for bug test
```

The bug is that the final phase read TOST.TXT instead of TEST.TXT. The test
failure looks like:

```console
    $ ./eden test tests/escript/ -r TestEdenScripts/bug
    INFO[0000] testData directory: testdata
    --- FAIL: TestEdenScripts (0.00s)
        --- FAIL: TestEdenScripts/bug (0.02s)
            testscript.go:382:
                > [!exec:cat] stop
                > cp test.txt TEST.TXT
                > exec cat TOST.TXT
                [stderr]
                /bin/cat: TOST.TXT: No such file or directory
                [exit status 1]
                FAIL: testdata/bug.txt:5: unexpected command failure

    FAIL
    FATA[0000] Test running failed with exit status 1
    $
```

Note that the commands in earlier phases have been hidden, so that the
relevant commands are more easily found, and the elapsed time for a
completed phase is shown next to the phase heading. To see the entire
execution, use "go test -v", which also adds an initial environment dump to
the beginning of the log.

Note also that in reported output, the actual name of the per-script
temporary directory has been consistently replaced with the literal string
$WORK.

If Params.TestWork is true, it causes each test to log the name of its $WORK
directory and other environment variable settings and also to leave that
directory behind when it exits, for manual debugging of failing tests:

```console
    $ ./eden test tests/escript/ -r TestEdenScripts/bug -v debug -a '-testwork'
    DEBU[0000] DIR: tests/escript/
    DEBU[0000] Will use config from /home/user/.eden/contexts/default.yml
    DEBU[0000] Try to add config from /data/work/user/EVE/github/itmo-eve/eden/tests/escript/eden-config.yml
    DEBU[0000] Merged config with /data/work/user/EVE/github/itmo-eve/eden/tests/escript/eden-config.yml
    DEBU[0000] testApp: eden.escript.test
    DEBU[0000] Will use config from /home/user/.eden/contexts/default.yml
    DEBU[0000] Try to add config from /data/work/user/EVE/github/itmo-eve/eden/tests/escript/eden-config.yml
    DEBU[0000] Merged config with /data/work/user/EVE/github/itmo-eve/eden/tests/escript/eden-config.yml
    DEBU[0000] testProg: /home/user/work/EVE/github/itmo-eve/eden/dist/bin/eden.escript.test
    DEBU[0000] Test: /home/user/work/EVE/github/itmo-eve/eden/dist/bin/eden.escript.test -test.run TestEdenScripts/bug -test.v -testwork
    === RUN   TestEdenScripts
    INFO[0000] testData directory: testdata
    === RUN   TestEdenScripts/bug
    === PAUSE TestEdenScripts/bug
    === CONT  TestEdenScripts/bug
        TestEdenScripts/bug: testscript.go:382:
            WORK=/tmp/go-test-script884869182/script-bug
            PATH=/home/user/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/home/user/bin:/home/user/go/bin
            HOME=/no-home
            TMPDIR=$WORK/tmp
            devnull=/dev/null
            /=/
            :=:
            exe=

            > [!exec:cat] stop
            > cp test.txt TEST.TXT
            > exec cat TOST.TXT
            [stderr]
            /bin/cat: TOST.TXT: No such file or directory
            [exit status 1]
            FAIL: testdata/bug.txt:5: unexpected command failure

    --- FAIL: TestEdenScripts (0.00s)
        --- FAIL: TestEdenScripts/bug (0.01s)
    FAIL
    FATA[0000] Test running failed with exit status 1
    $

    $ WORK=/tmp/go-test-script884869182/script-bug
    $ cd $WORK/
    $ cat TEST.TXT
    text for bug test

    $
```
