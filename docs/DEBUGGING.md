# Debugging

This document describes various scenarios and how to debug them. It is a living document to which elements will be added.

## Live updates of system containers

In order to aid rapid edit/compile/debug cycle EVE's storage-init container can be instructed to dynamically
substitute systems containers with a copy under `/persist/service`. This requires building a special EVE image
with the code block at the bottom of [storage-init.sh](../pkg/storage-init/storage-init.sh) uncommented. Once
that image is ready, content of the `/persist/service/<service name>` will be made available as a rootfs of
the `<service name>`. For example, in order to rapidly iterate on pillar services one can:

```
cp -r /containers/services/pillar/lower /persist/service/pillar
# edit content under /persist/service/pillar
# reboot and enjoy updates to the pillar container
``` 

## Reboots

EVE is architected in such a way that if any service is unresponsive for a period of time, the entire device will reboot. To track
down the source of reboots, follow this process:

1. Go to the log directory. These are in `/var/persist/{IMGA,IMGB}/logs/` when on the base operating system, and `/persist/{IMGA,IMGB}/logs/` when in pillar via `eve enter`
1. Check for the reason for reboot by looking in `device-steps.log` for the phrase `reboot-reason`. There will be lines that indicate the reason for the last reboot.
1. Using the output, determine which agent was unresponsive, causing watchdog to reboot it.
1. Look at the log for the particular agent as `<agent>.log`.
1. Find the line that shows the dumped stack right before watchdog invoked a reboot. The stack was dumped by watchdog sending a `SIGUSR1` to the process. Thus, search the logfile for `SIGUSR1`.
1. Look through the stack trace to see the various goroutines and why it is stuck.

### Reboot Example

Check for the reason for reboot in `device-steps.log

```sh
$ grep reboot-reason device-steps.log
IMGA reboot-reason: Watchdog report at 2020-01-16T22:00:15,757460668+00:00: 250 /var/run/nim.touch
Common reboot-reason: Watchdog report at 2020-01-16T22:00:15,757460668+00:00: 250 /var/run/nim.touch
```

The watchdog rebooted the device because the nim agent was unresponsive, as indicated by it not touching the flag file /var/run/nim.touch in 300 seconds

Now we can look for the stack by finding `SIGUSR1` in `nim.log`:

```sh
$ grep SIGUSR1 nim.log
<very long and messy output>
```

The output will be a single long line with carriage returns and tabs as escaped characters. Fix it by replacing the characters and dumping them to a file:

```sh
$ grep SIGUSR1 nim.log | sed 's/\\n/\'$'\n''/g' | sed 's/\\t/\'$'\t''/g'
{"file":"/pillar/agentlog/agentlog.go:71","func":"github.com/lf-edge/eve/pkg/pillar/agentlog.handleSignals","level":"warning","msg":"SIGUSR1 triggered stack traces:
goroutine 10 [running]:
github.com/lf-edge/eve/pkg/pillar/agentlog.getStacks(0xc000080101, 0xc000000004, 0x1465007)
	/pillar/agentlog/agentlog.go:218 +0x78
github.com/lf-edge/eve/pkg/pillar/agentlog.handleSignals(0xc00055a300)
	/pillar/agentlog/agentlog.go:72 +0x174
created by github.com/lf-edge/eve/pkg/pillar/agentlog.initImpl
	/pillar/agentlog/agentlog.go:58 +0x31b

goroutine 1 [chan receive, 6 minutes]:
github.com/lf-edge/eve/pkg/pillar/cmd/nim.Run()
	/pillar/cmd/nim/nim.go:258 +0x13ab
main.main()
	/pillar/zedbox/zedbox.go:56 +0x13e

goroutine 5 [syscall]:
os/signal.signal_recv(0x17874a0)
	/usr/local/go/src/runtime/sigqueue.go:139 +0x9c
os/signal.loop()
	/usr/local/go/src/os/signal/signal_unix.go:23 +0x22
created by os/signal.init.0
	/usr/local/go/src/os/signal/signal_unix.go:29 +0x41

goroutine 8 [select]:
go.opencensus.io/stats/view.(*worker).start(0xc0002a5180)
	/pillar/vendor/go.opencensus.io/stats/view/worker.go:154 +0x100
created by go.opencensus.io/stats/view.init.0
	/pillar/vendor/go.opencensus.io/stats/view/worker.go:32 +0x57

goroutine 11 [IO wait, 2 minutes]:
internal/poll.runtime_pollWait(0x7fdeb06117d0, 0x72, 0x0)
	/usr/local/go/src/runtime/netpoll.go:182 +0x56
internal/poll.(*pollDesc).wait(0xc000524818, 0x72, 0x0, 0x0, 0x1436903)
	/usr/local/go/src/internal/poll/fd_poll_runtime.go:87 +0x9b
internal/poll.(*pollDesc).waitRead(...)
	/usr/local/go/src/internal/poll/fd_poll_runtime.go:92
internal/poll.(*FD).Accept(0xc000524800, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/usr/local/go/src/internal/poll/fd_unix.go:384 +0x1ba
net.(*netFD).accept(0xc000524800, 0xc000010040, 0x0, 0x0)
	/usr/local/go/src/net/fd_unix.go:238 +0x42
net.(*UnixListener).accept(0xc000567290, 0xc00006af60, 0xc00006af68, 0x20)
	/usr/local/go/src/net/unixsock_posix.go:162 +0x32
net.(*UnixListener).Accept(0xc000567290, 0x14b04e0, 0xc0003e7560, 0x17aec80, 0xc000010040)
	/usr/local/go/src/net/unixsock.go:260 +0x48
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1(0xc0003e7560)
	/pillar/pubsub/socketdriver/publish.go:108 +0x42
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start
	/pillar/pubsub/socketdriver/publish.go:105 +0x46

goroutine 12 [IO wait, 6 minutes]:
internal/poll.runtime_pollWait(0x7fdeb0611700, 0x72, 0x0)
	/usr/local/go/src/runtime/netpoll.go:182 +0x56
internal/poll.(*pollDesc).wait(0xc000524d98, 0x72, 0x0, 0x0, 0x1436903)
	/usr/local/go/src/internal/poll/fd_poll_runtime.go:87 +0x9b
internal/poll.(*pollDesc).waitRead(...)
	/usr/local/go/src/internal/poll/fd_poll_runtime.go:92
internal/poll.(*FD).Accept(0xc000524d80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/usr/local/go/src/internal/poll/fd_unix.go:384 +0x1ba
net.(*netFD).accept(0xc000524d80, 0xc000010768, 0x0, 0x0)
	/usr/local/go/src/net/fd_unix.go:238 +0x42
net.(*UnixListener).accept(0xc000567920, 0xc000067f60, 0xc000067f68, 0x20)
	/usr/local/go/src/net/unixsock_posix.go:162 +0x32
net.(*UnixListener).Accept(0xc000567920, 0x14b04e0, 0xc0003e7680, 0x17aec80, 0xc000010768)
	/usr/local/go/src/net/unixsock.go:260 +0x48
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1(0xc0003e7680)
	/pillar/pubsub/socketdriver/publish.go:108 +0x42
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start
	/pillar/pubsub/socketdriver/publish.go:105 +0x46

goroutine 13 [IO wait, 6 minutes]:
internal/poll.runtime_pollWait(0x7fdeb0611630, 0x72, 0x0)
	/usr/local/go/src/runtime/netpoll.go:182 +0x56
internal/poll.(*pollDesc).wait(0xc000525318, 0x72, 0x0, 0x0, 0x1436903)
	/usr/local/go/src/internal/poll/fd_poll_runtime.go:87 +0x9b
internal/poll.(*pollDesc).waitRead(...)
	/usr/local/go/src/internal/poll/fd_poll_runtime.go:92
internal/poll.(*FD).Accept(0xc000525300, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/usr/local/go/src/internal/poll/fd_unix.go:384 +0x1ba
net.(*netFD).accept(0xc000525300, 0x0, 0x0, 0x0)
	/usr/local/go/src/net/fd_unix.go:238 +0x42
net.(*UnixListener).accept(0xc00003d770, 0x0, 0x0, 0x0)
	/usr/local/go/src/net/unixsock_posix.go:162 +0x32
net.(*UnixListener).Accept(0xc00003d770, 0x0, 0x0, 0x0, 0x0)
	/usr/local/go/src/net/unixsock.go:260 +0x48
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1(0xc0003e7710)
	/pillar/pubsub/socketdriver/publish.go:108 +0x42
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start
	/pillar/pubsub/socketdriver/publish.go:105 +0x46

goroutine 14 [sleep]:
runtime.goparkunlock(...)
	/usr/local/go/src/runtime/proc.go:307
time.Sleep(0x2540be400)
	/usr/local/go/src/runtime/time.go:105 +0x159
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).connectAndRead(0xc00055b200, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/pillar/pubsub/socketdriver/subscribe.go:104 +0x1ba1
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).watchSock(0xc00055b200)
	/pillar/pubsub/socketdriver/subscribe.go:68 +0x40
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).Start
	/pillar/pubsub/socketdriver/subscribe.go:58 +0x267

goroutine 15 [sleep]:
runtime.goparkunlock(...)
	/usr/local/go/src/runtime/proc.go:307
time.Sleep(0x2540be400)
	/usr/local/go/src/runtime/time.go:105 +0x159
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).connectAndRead(0xc00055b5c0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/pillar/pubsub/socketdriver/subscribe.go:104 +0x1ba1
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).watchSock(0xc00055b5c0)
	/pillar/pubsub/socketdriver/subscribe.go:68 +0x40
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).Start
	/pillar/pubsub/socketdriver/subscribe.go:58 +0x267

goroutine 16 [sleep]:
runtime.goparkunlock(...)
	/usr/local/go/src/runtime/proc.go:307
time.Sleep(0x2540be400)
	/usr/local/go/src/runtime/time.go:105 +0x159
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).connectAndRead(0xc00055b680, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/pillar/pubsub/socketdriver/subscribe.go:104 +0x1ba1
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).watchSock(0xc00055b680)
	/pillar/pubsub/socketdriver/subscribe.go:68 +0x40
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).Start
	/pillar/pubsub/socketdriver/subscribe.go:58 +0x267

goroutine 18 [chan send, 6 minutes]:
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).watchSock(0xc00055b7a0)
	/pillar/pubsub/socketdriver/subscribe.go:76 +0x1f3
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).Start
	/pillar/pubsub/socketdriver/subscribe.go:58 +0x267

goroutine 19 [sleep]:
runtime.goparkunlock(...)
	/usr/local/go/src/runtime/proc.go:307
time.Sleep(0x2540be400)
	/usr/local/go/src/runtime/time.go:105 +0x159
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).connectAndRead(0xc00055b860, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	/pillar/pubsub/socketdriver/subscribe.go:104 +0x1ba1
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).watchSock(0xc00055b860)
	/pillar/pubsub/socketdriver/subscribe.go:68 +0x40
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).Start
	/pillar/pubsub/socketdriver/subscribe.go:58 +0x267

goroutine 20 [sleep]:
runtime.goparkunlock(...)
	/usr/local/go/src/runtime/proc.go:307
time.Sleep(0x2540be400)
	/usr/local/go/src/runtime/time.go:105 +0x159
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).connectAndRead(0xc00055b920, 0x270, 0x280, 0xc0001d8780, 0xc0000d8fe0, 0x627be5, 0x2235fc0)
	/pillar/pubsub/socketdriver/subscribe.go:104 +0x1ba1
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).watchSock(0xc00055b920)
	/pillar/pubsub/socketdriver/subscribe.go:68 +0x40
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Subscriber).Start
	/pillar/pubsub/socketdriver/subscribe.go:58 +0x267

goroutine 21 [chan receive, 6 minutes]:
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).serveConnection(0xc0003e7680, 0x17aec80, 0xc000010768, 0x0)
	/pillar/pubsub/socketdriver/publish.go:203 +0xa83
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1
	/pillar/pubsub/socketdriver/publish.go:113 +0x155

goroutine 22 [chan receive, 6 minutes]:
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).serveConnection(0xc0003e7560, 0x17aec80, 0xc0000108e0, 0x0)
	/pillar/pubsub/socketdriver/publish.go:203 +0xa83
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1
	/pillar/pubsub/socketdriver/publish.go:113 +0x155

goroutine 23 [chan receive, 6 minutes]:
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).serveConnection(0xc0003e7560, 0x17aec80, 0xc0000108e8, 0x1)
	/pillar/pubsub/socketdriver/publish.go:203 +0xa83
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1
	/pillar/pubsub/socketdriver/publish.go:113 +0x155

goroutine 24 [chan receive, 6 minutes]:
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).serveConnection(0xc0003e7560, 0x17aec80, 0xc0000108f0, 0x2)
	/pillar/pubsub/socketdriver/publish.go:203 +0xa83
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1
	/pillar/pubsub/socketdriver/publish.go:113 +0x155

goroutine 25 [chan receive, 2 minutes]:
github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).serveConnection(0xc0003e7560, 0x17aec80, 0xc000010040, 0x3)
	/pillar/pubsub/socketdriver/publish.go:203 +0xa83
created by github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).Start.func1
	/pillar/pubsub/socketdriver/publish.go:113 +0x155

","time":"2020-01-16T22:00:18.428537758Z"}
```

Looking at the above, we can see all of the go routines. Specifically, the `main` routine shows where it is processing and in which file.

### Log Files in QEMU

If you are running in qemu and want to pull the log files off, use the following utility:

```sh
tools/extract-persist.sh [<type>] [<arch>]
```

It will extract the contents of the `/persist` partition to `./tmp/persist.tgz` for the given type and architecture.

* `type`: either `live` or `installer`. Defaults to `live`.
* `arch`: any supported architecture, currently `arm64` or `amd64`. Defaults to `amd64`.

