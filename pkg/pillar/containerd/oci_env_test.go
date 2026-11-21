// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package containerd

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// shimEnvTests are the cases of TestShimVMEnvironment, and the seeds of
// FuzzShimVMEnvironment.
//
// imageEnv are the variables as the config of the image has them. userEnv are
// the variables of the user-data as domainmgr has parsed them, which is where
// \" has become a double quote already. runcmd tells that the user-data is a
// cloud-config whose runcmd entries give the variables; otherwise it is plain
// NAME=value lines.
var shimEnvTests = []struct {
	name     string
	imageEnv []string
	userEnv  map[string]string
	runcmd   bool
	want     map[string]string
	// kvmOnly is set where the case cannot work on kubevirt, with the reason
	kvmOnly string
}{
	{
		name:     "image value with shell syntax",
		imageEnv: []string{"FROM_IMAGE=home:$HOME sub:$(echo ran) bq:`echo ran` ${ ' \" \\ * ? ; & | < > ( ) # ~"},
		want:     map[string]string{"FROM_IMAGE": "home:$HOME sub:$(echo ran) bq:`echo ran` ${ ' \" \\ * ? ; & | < > ( ) # ~"},
	},
	{
		name:     "image value is a JSON document",
		imageEnv: []string{`FROM_IMAGE=[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`},
		want:     map[string]string{"FROM_IMAGE": `[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`},
	},
	{
		name:     "image value with single quotes",
		imageEnv: []string{`FROM_IMAGE='it's' ''quoted''`},
		want:     map[string]string{"FROM_IMAGE": `'it's' ''quoted''`},
	},
	{
		name:     "image value with a backslash in front of a dollar sign",
		imageEnv: []string{`FROM_IMAGE=\$HOME \\ \`},
		want:     map[string]string{"FROM_IMAGE": `\$HOME \\ \`},
	},
	{
		name:     "image value with a line break",
		imageEnv: []string{"FROM_IMAGE=one\ntwo"},
		want:     map[string]string{"FROM_IMAGE": "one\ntwo"},
	},
	{
		name:     "values without content",
		imageEnv: []string{"FROM_IMAGE="},
		userEnv:  map[string]string{"FROM_USER_DATA": ""},
		want:     map[string]string{"FROM_IMAGE": "", "FROM_USER_DATA": ""},
	},
	{
		name:    "plain lines: value is a JSON document",
		userEnv: map[string]string{"FROM_USER_DATA": `[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`},
		want:    map[string]string{"FROM_USER_DATA": `[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`},
	},
	{
		// a password must not change because some variable happens to
		// have the name of a part of it
		name:     "plain lines: value with dollar signs next to variables of that name",
		imageEnv: []string{"omeR=other", "word=other"},
		userEnv:  map[string]string{"SQL_ROOT_PASSWORD": "$omeR&NdomPa$$word"},
		want:     map[string]string{"SQL_ROOT_PASSWORD": "$omeR&NdomPa$$word"},
	},
	{
		name:    "plain lines: value with shell syntax",
		userEnv: map[string]string{"FROM_USER_DATA": "home:$HOME sub:$(echo ran) bq:`echo ran` ${ ' \" \\ \\$ * ? ; & | < > ( ) # ~"},
		want:    map[string]string{"FROM_USER_DATA": "home:$HOME sub:$(echo ran) bq:`echo ran` ${ ' \" \\ \\$ * ? ; & | < > ( ) # ~"},
	},
	{
		name:    "plain lines: value with a line break",
		userEnv: map[string]string{"FROM_USER_DATA": "one\ntwo"},
		want:    map[string]string{"FROM_USER_DATA": "one\ntwo"},
		kvmOnly: "the init takes the user-data from the cidata disk line by line",
	},
	{
		name:    "runcmd: value is a JSON document",
		userEnv: map[string]string{"FROM_USER_DATA": `[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`},
		runcmd:  true,
		want:    map[string]string{"FROM_USER_DATA": `[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`},
	},
	{
		name:     "runcmd: value refers to a variable and runs a command",
		imageEnv: []string{"FROM_IMAGE=one"},
		userEnv:  map[string]string{"FROM_USER_DATA": "image:$FROM_IMAGE braces:${FROM_IMAGE} sub:$(echo ran) bq:`echo ran`"},
		runcmd:   true,
		want:     map[string]string{"FROM_USER_DATA": "image:one braces:one sub:ran bq:ran"},
	},
	{
		name:     "runcmd: value extends the variable of the image with the same name",
		imageEnv: []string{"SEARCH=/usr/bin"},
		userEnv:  map[string]string{"SEARCH": "$SEARCH:/opt/bin"},
		runcmd:   true,
		want:     map[string]string{"SEARCH": "/usr/bin:/opt/bin"},
	},
	{
		name:    "runcmd: value with a backslash in front of what the shell expands",
		userEnv: map[string]string{"FROM_USER_DATA": "\\$HOME \\`echo no\\`"},
		runcmd:  true,
		want:    map[string]string{"FROM_USER_DATA": "$HOME `echo no`"},
	},
	{
		name:    "runcmd: value with backslashes and quotes",
		userEnv: map[string]string{"FROM_USER_DATA": `\\server\share\ "double" 'single' \"`},
		runcmd:  true,
		want:    map[string]string{"FROM_USER_DATA": `\\server\share\ "double" 'single' \"`},
	},
	{
		name:    "runcmd: value with a line break",
		userEnv: map[string]string{"FROM_USER_DATA": "one\ntwo"},
		runcmd:  true,
		want:    map[string]string{"FROM_USER_DATA": "one\ntwo"},
		kvmOnly: "the init takes the user-data from the cidata disk line by line",
	},
}

// TestShimVMEnvironment checks which environment a container gets which runs
// inside a shim VM, on kvm and on kubevirt, through the init script of the
// shim VM itself.
//
// Where a variable comes from decides what its value means. An image holds
// final values, so a variable of the image has to arrive as it is. The same
// holds for a variable which the user-data gives in a plain NAME=value line.
// An entry of runcmd in a cloud-config is a line of shell: the shell of the
// init expands $NAME, $(command) and backquotes in its value, and everything
// else of the value has to arrive as it is.
func TestShimVMEnvironment(t *testing.T) {
	for _, tt := range shimEnvTests {
		for _, hypervisor := range []string{"kvm", "kubevirt"} {
			t.Run(tt.name+"/"+hypervisor, func(t *testing.T) {
				if hypervisor == "kubevirt" && tt.kvmOnly != "" {
					t.Skipf("not on kubevirt: %s", tt.kvmOnly)
				}
				vm := shimVMFor(hypervisor, tt.imageEnv, tt.userEnv, tt.runcmd)
				env, err := runShimInit(t, vm)
				if err != nil {
					t.Fatalf("the init cannot process the environment: %v\n%s", err, vm)
				}
				for name, want := range tt.want {
					if got, isSet := env[name]; !isSet {
						t.Errorf("the variable %s is missing\n%s", name, vm)
					} else if got != want {
						t.Errorf("the variable %s is not what the container has to get\n"+
							"want: %q\n got: %q\n%s", name, want, got, vm)
					}
				}
			})
		}
	}
}

// FuzzShimVMEnvironment tries arbitrary values on what TestShimVMEnvironment
// checks with a few: a value of the image arrives as it is, and so does a
// value of the user-data, unless it is an entry of runcmd in which the shell
// has something to expand.
func FuzzShimVMEnvironment(f *testing.F) {
	for _, tt := range shimEnvTests {
		var imageValue string
		if len(tt.imageEnv) > 0 {
			_, imageValue, _ = strings.Cut(tt.imageEnv[0], "=")
		}
		for _, userValue := range tt.userEnv {
			f.Add(imageValue, userValue, tt.runcmd)
		}
		if len(tt.userEnv) == 0 {
			f.Add(imageValue, imageValue, false)
			f.Add(imageValue, imageValue, true)
		}
	}
	f.Add("\x01\x7f\x81\x88\xff ü 日本", "one\rtwo\ttabs  and spaces  ", false)
	f.Add("\x01\x7f\x81\x88\xff ü 日本", "one\rtwo\ttabs  and spaces  ", true)
	f.Fuzz(func(t *testing.T, imageValue, userValue string, runcmd bool) {
		// No environment variable can hold a NUL byte, and what one argument
		// of a program can hold bounds a variable anyway.
		if strings.ContainsRune(imageValue+userValue, 0) || len(imageValue)+len(userValue) > 64*1024 {
			t.Skip("not a value of an environment variable")
		}
		imageEnv := []string{"FROM_IMAGE=" + imageValue}
		for _, hypervisor := range []string{"kvm", "kubevirt"} {
			userEnv := map[string]string{"FROM_USER_DATA": userValue}
			switch {
			case runcmd && strings.ContainsAny(userValue, "$`"):
				// What the shell makes of this value is its own business: it
				// expands it, or it refuses it. Only the image is tried.
				userEnv = nil
			case hypervisor == "kubevirt" && strings.Contains(userValue, "\n"):
				// On kubevirt the init takes the user-data from the cidata
				// disk line by line.
				userEnv = nil
			}
			vm := shimVMFor(hypervisor, imageEnv, userEnv, runcmd)
			env, err := runShimInit(t, vm)
			if err != nil {
				t.Fatalf("%s: the init cannot process the environment: %v\n%s", hypervisor, err, vm)
			}
			if got, isSet := env["FROM_IMAGE"]; !isSet || got != imageValue {
				t.Errorf("%s: the value of the image changed\nwant: %q\n got: %q\n%s",
					hypervisor, imageValue, got, vm)
			}
			if userEnv == nil {
				continue
			}
			if got, isSet := env["FROM_USER_DATA"]; !isSet || got != userValue {
				t.Errorf("%s: the value of the user-data changed\nwant: %q\n got: %q\n%s",
					hypervisor, userValue, got, vm)
			}
		}
	})
}

// TestShimVMEnvironmentBrokenShellText checks what follows from an entry of
// runcmd being a line of shell: if the shell cannot process it, the init does
// not start the container, it ends with the exit status for wrong input data.
// The same text in a plain line is a value as any other.
func TestShimVMEnvironmentBrokenShellText(t *testing.T) {
	const text = "no closing brace: ${FROM_IMAGE"
	for _, hypervisor := range []string{"kvm", "kubevirt"} {
		t.Run("runcmd/"+hypervisor, func(t *testing.T) {
			vm := shimVMFor(hypervisor, []string{"FROM_IMAGE=one"},
				map[string]string{"FROM_USER_DATA": text}, true)
			env, err := runShimInit(t, vm)
			if err == nil {
				t.Fatalf("the init started the container with %q\n%s", env["FROM_USER_DATA"], vm)
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 65 {
				t.Errorf("the init did not end with exit status 65: %v", err)
			}
		})
		t.Run("plain lines/"+hypervisor, func(t *testing.T) {
			vm := shimVMFor(hypervisor, []string{"FROM_IMAGE=one"},
				map[string]string{"FROM_USER_DATA": text}, false)
			env, err := runShimInit(t, vm)
			if err != nil {
				t.Fatalf("the init cannot process the environment: %v\n%s", err, vm)
			}
			if got := env["FROM_USER_DATA"]; got != text {
				t.Errorf("the value changed\nwant: %q\n got: %q\n%s", text, got, vm)
			}
		})
	}
}

// shimVMFor gives what the init of a shim VM finds, for a container with the
// given variables of its image and of its user-data. runcmd tells that the
// user-data is a cloud-config, whose values the shell expands.
//
// On kvm pillar renders all of them into the environment file at every start
// of the VM, see AddLoader. On kubevirt the variables of the image are in the
// volume of the container, where PrepareContainerRootDir of cas has put them,
// and the ones of the user-data come on a cidata disk, as envVarsToUserData
// of domainmgr renders them.
func shimVMFor(hypervisor string, imageEnv []string, userEnv map[string]string, runcmd bool) shimVM {
	if hypervisor == "kvm" {
		spec := ociSpec{Spec: specs.Spec{Process: &specs.Process{Cwd: "/", Env: imageEnv}}}
		spec.UpdateEnvVar(userEnv, runcmd)
		return shimVM{cmdline: kvmCmdline, environment: spec.envManifest()}
	}
	names := make([]string, 0, len(userEnv))
	for name := range userEnv {
		names = append(names, name)
	}
	sort.Strings(names)
	quote := ShellLiteral
	if runcmd {
		quote = ShellExpanded
	}
	var userData strings.Builder
	for _, name := range names {
		fmt.Fprintf(&userData, "%s=%s\n", name, quote(userEnv[name]))
	}
	return shimVM{
		cmdline:     kubevirtCmdline,
		environment: ShimEnvManifest("/", imageEnv, nil, false),
		userData:    userData.String(),
	}
}

// shimInitTools are the busybox tools which the init script gets for real:
// they only read, or they write below the root directory of the run.
var shimInitTools = []string{"sh", "awk", "cat", "cut", "env", "grep", "ln", "mkdir", "rmdir", "sleep", "tee", "tr"}

// shimInitStandIns are the commands of the init script which act on the
// machine. In the root directory of the run they only note that they were
// called. Any other command does not exist there, so it cannot do anything.
var shimInitStandIns = []string{"/bin/busybox", "/bin/mount", "/bin/umount", "/bin/mountpoint",
	"/bin/modprobe", "/bin/acpid", "/bin/blkid", "/sbin/poweroff", "/mount_disk.sh"}

// shimVM is what the init of a shim VM finds when it starts.
type shimVM struct {
	// cmdline is the kernel command line. It tells the init how the VM got
	// the root file system of the container, and which console it has.
	cmdline string
	// environment is the content of the environment file, /mnt/environment.
	environment string
	// userData is the user-data on the cidata disk which domainmgr attaches
	// to a kubevirt shim VM. Without it the VM has no such disk.
	userData string
}

func (vm shimVM) String() string {
	return fmt.Sprintf("kernel command line: %s\nenvironment file:\n%s\nuser-data:\n%s",
		vm.cmdline, vm.environment, vm.userData)
}

// The kernel command lines of the shim VMs, as far as the init acts on them
// here. On kvm, zedmanager makes the root file system a 9p share. On
// kubevirt, hypervisor/kubevirt.go makes it the volume of the container, and
// the console is tty0.
const (
	kvmCmdline      = "console=hvc0 root=9p"
	kubevirtCmdline = "console=tty0 root=/dev/vda"
)

// runShimInit runs the init script of the shim VM, initrd/init-initrd, as it
// is, and returns the environment which the init starts the container with.
//
// The script is the init of a VM: it mounts file systems, loads modules and
// powers the machine off at the end. So it runs inside a root directory of
// its own, which holds a shell, the harmless tools the script uses, and
// stand-ins for everything else. /chroot2, through which the init starts the
// container, is such a stand-in: it records the environment it is started
// with.
//
// The test is skipped where the script cannot run this way: without busybox,
// and where neither a user namespace nor root lets the test enter the
// directory.
func runShimInit(t *testing.T, vm shimVM) (map[string]string, error) {
	t.Helper()

	busybox, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("busybox is needed to run the init script of the shim VM")
	}
	script, err := os.ReadFile(filepath.Join("..", "initrd", "init-initrd"))
	if err != nil {
		t.Fatalf("failed to read the init script of the shim VM: %v", err)
	}

	root := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		file := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	installProgram(t, busybox, root, "/bin/.busybox")
	for _, tool := range shimInitTools {
		if err := os.Symlink(".busybox", filepath.Join(root, "bin", tool)); err != nil {
			t.Fatal(err)
		}
	}
	for _, standIn := range shimInitStandIns {
		write(standIn, "#!/bin/sh\necho \"$0 $*\" >> /calls\n", 0755)
	}
	// the init keeps a login prompt running in the background
	write("/bin/setsid", "#!/bin/sh\nkill -9 \"$PPID\"\n", 0755)
	// a NUL byte ends each variable, as a value may have line breaks
	write("/chroot2", "#!/bin/sh\nenv -0 > /chroot2.env\n", 0755)

	// what the init finds when it starts
	write("/proc/cmdline", vm.cmdline+"\n", 0644)
	write("/proc/cgroups", "", 0644)
	for _, device := range []string{"/dev/null", "/dev/console", "/dev/kmsg"} {
		write(device, "", 0666)
	}
	for _, dir := range []string{"/sys", "/lib/modules", "/mnt/rootfs", "/mnt/modules"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write("/mnt/environment", vm.environment, 0644)
	if vm.userData != "" {
		// The cidata disk: blkid reports it. Its content is already where
		// the init mounts it, because mount is a stand-in.
		write("/bin/blkid", "#!/bin/sh\necho '/dev/vdb: LABEL=\"cidata\" TYPE=\"iso9660\"'\n", 0755)
		write("/cidata/user-data", vm.userData, 0644)
	}
	write("/mnt/cmdline", `"/entrypoint.sh"`, 0644)
	write("/init-initrd", string(script), 0755)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, err := os.Create(filepath.Join(root, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()

	// runs the shell of the root directory inside it
	inRoot := func(attr *syscall.SysProcAttr, arg ...string) error {
		cmd := exec.CommandContext(ctx, "/bin/sh", arg...)
		cmd.Dir = "/"
		cmd.Env = []string{"HOME=/", "TERM=linux"}
		cmd.Stdout, cmd.Stderr = output, output
		cmd.SysProcAttr = attr
		err := cmd.Run()
		if attr.Setpgid && cmd.Process != nil {
			// nothing else ends what the init has left running
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return err
	}

	// A user namespace lets an ordinary user enter the root directory, and
	// its PID namespace ends everything the init has started when it exits.
	// Where that is not allowed, as in a container, root can still chroot.
	ways := []*syscall.SysProcAttr{{
		Chroot:      root,
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}}
	if os.Geteuid() == 0 {
		ways = append(ways, &syscall.SysProcAttr{Chroot: root, Setpgid: true})
	}
	var way *syscall.SysProcAttr
	var reasons []string
	for _, attr := range ways {
		err := inRoot(attr, "-c", "exit 0")
		if err == nil {
			way = attr
			break
		}
		reasons = append(reasons, err.Error())
	}
	if way == nil {
		t.Skipf("cannot run the init script of the shim VM in a root directory of its own: %s",
			strings.Join(reasons, "; "))
	}

	err = inRoot(way, "/init-initrd")
	printed, _ := os.ReadFile(output.Name())
	if err != nil {
		return nil, fmt.Errorf("the init script failed: %w\n%s", err, printed)
	}
	recorded, err := os.ReadFile(filepath.Join(root, "chroot2.env"))
	if err != nil {
		return nil, fmt.Errorf("the init did not start the container: %w\n%s", err, printed)
	}

	env := map[string]string{}
	for _, entry := range strings.Split(string(recorded), "\x00") {
		if name, value, found := strings.Cut(entry, "="); found {
			env[name] = value
		}
	}
	return env, nil
}

// installProgram copies a program into a root directory, together with the
// dynamic loader and the libraries it needs if it is not linked statically.
func installProgram(t *testing.T, program, root, target string) {
	t.Helper()

	copyFile := func(from, to string) {
		t.Helper()
		content, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(to), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, content, 0755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(program, filepath.Join(root, target))

	binary, err := elf.Open(program)
	if err != nil {
		t.Fatalf("failed to read %s: %v", program, err)
	}
	defer binary.Close()
	for _, prog := range binary.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		loader, err := io.ReadAll(prog.Open())
		if err != nil {
			t.Fatal(err)
		}
		path := strings.TrimRight(string(loader), "\x00")
		copyFile(path, filepath.Join(root, path))
	}
	libraries, err := binary.ImportedLibraries()
	if err != nil {
		t.Fatal(err)
	}
	dirs := []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64"}
	for _, pattern := range []string{"/lib/*-linux-*", "/usr/lib/*-linux-*"} {
		multiarch, _ := filepath.Glob(pattern)
		dirs = append(dirs, multiarch...)
	}
	for _, library := range libraries {
		for _, dir := range dirs {
			path := filepath.Join(dir, library)
			// a directory may hold the library for another architecture
			candidate, err := elf.Open(path)
			if err != nil {
				continue
			}
			fits := candidate.Class == binary.Class && candidate.Machine == binary.Machine
			candidate.Close()
			if fits {
				copyFile(path, filepath.Join(root, path))
				break
			}
		}
	}
}
