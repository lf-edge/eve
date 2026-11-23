// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// fakeQemuImg replaces qemu-img with a script. Every call but info exits
// with the next code of exitCodes. info reports the image to have the
// snapshot "snap" if hasSnap is "yes" and none if it is "no"; with anything
// else it fails. It returns functions that list the calls made, as "create",
// "apply", "delete", "info", "check" and "repair", and their command lines.
func fakeQemuImg(t *testing.T, hasSnap string, exitCodes ...string) (calls, cmdLines func() string) {
	t.Helper()
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan")
	callsFile := filepath.Join(dir, "calls")
	argsFile := filepath.Join(dir, "args")
	script := `#!/bin/sh
case "$1 $2" in
"snapshot -c") op=create ;;
"snapshot -a") op=apply ;;
"snapshot -d") op=delete ;;
"check -r") op=repair ;;
check*) op=check ;;
info*) op=info ;;
*) op=unknown ;;
esac
echo "$op" >> "` + callsFile + `"
echo "$*" >> "` + argsFile + `"
if [ $op = info ]; then
	case "` + hasSnap + `" in
	yes) echo '{"snapshots": [{"name": "snap"}]}' ;;
	no) echo '{"snapshots": [{"name": "another"}]}' ;;
	*) echo "cannot open the image" >&2; exit 1 ;;
	esac
	exit 0
fi
code=$(head -n 1 "` + plan + `")
tail -n +2 "` + plan + `" > "` + plan + `.rest"
mv "` + plan + `.rest" "` + plan + `"
exit "${code:-99}"
`
	bin := filepath.Join(dir, "qemu-img")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan, []byte(strings.Join(exitCodes, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedBin, savedWait := qemuImgBin, qemuImgLockWait
	qemuImgBin, qemuImgLockWait = bin, 0
	t.Cleanup(func() { qemuImgBin, qemuImgLockWait = savedBin, savedWait })
	read := func(file string, sep string) func() string {
		return func() string {
			out, _ := os.ReadFile(file)
			return strings.Join(strings.Split(strings.TrimSpace(string(out)), "\n"), sep)
		}
	}
	return read(callsFile, " "), read(argsFile, "\n")
}

// A snapshot command is only good if the image passes its check afterwards.
// An attempt that fails may have been cut off half way, so the image is
// repaired first and the command run once more, unless the image shows that
// it had done its part. Each case lists the exit codes qemu-img returns in
// turn and the calls expected.
func TestSnapshotCommandsRepairAndCheck(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0)
	diskfile := filepath.Join(t.TempDir(), "disk.qcow2")
	if err := os.WriteFile(diskfile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	type op func(context.Context, *base.LogObject, string, string) error
	tests := []struct {
		name        string
		op          op
		hasSnap     string
		exitCodes   []string
		wantCalls   string
		wantErr     string // part of the error, "" for none
		notVerified bool
	}{
		{"clean rollback", ApplySnapshot, "yes", []string{"0", "0"}, "apply check", "", false},
		{"leaks are not damage", ApplySnapshot, "yes", []string{"0", "3"}, "apply check", "", false},
		{"repair and retry", ApplySnapshot, "yes", []string{"1", "0", "0", "0"},
			"apply repair apply check", "", false},
		{"repair fails", ApplySnapshot, "yes", []string{"1", "2"}, "apply repair", "corrupt", true},
		{"retry fails on a sound image", ApplySnapshot, "yes", []string{"1", "0", "1", "0"},
			"apply repair apply check", "first attempt", false},
		{"check fails, repair helps", ApplySnapshot, "yes", []string{"0", "2", "0"},
			"apply check repair", "", false},
		{"check fails, repair does not help", ApplySnapshot, "yes", []string{"0", "2", "2"},
			"apply check repair", "corrupt", true},
		{"image locked for a moment", ApplySnapshot, "yes", []string{"0", "1", "1", "0"},
			"apply check check check", "", false},
		{"check cannot be run", ApplySnapshot, "yes", []string{"0", "1", "1", "1", "1", "1", "1"},
			"apply check check check repair repair repair", "could not be run", true},
		{"unknown answer of the check", ApplySnapshot, "yes", []string{"0", "63", "63"},
			"apply check repair", "could not be run", true},
		{"clean delete", DeleteSnapshot, "yes", []string{"0", "0"}, "delete check", "", false},
		{"delete cut off after the snapshot was gone", DeleteSnapshot, "no", []string{"1", "0", "0"},
			"delete repair info check", "", false},
		{"delete cut off before", DeleteSnapshot, "yes", []string{"1", "0", "0", "0"},
			"delete repair info delete check", "", false},
		{"delete, repair fails", DeleteSnapshot, "yes", []string{"1", "2"}, "delete repair", "corrupt", true},
		{"delete, image cannot be read", DeleteSnapshot, "fails", []string{"1", "0", "0"},
			"delete repair info check", "cannot tell how far it got", false},
		{"clean create", CreateSnapshot, "no", []string{"0", "0"}, "create check", "", false},
		{"create cut off before the snapshot was there", CreateSnapshot, "no", []string{"1", "0", "0", "0"},
			"create repair info create check", "", false},
		{"create cut off after", CreateSnapshot, "yes", []string{"1", "0", "0"},
			"create repair info check", "", false},
		{"create, image cannot be read", CreateSnapshot, "fails", []string{"1", "0", "0"},
			"create repair info check", "cannot tell how far it got", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls, _ := fakeQemuImg(t, tt.hasSnap, tt.exitCodes...)
			err := tt.op(context.Background(), log, diskfile, "snap")
			if got := calls(); got != tt.wantCalls {
				t.Errorf("qemu-img calls: got %q, want %q", got, tt.wantCalls)
			}
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("error: got %v, want one with %q", err, tt.wantErr)
			}
			if errors.Is(err, ErrImageNotVerified) != tt.notVerified {
				t.Errorf("not verified: got %v, want %v", err, tt.notVerified)
			}
			var sound *SoundImageError
			if errors.As(err, &sound) != (err != nil && !tt.notVerified) {
				t.Errorf("sound image: got %v", err)
			}
		})
	}
}

// The repair has to be the one that fixes more than leaks, and the commands
// have to name the snapshot and the image in this order.
func TestSnapshotCommandLines(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0)
	diskfile := filepath.Join(t.TempDir(), "disk.qcow2")
	if err := os.WriteFile(diskfile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, cmdLines := fakeQemuImg(t, "yes", "1", "0", "0", "0")
	if err := DeleteSnapshot(context.Background(), log, diskfile, "snap"); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"snapshot -d snap " + diskfile,
		"check -r all " + diskfile,
		"info --output=json " + diskfile,
		"snapshot -d snap " + diskfile,
		"check " + diskfile,
	}, "\n")
	if got := cmdLines(); got != want {
		t.Errorf("command lines:\ngot\n%s\nwant\n%s", got, want)
	}
}
