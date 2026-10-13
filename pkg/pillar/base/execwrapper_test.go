package base_test

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

func TestTimeoutLongerThanLimit(t *testing.T) {
	t.Parallel()

	timeout := 600 * time.Second
	_, err := base.Exec(nil, "/bin/true").WithLimitedTimeout(timeout).CombinedOutput()
	if err == nil {
		t.Fatalf("Execution should fail with timeout too long, but succeeded")
	}
}

func TestErrorOutputReturnsOnlyStderr(t *testing.T) {
	t.Parallel()

	out, err := base.Exec(nil, "/bin/sh", "-c",
		"echo progress-frame; echo the-real-error >&2; exit 3").ErrorOutput()
	if err == nil {
		t.Fatal("expected the exit status error, got nil")
	}
	got := strings.TrimSpace(string(out))
	if got != "the-real-error" {
		t.Errorf("ErrorOutput() = %q, want only the stderr line", got)
	}
}
