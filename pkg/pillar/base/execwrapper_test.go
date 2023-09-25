package base_test

import (
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
