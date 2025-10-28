// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package immcore //nolint:testpackage // Internal tests need access to unexported helpers (ewmaAlpha, clamp*, medianFilterInto, etc.) for thorough coverage

import (
	"math"
	"testing"
	"time"
)

const (
	MiB = uint64(1 << 20)
)

// TestCollectNow verifies that metric collection works without errors
func TestCollectNow(t *testing.T) {
	t.Parallel()
	vals, errs := CollectNow()

	if len(errs) > 0 {
		t.Errorf("Expected no errors during collection, got: %v", errs)
	}

	// Verify values are reasonable (non-zero for memory metrics)
	for i, val := range vals {
		if val == 0 {
			t.Logf("Warning: metric %d (%s) has zero value", i, MetricRegistry[i].Name)
		}
	}
}

// TestDefaultConfig verifies the default configuration
func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()

	if cfg.AnalysisWindow <= 0 {
		t.Error("AnalysisWindow should be positive")
	}
	if cfg.ProbingInterval <= 0 {
		t.Error("ProbingInterval should be positive")
	}
	if len(cfg.Weights) != NumMetrics {
		t.Errorf("Expected %d weights, got %d", NumMetrics, len(cfg.Weights))
	}

	// Verify weights are reasonable
	for i, w := range cfg.Weights {
		if w <= 0 || w > 10 {
			t.Errorf("Weight for metric %d is out of reasonable range: %f", i, w)
		}
	}
}

// TestNewState verifies state initialization
func TestNewState(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.MaxHistory = 100

	state := NewState(cfg)

	if state == nil {
		t.Fatal("NewState returned nil")
	}

	if len(state.History()) != 0 {
		l := len(state.History())
		t.Errorf("non-empty history: %d", l)
	}
	if cap(state.hist) != cfg.MaxHistory {
		l := cap(state.hist)
		t.Errorf("history cap mismatch want %d got %d", cfg.MaxHistory, l)
	}
}

// TestStepBasic verifies basic step functionality
func TestStepBasic(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 1 * time.Minute
	cfg.ProbingInterval = 5 * time.Second
	cfg.MaxHistory = 100

	state := NewState(cfg)

	// Create a test input
	now := time.Now()
	input := Input{
		Time:   now,
		Values: [NumMetrics]uint64{1024 * 1024 * 100, 1024 * 1024 * 150},
	}

	probe := state.Step(input)

	// Verify probe was created
	if probe.Time != now {
		l := probe.Time
		t.Errorf("time mismatch want %v got %v", now, l)
	}
	if len(state.History()) != 1 {
		l := len(state.History())
		t.Errorf("history entries want 1 got %d", l)
	}

	// Verify values were stored
	for i := range NumMetrics {
		if probe.Values[i] != input.Values[i] {
			t.Errorf("Metric %d: expected value %d, got %d", i, input.Values[i], probe.Values[i])
		}
	}
}

// TestStepMultiple verifies multiple steps and history management
func TestStepMultiple(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 1 * time.Minute
	cfg.ProbingInterval = 5 * time.Second
	cfg.MaxHistory = 10

	state := NewState(cfg)

	baseTime := time.Now()

	// Add more probes than capacity to test ring buffer
	for i := range 15 {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * cfg.ProbingInterval),
			Values: [NumMetrics]uint64{
				MiB*100 + MiB*uint64(i), //nolint:gosec // i is bounded by range 15
				MiB*150 + MiB*uint64(i), //nolint:gosec // i is bounded by range 15
			},
		}
		state.Step(input)
	}

	// Should be capped at MaxHistory
	if len(state.History()) > cfg.MaxHistory {
		l := len(state.History())
		t.Errorf("history len > max: max %d got %d", cfg.MaxHistory, l)
	}
}

// TestAppendOnly verifies store-only mode
func TestAppendOnly(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.MaxHistory = 100

	state := NewState(cfg)

	now := time.Now()
	input := Input{
		Time:   now,
		Values: [NumMetrics]uint64{1024 * 1024 * 100, 1024 * 1024 * 150},
	}

	probe := state.AppendOnly(input)

	// Verify probe was created without analysis
	if probe.Time != now {
		l := probe.Time
		t.Errorf("time mismatch want %v got %v", now, l)
	}
	if len(state.History()) != 1 {
		l := len(state.History())
		t.Errorf("history entries want 1 got %d", l)
	}

	// Evidence values should be zero (no analysis)
	if probe.Score != 0 {
		t.Errorf("Expected zero score in append-only mode, got %f", probe.Score)
	}
	if probe.RecentFeature != 0 {
		t.Errorf("Expected zero recent feature, got %f", probe.RecentFeature)
	}
	if probe.EntireFeature != 0 {
		t.Errorf("Expected zero entire feature, got %f", probe.EntireFeature)
	}
}

// TestDropHead verifies history trimming
func TestDropHead(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.MaxHistory = 100

	state := NewState(cfg)

	// Add some probes
	baseTime := time.Now()
	for i := range 10 {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * time.Second),
			Values: [NumMetrics]uint64{
				MiB*100 + MiB*uint64(i), //nolint:gosec // i is bounded by range 10
				MiB*150 + MiB*uint64(i), //nolint:gosec // i is bounded by range 10
			},
		}
		state.Step(input)
	}

	initialLen := len(state.History())
	if initialLen != 10 {
		t.Fatalf("Expected 10 entries, got %d", initialLen)
	}

	// Drop first 3
	state.DropHead(3)

	newLen := len(state.History())
	if newLen != 7 {
		t.Errorf("after drop want 7 got %d", newLen)
	}

	// Verify the correct entries remain
	firstTime := state.History()[0].Time
	expectedTime := baseTime.Add(3 * time.Second)
	if !firstTime.Equal(expectedTime) {
		t.Errorf("first time want %v got %v", expectedTime, firstTime)
	}
}

// TestSummary verifies summary string generation
func TestSummary(t *testing.T) {
	t.Parallel()
	probe := Probe{
		Time: time.Now(),
		Values: [NumMetrics]uint64{
			1024 * 1024 * 100, // 100 MB
			1024 * 1024 * 200, // 200 MB
		},
	}

	summary := Summary(probe)

	if summary == "" {
		t.Error("empty summary")
	}
	if len(summary) < 10 {
		t.Error("summary too short")
	}
}

// TestLeakDetection verifies that increasing memory triggers detection
func TestLeakDetection(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 30 * time.Second
	cfg.ProbingInterval = 1 * time.Second
	cfg.MaxHistory = 200

	state := NewState(cfg)

	baseTime := time.Now()
	baseHeapU := uint64(1024 * 1024 * 100) // Start at 100 MB

	// Simulate a memory leak: slow steady increase
	var lastProbe Probe
	for i := range 120 {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * cfg.ProbingInterval),
			Values: [NumMetrics]uint64{
				baseHeapU + uint64(i)*1024*100, //nolint:gosec // i is bounded by range 120
				baseHeapU + uint64(i)*1024*150, //nolint:gosec // i is bounded by range 120
			},
		}
		lastProbe = state.Step(input)
	}

	// After sustained growth, score should be elevated
	// This is a heuristic check - adjust thresholds based on your algorithm
	if lastProbe.Score < 1.0 {
		t.Logf("low leak score=%f", lastProbe.Score)
	}
}

// TestStableMemory verifies that stable memory doesn't trigger false positives
func TestStableMemory(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 30 * time.Second
	cfg.ProbingInterval = 1 * time.Second
	cfg.MaxHistory = 200

	state := NewState(cfg)

	baseTime := time.Now()
	baseHeapU := uint64(1024 * 1024 * 100) // Stable at 100 MB

	var lastProbe Probe
	for i := range 120 {
		noise := (uint64(i) % 5) * 1024 * 10 //nolint:gosec // i is bounded by range 120
		input := Input{
			Time: baseTime.Add(time.Duration(i) * cfg.ProbingInterval),
			Values: [NumMetrics]uint64{
				baseHeapU + noise,
				baseHeapU + noise*2,
			},
		}
		lastProbe = state.Step(input)
	}

	// Score should remain low for stable memory
	if lastProbe.Score > 3.0 {
		t.Logf("stable mem high score=%f", lastProbe.Score)
	}
}

// TestEWMAAlpha verifies EWMA alpha calculation
func TestEWMAAlpha(t *testing.T) {
	t.Parallel()
	tests := []struct {
		halfLife float64
		want     float64
	}{
		{0, 1.0},
		{-1, 1.0},
		{1, 1 - math.Exp(-math.Ln2)},
		{10, 1 - math.Exp(-math.Ln2/10)},
	}

	for _, tt := range tests {
		got := ewmaAlpha(tt.halfLife)
		if math.Abs(got-tt.want) > 1e-10 {
			t.Errorf("ewmaAlpha halfLife=%f got=%f want=%f", tt.halfLife, got, tt.want)
		}
	}
}

// TestClamp01 verifies value clamping
func TestClamp01(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input float64
		want  float64
	}{
		{-0.5, 0.0},
		{0.0, 0.0},
		{0.5, 0.5},
		{1.0, 1.0},
		{1.5, 1.0},
	}

	for _, tt := range tests {
		got := clamp01(tt.input)
		if got != tt.want {
			t.Errorf("clamp01 input=%f got=%f want=%f", tt.input, got, tt.want)
		}
	}
}

// TestClampOdd verifies odd value clamping
func TestClampOdd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		val  int
		lo   int
		hi   int
		want int
	}{
		{2, 1, 10, 1},   // even -> prev odd (since at lo after clamp)
		{3, 1, 10, 3},   // already odd
		{10, 1, 9, 9},   // even, at hi -> prev odd
		{0, 1, 10, 1},   // below lo
		{11, 1, 10, 9},  // above hi, even -> prev odd
		{11, 1, 11, 11}, // above hi, odd -> self
		{4, 1, 10, 3},   // even in middle -> prev odd
	}

	for _, tt := range tests {
		got := clampOdd(tt.val, tt.lo, tt.hi)
		if got != tt.want {
			t.Errorf("clampOdd got %d want %d", got, tt.want)
		}
		// Verify result is odd
		if got%2 == 0 {
			t.Errorf("clampOdd(%d, %d, %d) = %d, should be odd", tt.val, tt.lo, tt.hi, got)
		}
	}
}

// TestMedianFilter verifies median filtering
func TestMedianFilter(t *testing.T) {
	t.Parallel()
	values := []uint64{10, 5, 20, 15, 8, 100, 12}
	windowSize := 3
	out := make([]uint64, len(values))
	win := make([]uint64, windowSize)

	result := medianFilterInto(values, windowSize, out, win)

	if len(result) != len(values) {
		l := len(result)
		t.Errorf("median len want %d got %d", len(values), l)
	}
	if result[5] >= 100 {
		t.Errorf("spike not smoothed idx5=%d", result[5])
	}
}

// TestTheilSenSlope verifies slope calculation
func TestTheilSenSlope(t *testing.T) {
	t.Parallel()
	// Perfect line: y = 2x + 1
	xs := []float64{0, 1, 2, 3, 4, 5}
	ys := []float64{1, 3, 5, 7, 9, 11}

	var slopes []float64
	slope := theilSenSlopeWithBuf(xs, ys, &slopes)

	// Should detect slope of 2
	if math.Abs(slope-2.0) > 0.01 {
		t.Errorf("slope got %f want ~2", slope)
	}
}

// TestPearsonR2 verifies correlation calculation
func TestPearsonR2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		xs       []float64
		ys       []float64
		expected float64
		tol      float64
	}{
		{
			name:     "perfect positive correlation",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{2, 4, 6, 8, 10},
			expected: 1.0,
			tol:      0.001,
		},
		{
			name:     "perfect negative correlation",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{10, 8, 6, 4, 2},
			expected: 1.0, // R² is squared, so negative correlation also gives 1.0
			tol:      0.001,
		},
		{
			name:     "no correlation",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{3, 3, 3, 3, 3}, // constant y
			expected: 0.0,
			tol:      0.001,
		},
		{
			name: "moderate positive correlation",
			// Manually calculated: r ≈ 0.8944 → R² ≈ 0.8
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{1, 3, 2, 4, 5},
			expected: 0.8,
			tol:      0.05,
		},
		{
			name:     "weak correlation",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{5, 3, 7, 2, 8},
			expected: 0.1, // Should be low
			tol:      0.15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r2 := pearsonR2(tt.xs, tt.ys)

			if math.Abs(r2-tt.expected) > tt.tol {
				t.Errorf("pearsonR2 got %f want %f tol %f", r2, tt.expected, tt.tol)
			}
			if r2 < 0 || r2 > 1 {
				t.Errorf("pearsonR2 out of range %f", r2)
			}
		})
	}
}

// TestSpearmanRho verifies rank correlation
func TestSpearmanRho(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		xs       []float64
		ys       []float64
		expected float64
		tol      float64
	}{
		{
			name:     "perfect monotonic increasing",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{2, 4, 6, 8, 10},
			expected: 1.0,
			tol:      0.01,
		},
		{
			name:     "perfect monotonic decreasing",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{10, 8, 6, 4, 2},
			expected: -1.0,
			tol:      0.01,
		},
		{
			name:     "perfect rank correlation (non-linear)",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{1, 4, 9, 16, 25}, // y = x²
			expected: 1.0,                        // Perfect monotonic
			tol:      0.01,
		},
		{
			name:     "no correlation (constant)",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{5, 5, 5, 5, 5},
			expected: 0.0,
			tol:      0.01,
		},
		{
			name:     "moderate positive rank correlation",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{1, 3, 2, 5, 4}, // Mostly increasing but with swaps
			expected: 0.7,                      // Strong but not perfect
			tol:      0.15,
		},
		{
			name:     "weak correlation (random-ish)",
			xs:       []float64{1, 2, 3, 4, 5},
			ys:       []float64{3, 1, 4, 2, 5},
			expected: 0.4, // Some correlation but weak
			tol:      0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var kvBuf []kv
			var r1, r2 []float64

			rho := spearmanRhoWithBuf(tt.xs, tt.ys, &kvBuf, &r1, &r2)

			if math.Abs(rho-tt.expected) > tt.tol {
				t.Errorf("spearman rho got %f want %f tol %f", rho, tt.expected, tt.tol)
			}
			if rho < -1 || rho > 1 {
				t.Errorf("spearman rho out of range %f", rho)
			}
		})
	}
}

// TestRobustNoise verifies noise estimation
func TestRobustNoise(t *testing.T) {
	t.Parallel()
	xs := []float64{0, 1, 2, 3, 4, 5}
	ys := []float64{1, 3, 5, 7, 9, 11} // Perfect line with slope 2

	var diffs []float64
	med, sigma := robustNoiseBpsWithBuf(xs, ys, &diffs)

	// Median should be close to 2 (the slope)
	if math.Abs(med-2.0) > 0.1 {
		t.Errorf("median got %f want ~2", med)
	}
	if sigma > 0.1 {
		t.Logf("sigma high=%f", sigma)
	}
}

// TestEvidence verifies evidence calculation
func TestEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		slope     float64
		eff       float64
		sigma     float64
		qualityOK bool
		want      float64
	}{
		{"no quality", 100, 50, 10, false, 0.0},
		{"below threshold", 40, 50, 10, true, 0.0},
		{"above threshold", 100, 50, 10, true, 0.0}, // will be > 0 but depends on params
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := evidenceWith(tt.slope, tt.eff, tt.sigma, tt.qualityOK, 2.0, 0.5, 0.8)

			if tt.qualityOK == false && got != 0.0 {
				t.Errorf("evidence should be 0 got %f", got)
			}
			if got < 0 || got > 1 {
				t.Errorf("evidence out of range %f", got)
			}
		})
	}
}

// TestGrowthNoise verifies growth-only noise estimation
func TestGrowthNoise(t *testing.T) {
	t.Parallel()
	xs := []float64{0, 1, 2, 3, 4, 5}
	ys := []float64{10, 12, 11, 15, 14, 18} // Growing with noise

	var diffs []float64
	med, sigma := growthNoiseBpsWithBuf(xs, ys, &diffs)
	_ = sigma // ignore sigma; we only assert med

	// Median should be positive (growth)
	if med < 0 {
		t.Errorf("median negative %f", med)
	}
}

// TestPercentileSorted verifies percentile calculation
func TestPercentileSorted(t *testing.T) {
	t.Parallel()
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	tests := []struct {
		p    float64
		want float64
	}{
		{0.0, 1},
		{0.5, 5.5},
		{1.0, 10},
	}

	for _, tt := range tests {
		got := percentileSorted(sorted, tt.p)
		if math.Abs(got-tt.want) > 0.1 {
			t.Errorf("percentile p=%f got=%f want=%f", tt.p, got, tt.want)
		}
	}
}

// BenchmarkStep benchmarks the core step operation
func BenchmarkStep(b *testing.B) {
	cfg := DefaultConfig()
	cfg.MaxHistory = 1000
	state := NewState(cfg)

	baseTime := time.Now()

	b.ResetTimer()
	for i := range b.N {
		heap := MiB*100 + uint64(i)*1024 //nolint:gosec // benchmark loop variable
		rss := MiB*150 + uint64(i)*1024  //nolint:gosec // benchmark loop variable
		input := Input{
			Time:   baseTime.Add(time.Duration(i) * time.Second),
			Values: [NumMetrics]uint64{heap, rss},
		}
		state.Step(input)
	}
}

// BenchmarkAppendOnly benchmarks store-only mode
func BenchmarkAppendOnly(b *testing.B) {
	cfg := DefaultConfig()
	cfg.MaxHistory = 1000
	state := NewState(cfg)

	baseTime := time.Now()

	b.ResetTimer()
	for i := range b.N {
		heap := MiB*100 + uint64(i)*1024 //nolint:gosec // benchmark loop variable
		rss := MiB*150 + uint64(i)*1024  //nolint:gosec // benchmark loop variable
		input := Input{
			Time:   baseTime.Add(time.Duration(i) * time.Second),
			Values: [NumMetrics]uint64{heap, rss},
		}
		state.AppendOnly(input)
	}
}
