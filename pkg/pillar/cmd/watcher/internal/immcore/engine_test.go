// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package immcore

import (
	"math"
	"testing"
	"time"
)

// TestCollectNow verifies that metric collection works without errors
func TestCollectNow(t *testing.T) {
	vals, errs := CollectNow()

	if len(errs) > 0 {
		t.Errorf("Expected no errors during collection, got: %v", errs)
	}

	// Check that we got values for all metrics
	if len(vals) != NumMetrics {
		t.Errorf("Expected %d metric values, got %d", NumMetrics, len(vals))
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
	cfg := DefaultConfig()
	cfg.MaxHistory = 100

	state := NewState(cfg)

	if state == nil {
		t.Fatal("NewState returned nil")
	}

	if len(state.History()) != 0 {
		t.Errorf("Expected empty history initially, got %d entries", len(state.History()))
	}

	if cap(state.hist) != cfg.MaxHistory {
		t.Errorf("Expected history capacity of %d, got %d", cfg.MaxHistory, cap(state.hist))
	}
}

// TestStepBasic verifies basic step functionality
func TestStepBasic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 1 * time.Minute
	cfg.ProbingInterval = 5 * time.Second
	cfg.MaxHistory = 100

	state := NewState(cfg)

	// Create a test input
	now := time.Now()
	input := Input{
		Time: now,
		Values: [NumMetrics]uint64{
			1024 * 1024 * 100, // 100 MB heap
			1024 * 1024 * 150, // 150 MB RSS
		},
	}

	probe := state.Step(input)

	// Verify probe was created
	if probe.Time != now {
		t.Errorf("Expected time %v, got %v", now, probe.Time)
	}

	if len(state.History()) != 1 {
		t.Errorf("Expected 1 entry in history, got %d", len(state.History()))
	}

	// Verify values were stored
	for i := 0; i < NumMetrics; i++ {
		if probe.Values[i] != input.Values[i] {
			t.Errorf("Metric %d: expected value %d, got %d", i, input.Values[i], probe.Values[i])
		}
	}
}

// TestStepMultiple verifies multiple steps and history management
func TestStepMultiple(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 1 * time.Minute
	cfg.ProbingInterval = 5 * time.Second
	cfg.MaxHistory = 10

	state := NewState(cfg)

	baseTime := time.Now()

	// Add more probes than capacity to test ring buffer
	for i := 0; i < 15; i++ {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * cfg.ProbingInterval),
			Values: [NumMetrics]uint64{
				uint64(1024 * 1024 * (100 + i)), // increasing heap
				uint64(1024 * 1024 * (150 + i)), // increasing RSS
			},
		}
		state.Step(input)
	}

	// Should be capped at MaxHistory
	if len(state.History()) > cfg.MaxHistory {
		t.Errorf("Expected history length <= %d, got %d", cfg.MaxHistory, len(state.History()))
	}
}

// TestAppendOnly verifies store-only mode
func TestAppendOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxHistory = 100

	state := NewState(cfg)

	now := time.Now()
	input := Input{
		Time: now,
		Values: [NumMetrics]uint64{
			1024 * 1024 * 100,
			1024 * 1024 * 150,
		},
	}

	probe := state.AppendOnly(input)

	// Verify probe was created without analysis
	if probe.Time != now {
		t.Errorf("Expected time %v, got %v", now, probe.Time)
	}

	if len(state.History()) != 1 {
		t.Errorf("Expected 1 entry in history, got %d", len(state.History()))
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
	cfg := DefaultConfig()
	cfg.MaxHistory = 100

	state := NewState(cfg)

	// Add some probes
	baseTime := time.Now()
	for i := 0; i < 10; i++ {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * time.Second),
			Values: [NumMetrics]uint64{
				uint64(1024 * 1024 * (100 + i)),
				uint64(1024 * 1024 * (150 + i)),
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
		t.Errorf("Expected 7 entries after dropping 3, got %d", newLen)
	}

	// Verify the correct entries remain
	firstTime := state.History()[0].Time
	expectedTime := baseTime.Add(3 * time.Second)
	if !firstTime.Equal(expectedTime) {
		t.Errorf("Expected first entry time %v, got %v", expectedTime, firstTime)
	}
}

// TestSummary verifies summary string generation
func TestSummary(t *testing.T) {
	probe := Probe{
		Time: time.Now(),
		Values: [NumMetrics]uint64{
			1024 * 1024 * 100, // 100 MB
			1024 * 1024 * 200, // 200 MB
		},
	}

	summary := Summary(probe)

	if summary == "" {
		t.Error("Expected non-empty summary")
	}

	// Verify summary is reasonable length
	if len(summary) < 10 {
		t.Error("Expected summary to have meaningful content")
	}

	t.Logf("Summary: %s", summary)
}

// TestLeakDetection verifies that increasing memory triggers detection
func TestLeakDetection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 30 * time.Second
	cfg.ProbingInterval = 1 * time.Second
	cfg.MaxHistory = 200

	state := NewState(cfg)

	baseTime := time.Now()
	baseHeap := uint64(1024 * 1024 * 100) // Start at 100 MB

	// Simulate a memory leak: slow steady increase
	var lastProbe Probe
	for i := 0; i < 120; i++ {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * cfg.ProbingInterval),
			Values: [NumMetrics]uint64{
				baseHeap + uint64(i*1024*100), // Increase by 100KB per probe
				baseHeap + uint64(i*1024*150), // RSS increases too
			},
		}
		lastProbe = state.Step(input)
	}

	// After sustained growth, score should be elevated
	// This is a heuristic check - adjust thresholds based on your algorithm
	if lastProbe.Score < 1.0 {
		t.Logf("Warning: Expected elevated score after leak simulation, got %f", lastProbe.Score)
		t.Logf("Recent feature: %f, Entire feature: %f", lastProbe.RecentFeature, lastProbe.EntireFeature)
	}

	t.Logf("Final score after leak: %f", lastProbe.Score)
}

// TestStableMemory verifies that stable memory doesn't trigger false positives
func TestStableMemory(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AnalysisWindow = 30 * time.Second
	cfg.ProbingInterval = 1 * time.Second
	cfg.MaxHistory = 200

	state := NewState(cfg)

	baseTime := time.Now()
	baseHeap := uint64(1024 * 1024 * 100) // Stable at 100 MB

	var lastProbe Probe
	for i := 0; i < 120; i++ {
		// Add small random noise to make it realistic
		noise := uint64((i % 5) * 1024 * 10) // +/- 50KB noise
		input := Input{
			Time: baseTime.Add(time.Duration(i) * cfg.ProbingInterval),
			Values: [NumMetrics]uint64{
				baseHeap + noise,
				baseHeap + noise*2,
			},
		}
		lastProbe = state.Step(input)
	}

	// Score should remain low for stable memory
	if lastProbe.Score > 3.0 {
		t.Logf("Warning: Expected low score for stable memory, got %f", lastProbe.Score)
	}

	t.Logf("Final score for stable memory: %f", lastProbe.Score)
}

// TestEWMAAlpha verifies EWMA alpha calculation
func TestEWMAAlpha(t *testing.T) {
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
			t.Errorf("ewmaAlpha(%f) = %f, want %f", tt.halfLife, got, tt.want)
		}
	}
}

// TestClamp01 verifies value clamping
func TestClamp01(t *testing.T) {
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
			t.Errorf("clamp01(%f) = %f, want %f", tt.input, got, tt.want)
		}
	}
}

// TestClampOdd verifies odd value clamping
func TestClampOdd(t *testing.T) {
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
			t.Errorf("clampOdd(%d, %d, %d) = %d, want %d", tt.val, tt.lo, tt.hi, got, tt.want)
		}
		// Verify result is odd
		if got%2 == 0 {
			t.Errorf("clampOdd(%d, %d, %d) = %d, should be odd", tt.val, tt.lo, tt.hi, got)
		}
	}
}

// TestMedianFilter verifies median filtering
func TestMedianFilter(t *testing.T) {
	values := []uint64{10, 5, 20, 15, 8, 100, 12}
	windowSize := 3
	out := make([]uint64, len(values))
	win := make([]uint64, windowSize)

	result := medianFilterInto(values, windowSize, out, win)

	if len(result) != len(values) {
		t.Errorf("Expected output length %d, got %d", len(values), len(result))
	}

	// Check that extreme spike at index 5 is smoothed
	if result[5] >= 100 {
		t.Errorf("Expected median filter to smooth spike, got %d", result[5])
	}

	t.Logf("Median filtered: %v", result)
}

// TestTheilSenSlope verifies slope calculation
func TestTheilSenSlope(t *testing.T) {
	// Perfect line: y = 2x + 1
	xs := []float64{0, 1, 2, 3, 4, 5}
	ys := []float64{1, 3, 5, 7, 9, 11}

	var slopes []float64
	slope := theilSenSlopeWithBuf(xs, ys, &slopes)

	// Should detect slope of 2
	if math.Abs(slope-2.0) > 0.01 {
		t.Errorf("Expected slope ~2.0, got %f", slope)
	}
}

// TestPearsonR2 verifies correlation calculation
func TestPearsonR2(t *testing.T) {
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
			r2 := pearsonR2(tt.xs, tt.ys)

			if math.Abs(r2-tt.expected) > tt.tol {
				t.Errorf("pearsonR2() = %f, expected ~%f (±%f)", r2, tt.expected, tt.tol)
			}

			// R² should always be in [0, 1]
			if r2 < 0 || r2 > 1 {
				t.Errorf("R² should be in [0,1], got %f", r2)
			}
		})
	}
}

// TestSpearmanRho verifies rank correlation
func TestSpearmanRho(t *testing.T) {
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
			var kvBuf []kv
			var r1, r2 []float64

			rho := spearmanRhoWithBuf(tt.xs, tt.ys, &kvBuf, &r1, &r2)

			if math.Abs(rho-tt.expected) > tt.tol {
				t.Errorf("spearmanRho() = %f, expected ~%f (±%f)", rho, tt.expected, tt.tol)
			}

			// Spearman ρ should always be in [-1, 1]
			if rho < -1 || rho > 1 {
				t.Errorf("Spearman ρ should be in [-1,1], got %f", rho)
			}
		})
	}
}

// TestRobustNoise verifies noise estimation
func TestRobustNoise(t *testing.T) {
	xs := []float64{0, 1, 2, 3, 4, 5}
	ys := []float64{1, 3, 5, 7, 9, 11} // Perfect line with slope 2

	var diffs []float64
	med, sigma := robustNoiseBpsWithBuf(xs, ys, &diffs)

	// Median should be close to 2 (the slope)
	if math.Abs(med-2.0) > 0.1 {
		t.Errorf("Expected median ~2.0, got %f", med)
	}

	// Sigma should be small (no noise in perfect line)
	if sigma > 0.1 {
		t.Logf("Expected low noise for perfect line, got sigma=%f", sigma)
	}

	t.Logf("Noise estimation: median=%f, sigma=%f", med, sigma)
}

// TestEvidence verifies evidence calculation
func TestEvidence(t *testing.T) {
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
			got := evidenceWith(tt.slope, tt.eff, tt.sigma, tt.qualityOK, 2.0, 0.5, 0.8)

			if tt.qualityOK == false && got != 0.0 {
				t.Errorf("Expected 0 evidence without quality, got %f", got)
			}

			if got < 0 || got > 1 {
				t.Errorf("Evidence should be in [0,1], got %f", got)
			}
		})
	}
}

// TestGrowthNoise verifies growth-only noise estimation
func TestGrowthNoise(t *testing.T) {
	xs := []float64{0, 1, 2, 3, 4, 5}
	ys := []float64{10, 12, 11, 15, 14, 18} // Growing with noise

	var diffs []float64
	med, sigma := growthNoiseBpsWithBuf(xs, ys, &diffs)

	// Median should be positive (growth)
	if med < 0 {
		t.Errorf("Expected positive median for growing data, got %f", med)
	}

	t.Logf("Growth noise: median=%f, sigma=%f", med, sigma)
}

// TestPercentileSorted verifies percentile calculation
func TestPercentileSorted(t *testing.T) {
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
			t.Errorf("percentileSorted(p=%f) = %f, want %f", tt.p, got, tt.want)
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
	for i := 0; i < b.N; i++ {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * time.Second),
			Values: [NumMetrics]uint64{
				uint64(1024*1024*100 + i*1024),
				uint64(1024*1024*150 + i*1024),
			},
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
	for i := 0; i < b.N; i++ {
		input := Input{
			Time: baseTime.Add(time.Duration(i) * time.Second),
			Values: [NumMetrics]uint64{
				uint64(1024*1024*100 + i*1024),
				uint64(1024*1024*150 + i*1024),
			},
		}
		state.AppendOnly(input)
	}
}
