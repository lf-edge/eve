// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package immcore

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// bytesPerLineInFile is computed at build time from a representative CSV line.
	// It should reflect the longest plausible row we write (time + 2 uint64 metrics + score + 6 features) including the newline.
	// This is used to calculate how many probes we can store in a fixed-size CSV file.
	// Example line contains: timestamp, heap value, RSS value, score, and evidence features.
	// Adjust if the CSV schema changes.
	lineExample        = "2025-10-16T15:24:09Z,41402368,144699392,0.203,0.1575,0.0000,0.0033,0.1927,0.0000,0.0000\n"
	bytesPerLineInFile = len(lineExample)
)

var (
	// MaxStatsFileSize limits the CSV output file size to prevent unbounded disk usage.
	// Default is 1MB which allows for approximately 10,000+ probes depending on line length.
	MaxStatsFileSize = 1024 * 1024 // 1MB

	// MaxHistory is the maximum number of probes we keep in memory.
	// Calculated based on how many lines fit in MaxStatsFileSize.
	// This acts as a ring buffer - oldest probes are dropped when limit is reached.
	MaxHistory = MaxStatsFileSize / bytesPerLineInFile
)

// MetricCollector is a function type that collects a single memory metric.
// Returns the metric value in bytes and any error encountered during collection.
// Each metric (heap, RSS, etc.) has its own collector function.
type MetricCollector func() (uint64, error)

// MetricSpec describes a single memory metric that the IMM engine monitors.
// Each metric has a name (for CSV headers), a default weight (for scoring),
// and a collector function (to gather current values).
type MetricSpec struct {
	Name          string          // Human-readable name (e.g., "heap", "rss")
	DefaultWeight float64         // How much this metric contributes to final score (0.0-1.0+)
	Collector     MetricCollector // Function to collect current metric value
}

// MetricRegistry lists all known metrics and their configuration.
// This is an array (not a slice) so NumMetrics is a compile-time constant.
// The order here determines the order in CSV output and internal arrays.
// Keep this aligned with any external collectors.
//
// Current metrics:
// - heap: Go runtime heap memory (HeapInuse from runtime.MemStats)
// - rss: Resident Set Size from OS (read from /proc/self/statm)
//
// Weights determine relative importance in final score calculation:
// - heap weight 1.0: Primary indicator (Go allocations)
// - rss weight 0.8: Secondary indicator (total process memory)
var MetricRegistry = [...]MetricSpec{
	{Name: "heap", DefaultWeight: 1.0, Collector: collectHeapInUseSeenByGo},
	{Name: "rss", DefaultWeight: 0.8, Collector: collectRssSeenByOs},
}

// NumMetrics is a compile-time constant equal to the number of registered metrics.
// Using an array for MetricRegistry makes this constant at compile time,
// which enables fixed-size arrays in Input and Probe structs (no allocations).
const NumMetrics = len(MetricRegistry)

// CollectNow gathers current metric values in registry order.
// Errors are returned for callers to report/log as needed.
func CollectNow() (vals [NumMetrics]uint64, errs []error) {
	if Profiling() {
		defer Profile("imm.collect")()
	}
	for i, spec := range MetricRegistry {
		v, err := spec.Collector()
		if err != nil {
			errs = append(errs, fmt.Errorf("collect %q: %w", spec.Name, err))
			// leave zero value if error
		} else {
			vals[i] = v
		}
	}
	return
}

// Summary builds a short per-metric summary string from a probe.
// Currently treats values as bytes and prints MiB.
func Summary(p Probe) string {
	parts := make([]string, 0, NumMetrics)
	for i, spec := range MetricRegistry {
		mb := float64(p.Values[i]) / 1024.0 / 1024.0
		parts = append(parts, fmt.Sprintf("%s: %.2f MB", spec.Name, mb))
	}
	return strings.Join(parts, ", ")
}

// ---------------- collectors (engine-internal) ----------------

func collectHeapInUseSeenByGo() (uint64, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse, nil
}

func collectRssSeenByOs() (uint64, error) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	var size, rss uint64
	if _, err := fmt.Sscanf(string(data), "%d %d", &size, &rss); err != nil {
		return 0, err
	}
	pageSize := os.Getpagesize()
	if pageSize <= 0 {
		pageSize = 4096 // fallback to typical page size
	}
	// pageSize is now guaranteed > 0 and within normal OS page size range, conversion is safe.
	// #nosec G115 -- we validated pageSize non-negative before casting to uint64 to compute RSS bytes.
	return rss * uint64(pageSize), nil
}

// ---------------- Config ----------------

// Config holds all tunable parameters for the Internal Memory Monitor engine.
// The IMM uses a dual-evidence system:
// - "Recent" analysis: looks at a sliding time window (e.g., last 10 minutes)
// - "Entire" analysis: looks at all available history periodically
//
// Both analyses compute trend slopes, correlation quality, and noise levels
// to determine if memory is growing (potential leak) or stable.
type Config struct {
	// ===== Time Windows and Cadence =====

	// AnalysisWindow defines how far back "recent" analysis looks (default: 10 minutes).
	// Only data within this window from the current time is used for recent trend analysis.
	// Shorter windows detect leaks faster but may have more false positives.
	AnalysisWindow time.Duration

	// ProbingInterval is how often we collect memory metrics (default: 5 seconds).
	// Determines the granularity of our time series data.
	// Shorter intervals = more data points = better trend detection but more CPU/storage.
	ProbingInterval time.Duration

	// SlopeThresholdBps is the minimum memory growth rate (bytes/second) we consider significant.
	// If the detected slope is below this, we assume memory is stable.
	// Default: 208 bytes/second (~12KB/minute, ~700KB/hour, ~16MB/day)
	SlopeThresholdBps float64

	// SmoothingProbeCount is how many probes to use for median filtering (default: 60).
	// Median filtering removes noise spikes. Derived from 300s / 5s = 60 probes.
	// Higher values = smoother data but slower to react to real changes.
	SmoothingProbeCount int

	// EntireUpdateEveryWin controls how often we run "entire" analysis (default: 2).
	// Run entire analysis once per N analysis windows.
	// E.g., if AnalysisWindow=10min and EntireUpdateEveryWin=2, run entire every 20min.
	// Higher values save CPU but may miss long-term trends.
	EntireUpdateEveryWin int

	// EntireMedianCap limits median smoothing window for entire analysis (default: 241).
	// Entire uses ~5x recent smoothing but capped at this value.
	// Prevents excessive smoothing that could hide gradual leaks.
	EntireMedianCap int

	// EntireHoldTTLWindows defines how long to trust "entire" results (default: 12.0).
	// After this many analysis windows without updating entire, start decaying the score.
	// E.g., 12 windows × 10min = 2 hours before decay starts.
	EntireHoldTTLWindows float64

	// EntireStaleHalfLife controls decay rate when entire becomes stale (default: 32.0).
	// Using EWMA, after this many windows, stale entire evidence drops to 50%.
	// Larger values = slower decay = longer memory of old trends.
	EntireStaleHalfLife float64

	// RecentHalfLifeWindows controls EWMA smoothing for recent evidence (default: 12.0).
	// After this many windows, new evidence contributes ~50% to the aggregated score.
	// Smaller values = faster reaction to new trends.
	RecentHalfLifeWindows float64

	// EntireHalfLifeWindows controls EWMA smoothing for entire evidence (default: 8.0).
	// After this many windows, new evidence contributes ~50% to the aggregated score.
	// Smaller than recent because entire updates less frequently.
	EntireHalfLifeWindows float64

	// ===== Evidence Gates and Sensitivity =====

	// MinR2Gate is minimum R² (Pearson correlation coefficient squared) to trust a trend (default: 0.40).
	// R² = 1.0 means perfect linear fit, R² = 0.0 means no linear relationship.
	// Only trends with R² >= MinR2Gate OR Spearman >= MinSpearmanGate are considered valid.
	// Lower values = more sensitive but more false positives.
	MinR2Gate float64

	// MinSpearmanGate is minimum Spearman rank correlation to trust a trend (default: 0.50).
	// Spearman ρ = 1.0 means perfect monotonic relationship (not necessarily linear).
	// Used as alternative to R² - catches non-linear but monotonic growth.
	// Either R² OR Spearman must pass for trend to be considered "quality".
	MinSpearmanGate float64

	// ZDeadbandRecent is z-score threshold for recent evidence (default: 1.25).
	// Trend must exceed SlopeThreshold by this many standard deviations to trigger.
	// Z = (slope - threshold) / (sigma × SigmaFactor)
	// Higher values = less sensitive = fewer false positives.
	ZDeadbandRecent float64

	// ZDeadbandEntire is z-score threshold for entire evidence (default: 0.01).
	// Much lower than recent because entire looks at longer-term stable trends.
	// Even small sustained growth over entire history is significant.
	ZDeadbandEntire float64

	// SigmaFactorRecent multiplies noise estimate for recent threshold (default: 12.0).
	// Effective threshold = max(SlopeThreshold, SigmaFactor × noise).
	// Adapts to noise level: noisy data needs stronger signal to be considered a leak.
	// Higher values = more robust to noise but less sensitive to real leaks.
	SigmaFactorRecent float64

	// SigmaFactorEntire multiplies noise estimate for entire threshold (default: 2.0).
	// Lower than recent because entire uses more smoothing and looks at growth-only noise.
	SigmaFactorEntire float64

	// EvidenceBeta controls how quickly evidence rises with z-score (default: 0.8).
	// Evidence = 1 - exp(-beta × (z - zDeadband))
	// Higher beta = faster saturation = more aggressive detection.
	// Lower beta = gentler slope = more gradual evidence accumulation.
	EvidenceBeta float64

	// MaxRiseRecent limits how fast recent evidence can increase per window (default: 0.05).
	// Prevents sudden spikes from causing immediate high scores.
	// E.g., evidence can only rise by 0.05 (5%) per analysis window max.
	MaxRiseRecent float64

	// MaxRiseEntire limits how fast entire evidence can increase per window (default: 0.15).
	// Higher than recent because entire updates less frequently.
	MaxRiseEntire float64

	// ===== Final Score Combiner =====

	// RecentMixWeight determines how much recent evidence contributes to final score (default: 0.05 = 5%).
	// Final = RecentMixWeight × recent + EntireMixWeight × entire
	// Low weight because recent can be noisy; entire provides stability.
	RecentMixWeight float64

	// EntireMixWeight determines how much entire evidence contributes to final score (default: 0.95 = 95%).
	// High weight because entire represents long-term stable trends.
	// RecentMixWeight + EntireMixWeight should typically sum to 1.0.
	EntireMixWeight float64

	// KScore controls final score transformation (default: 2.6).
	// Score = (1 - exp(-K × finalEvidence)) × 10
	// Higher K = faster saturation = scores reach 10 sooner.
	// Lower K = gentler curve = more granular scores.
	KScore float64

	// ===== Per-Metric Weights =====

	// Weights determines relative importance of each metric in scoring (length = NumMetrics).
	// Index corresponds to MetricRegistry order: [0]=heap weight, [1]=rss weight.
	// Final evidence is weighted sum: Σ(weight[i] × evidence[i])
	// Allows prioritizing certain metrics (e.g., heap > rss).
	Weights []float64

	// MaxHistory is maximum number of probes to keep in memory (0 = use global default).
	// Acts as a ring buffer - oldest probes dropped when limit reached.
	// Limits memory usage and CSV file size.
	MaxHistory int
}

// DefaultConfig returns the default configuration for the Internal Memory Monitor.
// It initializes metric weights from the registry and sets reasonable defaults
// for analysis window, probing interval, and various threshold parameters.
func DefaultConfig() Config {
	// Seed weights from the registry by default
	weights := make([]float64, NumMetrics)
	for i, spec := range MetricRegistry {
		weights[i] = spec.DefaultWeight
	}
	return Config{
		AnalysisWindow:        10 * time.Minute,
		ProbingInterval:       5 * time.Second,
		SlopeThresholdBps:     208,
		SmoothingProbeCount:   300 / 5, // derived from 300s / 5s
		EntireUpdateEveryWin:  2,
		EntireMedianCap:       241,
		EntireHoldTTLWindows:  12.0,
		EntireStaleHalfLife:   32.0,
		RecentHalfLifeWindows: 12.0,
		EntireHalfLifeWindows: 8.0,

		MinR2Gate:         0.40,
		MinSpearmanGate:   0.50,
		ZDeadbandRecent:   1.25,
		ZDeadbandEntire:   0.01,
		SigmaFactorRecent: 12.0,
		SigmaFactorEntire: 2.0,
		EvidenceBeta:      0.8,
		MaxRiseRecent:     0.05,
		MaxRiseEntire:     0.15,

		RecentMixWeight: 0.05,
		EntireMixWeight: 0.95,
		KScore:          2.6,

		Weights: weights,
	}
}

// ---------------- I/O & Probe ----------------

// Input represents a single memory measurement at a specific time.
// This is the raw data fed into the IMM engine.
type Input struct {
	Time   time.Time          // When the measurement was taken
	Values [NumMetrics]uint64 // Raw metric values (bytes): [heap, rss, ...]
}

// Probe represents a fully analyzed memory measurement.
// Contains raw values plus all computed analysis results.
type Probe struct {
	Time   time.Time          // When the measurement was taken
	Values [NumMetrics]uint64 // Raw metric values (bytes): [heap, rss, ...]

	// Per-metric evidence scores (0.0 to 1.0):
	SRecent [NumMetrics]float64 // Recent window evidence for each metric
	SEntire [NumMetrics]float64 // Entire history evidence for each metric

	// Combined features (weighted sums across all metrics):
	RecentFeature float64 // Weighted sum of recent evidence
	EntireFeature float64 // Weighted sum of entire evidence

	// Final leak score (0 to 10):
	Score float64 // Combined score: higher = more likely a leak
}

// ---------------- State ----------------

// IMMState holds all the runtime state for the Internal Memory Monitor engine.
// This includes configuration, history of probes, aggregated evidence scores,
// and reusable buffers for statistical calculations.
type IMMState struct {
	// Configuration (immutable after creation)
	cfg Config // User-provided or default config

	// Computed configuration (derived from cfg)
	alphaRecent  float64 // EWMA alpha for recent evidence smoothing
	alphaEntire  float64 // EWMA alpha for entire evidence smoothing
	winProbes    int     // Number of probes in one analysis window
	entireEvery  int     // How many probes between entire updates
	medianRecent int     // Median filter window size for recent

	// Aggregated evidence (EWMA smoothed, per-metric)
	aggRecent [NumMetrics]float64 // Current recent evidence for each metric
	aggEntire [NumMetrics]float64 // Current entire evidence for each metric

	// Probe history (ring buffer)
	hist []Probe // Circular buffer of historical probes

	// Entire analysis tracking
	lastEntireIdx  int       // Index in hist where we last ran entire analysis
	lastEntireTime time.Time // Timestamp of last entire analysis

	// Reusable buffers (avoid allocations in hot path)
	buf scratch // Pre-allocated working memory for calculations
}

// kv is a key-value pair used for ranking in Spearman correlation.
// Stores a value and its original index for stable sorting.
type kv struct {
	v float64 // The value to rank
	i int     // Original index in the array
}

// scratch holds reusable buffers for statistical calculations.
// All these slices are reused across Step() calls to avoid allocations.
// They grow to the needed size and stay there (no shrinking).
type scratch struct {
	times     []float64 // Relative timestamps (seconds from first probe)
	valsU     []uint64  // Metric values as uint64 (working buffer)
	valsF     []float64 // Metric values as float64 (for calculations)
	medianWin []uint64  // Window buffer for median filter
	medianOut []uint64  // Output buffer for median filter
	diffs     []float64 // Inter-probe differences (for noise estimation)
	slopes    []float64 // All pairwise slopes (for Theil-Sen estimator)
	rankKV    []kv      // Key-value pairs for ranking (Spearman)
	rank1     []float64 // Rank buffer 1 (for X values in Spearman)
	rank2     []float64 // Rank buffer 2 (for Y values in Spearman)
}

// NewState creates a new IMM engine state with the given configuration.
// Initializes all internal parameters and allocates the history buffer.
//
// The function computes several derived values from the config:
// - EWMA alpha values for smoothing (based on half-lives)
// - Number of probes per analysis window (window duration / probe interval)
// - Frequency of entire updates (in number of probes)
//
// Returns a ready-to-use IMMState that can process Input probes via Step().
func NewState(cfg Config) *IMMState {
	// Sanitize weights: ensure we have exactly NumMetrics weights
	nMetrics := NumMetrics
	if len(cfg.Weights) != nMetrics {
		// If weights are wrong length, use safe defaults (0.5 for all)
		w := make([]float64, nMetrics)
		for i := range w {
			w[i] = 0.5
		}
		cfg.Weights = w
	}

	st := &IMMState{
		cfg: cfg,

		// Compute EWMA alpha from half-life using: alpha = 1 - exp(-ln(2)/halfLife)
		// This gives the decay constant for exponential weighted moving average.
		// After 'halfLife' windows, old values contribute ~50% to the average.
		alphaRecent: ewmaAlpha(cfg.RecentHalfLifeWindows),
		alphaEntire: ewmaAlpha(cfg.EntireHalfLifeWindows),

		// Calculate how many probes fit in one analysis window
		// E.g., 10 minute window / 5 second interval = 120 probes
		winProbes: max(1, int(cfg.AnalysisWindow/cfg.ProbingInterval)),

		// Calculate how many probes between entire updates
		// E.g., update every 2 windows × 120 probes/window = every 240 probes
		entireEvery: max(1, cfg.EntireUpdateEveryWin*max(1, int(cfg.AnalysisWindow/cfg.ProbingInterval))),

		// Median filter window for recent analysis (from config)
		medianRecent: max(1, cfg.SmoothingProbeCount),

		// Initialize lastEntireIdx to negative value so first update happens soon
		// Set to -entireEvery so the first Step() triggers entire analysis
		lastEntireIdx: -max(1,
			cfg.EntireUpdateEveryWin*max(1, int(cfg.AnalysisWindow/cfg.ProbingInterval))),
	}

	// Allocate history buffer with appropriate capacity
	if cfg.MaxHistory > 0 {
		// Use user-specified max history
		st.hist = make([]Probe, 0, cfg.MaxHistory)
	} else {
		// Use global default max history
		st.hist = make([]Probe, 0, MaxHistory)
	}

	return st
}

// History returns the complete history of memory probes collected by the monitor.
func (s *IMMState) History() []Probe { return s.hist }

// DropHead removes the first k probes from the history buffer.
// This implements ring buffer semantics by dropping oldest data when we reach capacity.
//
// The function:
// 1. Shifts remaining probes to the front of the slice (no reallocation)
// 2. Zeros out the now-unused tail slots to help GC release memory
// 3. Adjusts lastEntireIdx to account for removed probes
//
// This is called when the history buffer reaches its capacity limit.
// Parameters:
//
//	k: number of probes to drop from the beginning (must be > 0 and < len(hist))
func (s *IMMState) DropHead(k int) {
	if k <= 0 || k >= len(s.hist) {
		return // Nothing to do for invalid k
	}

	// Shift elements left by k positions
	// This moves probes[k:] to probes[0:] without allocating new memory
	n := len(s.hist)
	copy(s.hist[0:], s.hist[k:n])

	// Zero out the trailing slots to help garbage collector
	// This allows GC to reclaim any referenced objects in dropped probes
	var zero Probe
	for i := n - k; i < n; i++ {
		s.hist[i] = zero
	}

	// Truncate slice to new length (but keep same underlying capacity)
	s.hist = s.hist[:n-k]

	// Adjust the entire analysis index to account for dropped probes
	// If we haven't run entire yet (negative index), keep it negative
	// but ensure it doesn't go too far negative (bound at -entireEvery)
	if s.lastEntireIdx >= 0 {
		s.lastEntireIdx -= k
		if s.lastEntireIdx < -s.entireEvery {
			s.lastEntireIdx = -s.entireEvery
		}
	}
}

// ---------------- Step ----------------

// Step processes a new memory measurement and returns a fully analyzed Probe.
// This is the core function of the IMM engine, implementing the dual-evidence algorithm.
//
// The algorithm works in phases:
// 1. Add new probe to history (with ring buffer management)
// 2. Recent analysis: analyze trends in the recent time window
// 3. Entire analysis: periodically analyze all available history
// 4. Score computation: combine evidence into final leak score (0-10)
//
// The dual-evidence approach:
// - Recent: detects short-term trends, reacts quickly, but can be noisy
// - Entire: captures long-term stable trends, slower but more reliable
// - Final score: weighted combination (typically 5% recent + 95% entire)
//
// Mathematical basis:
// - Theil-Sen estimator: robust slope calculation (resistant to outliers)
// - Pearson R²: measures linear correlation quality
// - Spearman ρ: measures monotonic correlation quality
// - Median filtering: removes noise spikes
// - EWMA: exponentially weighted moving average for smoothing
// - Z-score: statistical significance testing
//
// Parameters:
//
//	in: Input containing timestamp and raw metric values
//
// Returns:
//
//	Probe with all analysis results (evidence scores, final score)
func (s *IMMState) Step(in Input) Probe {
	if Profiling() {
		defer Profile("imm.step")()
	}

	// ===== Phase 1: Add Probe to History =====

	// Enforce ring buffer semantics: never exceed preallocated capacity
	if cap(s.hist) > 0 && len(s.hist) == cap(s.hist) {
		// Drop oldest probe to make room for new one
		// This prevents unbounded memory growth
		s.DropHead(1)
	}

	// Create new probe with input data
	// Using fixed-size arrays (not slices) to avoid allocations
	var p Probe
	p.Time = in.Time
	for i := range NumMetrics {
		p.Values[i] = in.Values[i]
	}

	// Append to history and get its index
	s.hist = append(s.hist, p)
	i := len(s.hist) - 1

	// ===== Phase 2: Recent Analysis =====

	// Find the start of the recent window (based on time, not count)
	// Walk backwards until we exceed the analysis window duration
	// This gives us a time-based sliding window
	left := i
	for left > 0 && s.hist[i].Time.Sub(s.hist[left-1].Time) <= s.cfg.AnalysisWindow {
		left--
	}
	// sub = slice of probes in recent window [left..i]
	sub := s.hist[left : i+1]

	// Convert absolute timestamps to relative times (seconds from first probe)
	// This makes calculations simpler and more numerically stable
	s.buf.times = ensureF64(s.buf.times, len(sub))
	relTimesInto(sub, s.buf.times)

	// Analyze each metric independently
	for m := range NumMetrics {
		endMetric := func() {}
		if Profiling() {
			endMetric = Profile("imm.recent.metric")
		}

		// Extract this metric's values into scratch buffer
		s.buf.valsU = ensureU64(s.buf.valsU, len(sub))
		takeMetricInto(sub, m, s.buf.valsU)

		// Apply median filter to remove noise spikes
		// Median filter replaces each value with median of surrounding window
		// This is robust: a single spike doesn't affect the median
		if s.medianRecent > 1 {
			win := clampOdd(s.medianRecent, 1, len(s.buf.valsU))
			s.buf.medianWin = ensureU64(s.buf.medianWin, win)
			s.buf.medianOut = ensureU64(s.buf.medianOut, len(s.buf.valsU))
			s.buf.valsU = medianFilterInto(s.buf.valsU, win, s.buf.medianOut, s.buf.medianWin)
		}

		// Convert to float64 for statistical calculations
		s.buf.valsF = ensureF64(s.buf.valsF, len(s.buf.valsU))
		toF64Into(s.buf.valsU, s.buf.valsF)

		// Compute trend statistics:

		// Theil-Sen slope: robust linear regression
		// Calculates median of all pairwise slopes
		// Not affected by outliers unlike least squares
		slope := theilSenSlopeWithBuf(s.buf.times, s.buf.valsF, &s.buf.slopes)

		// Pearson R²: linear correlation quality (0 to 1)
		// R² = 1: perfect linear relationship
		// R² = 0: no linear relationship
		r2 := pearsonR2(s.buf.times, s.buf.valsF)

		// Spearman ρ: rank correlation quality (-1 to 1)
		// ρ = 1: perfect monotonic increase
		// ρ = 0: no monotonic relationship
		// Catches non-linear but consistent growth
		rho := spearmanRhoWithBuf(s.buf.times, s.buf.valsF, &s.buf.rankKV, &s.buf.rank1, &s.buf.rank2)

		// Robust noise estimate (standard deviation of growth rates)
		// Uses percentile-based estimation (16th to 84th percentile)
		// More robust than standard deviation to outliers
		_, sigma := robustNoiseBpsWithBuf(s.buf.times, s.buf.valsF, &s.buf.diffs)

		// Compute effective threshold (adaptive to noise level)
		// Use the larger of: fixed threshold OR noise-based threshold
		// This makes detection adaptive: noisy data needs stronger signal
		eff := math.Max(s.cfg.SlopeThresholdBps, s.cfg.SigmaFactorRecent*sigma)

		// Quality check: is the trend reliable?
		// Pass if EITHER R² OR Spearman meets threshold
		// This catches both linear and monotonic growth patterns
		quality := (r2 >= s.cfg.MinR2Gate || rho >= s.cfg.MinSpearmanGate)

		// Calculate evidence score (0 to 1)
		// This combines slope, threshold, noise, and quality into single score
		// Evidence = 0: no leak detected
		// Evidence = 1: strong leak signal
		e := evidenceWith(slope, eff, sigma, quality, s.cfg.SigmaFactorRecent, s.cfg.ZDeadbandRecent, s.cfg.EvidenceBeta)

		// Update aggregated evidence using EWMA smoothing
		// EWMA = (1-α) × old_value + α × new_value
		// This smooths out temporary fluctuations
		prev := s.aggRecent[m]
		next := ewmaUpdate(prev, e, s.alphaRecent)

		// Limit maximum rise per update to prevent sudden jumps
		// This prevents a single noisy spike from causing immediate high score
		if next-prev > s.cfg.MaxRiseRecent {
			next = prev + s.cfg.MaxRiseRecent
		}

		// Clamp to [0, 1] range and store
		s.aggRecent[m] = clamp01(next)
		s.hist[i].SRecent[m] = s.aggRecent[m]

		endMetric()
	}

	// ===== Phase 3: Entire Analysis (Periodic) =====

	// Check if it's time to run entire analysis
	// Run every N probes (configured via EntireUpdateEveryWin)
	// This is more expensive so we don't run it every Step()
	if i >= s.lastEntireIdx+s.entireEvery {
		endPass := func() {}
		if Profiling() {
			endPass = Profile("imm.entire.pass")
		}

		// Update tracking: remember when we ran entire analysis
		s.lastEntireIdx = i
		s.lastEntireTime = s.hist[i].Time

		// Analyze ALL available history (not just recent window)
		// This captures long-term stable trends that recent might miss
		all := s.hist[:i+1]
		s.buf.times = ensureF64(s.buf.times, len(all))
		relTimesInto(all, s.buf.times)

		// Analyze each metric over entire history
		for m := range NumMetrics {
			endEM := func() {}
			if Profiling() {
				endEM = Profile("imm.entire.metric")
			}

			// Extract metric values
			s.buf.valsU = ensureU64(s.buf.valsU, len(all))
			takeMetricInto(all, m, s.buf.valsU)

			// Apply stronger median filtering for entire
			// Use ~5x recent smoothing (but capped) to handle more noise in long history
			// More data = more potential for outliers, so more smoothing needed
			win := clampOdd(min(s.medianRecent*5, s.cfg.EntireMedianCap), 1, len(s.buf.valsU))
			if win > 1 {
				s.buf.medianWin = ensureU64(s.buf.medianWin, win)
				s.buf.medianOut = ensureU64(s.buf.medianOut, len(s.buf.valsU))
				_ = medianFilterInto(s.buf.valsU, win, s.buf.medianOut, s.buf.medianWin)
				// Copy filtered values back
				copy(s.buf.valsU, s.buf.medianOut)
			}

			// Convert to float for calculations
			s.buf.valsF = ensureF64(s.buf.valsF, len(s.buf.valsU))
			toF64Into(s.buf.valsU, s.buf.valsF)

			// Compute same statistics as recent, but over entire history
			slope := theilSenSlopeWithBuf(s.buf.times, s.buf.valsF, &s.buf.slopes)
			r2 := pearsonR2(s.buf.times, s.buf.valsF)
			rho := spearmanRhoWithBuf(s.buf.times, s.buf.valsF, &s.buf.rankKV, &s.buf.rank1, &s.buf.rank2)

			// Use growth-only noise for entire (not robust noise)
			// Growth-only ignores negative changes (memory decreases)
			// For long-term trend, we only care about sustained growth
			_, sigma := growthNoiseBpsWithBuf(s.buf.times, s.buf.valsF, &s.buf.diffs)

			// Use fixed threshold (not noise-adaptive) for entire
			// Long-term trends should be clear enough to not need adaptation
			eff := s.cfg.SlopeThresholdBps
			quality := (r2 >= s.cfg.MinR2Gate || rho >= s.cfg.MinSpearmanGate)

			// Calculate evidence using entire-specific parameters
			// Entire uses different sigma factor and z-deadband than recent
			e := evidenceWith(slope, eff, sigma, quality, s.cfg.SigmaFactorEntire, s.cfg.ZDeadbandEntire, s.cfg.EvidenceBeta)

			// Update aggregated entire evidence with EWMA
			prev := s.aggEntire[m]
			next := ewmaUpdate(prev, e, s.alphaEntire)

			// Limit rise (larger limit than recent since updates are infrequent)
			if next-prev > s.cfg.MaxRiseEntire {
				next = prev + s.cfg.MaxRiseEntire
			}
			s.aggEntire[m] = clamp01(next)

			endEM()
		}

		endPass()
	} else if !s.lastEntireTime.IsZero() {
		// ===== Entire Decay (When Stale) =====

		// If we haven't run entire recently, decay the entire evidence
		// This prevents stale entire scores from persisting too long
		// Calculate how long since last entire update (in analysis windows)
		windowsSince := float64(s.hist[i].Time.Sub(s.lastEntireTime)) / float64(s.cfg.AnalysisWindow)

		// If we've exceeded the hold TTL, start decaying
		// E.g., after 12 windows without update, begin decay
		if windowsSince > s.cfg.EntireHoldTTLWindows {
			endDecay := func() {}
			if Profiling() {
				endDecay = Profile("imm.entire.decay")
			}

			// Decay entire evidence toward 0 using EWMA
			// This gradually reduces confidence in stale data
			alphaStale := ewmaAlpha(s.cfg.EntireStaleHalfLife)
			for m := range NumMetrics {
				// EWMA toward 0: old × (1-α) + 0 × α
				s.aggEntire[m] = clamp01(ewmaUpdate(s.aggEntire[m], 0, alphaStale))
			}
			endDecay()
		}
	}

	// Save entire evidence to current probe (for CSV output)
	for m := range NumMetrics {
		s.hist[i].SEntire[m] = s.aggEntire[m]
	}

	// ===== Phase 4: Final Score Computation =====

	endCombine := func() {}
	if Profiling() {
		endCombine = Profile("imm.combine.score")
	}

	// Combine per-metric evidence into single features using weights
	// RecentFeature = Σ(weight[i] × recent_evidence[i])
	// EntireFeature = Σ(weight[i] × entire_evidence[i])
	var rF, eF float64
	for m := range NumMetrics {
		w := s.cfg.Weights[m]
		rF += w * s.hist[i].SRecent[m]
		eF += w * s.hist[i].SEntire[m]
	}

	// Combine recent and entire features with configured weights
	// Typically: 5% recent + 95% entire
	// Recent provides responsiveness, entire provides stability
	finalEvidence := s.cfg.RecentMixWeight*rF + s.cfg.EntireMixWeight*eF

	// Clamp finalEvidence to [0, 1]
	if finalEvidence > 1 {
		finalEvidence = 1
	}

	// Transform evidence to 0-10 score using exponential function
	// Score = (1 - exp(-K × evidence)) × 10
	// This creates a sigmoid-like curve:
	// - Low evidence → low scores (0-2)
	// - Medium evidence → mid scores (3-7)
	// - High evidence → high scores (8-10)
	// K parameter controls the steepness of the curve
	score := (1 - math.Exp(-s.cfg.KScore*finalEvidence)) * 10

	// Store features and final score in probe
	s.hist[i].RecentFeature = rF
	s.hist[i].EntireFeature = eF
	s.hist[i].Score = score

	endCombine()

	// Return the fully analyzed probe
	return s.hist[i]
}

// AppendOnly appends a probe without performing analysis. Useful for store-only mode.
func (s *IMMState) AppendOnly(in Input) Probe {
	if Profiling() {
		defer Profile("imm.append-only")()
	}
	// Enforce ring buffer semantics: never exceed preallocated capacity.
	if cap(s.hist) > 0 && len(s.hist) == cap(s.hist) {
		s.DropHead(1)
	}
	var p Probe
	p.Time = in.Time
	for i := range NumMetrics {
		p.Values[i] = in.Values[i]
		// leave SRecent/SEntire zeroed
	}
	// RecentFeature/EntireFeature/Score remain zero
	s.hist = append(s.hist, p)
	return s.hist[len(s.hist)-1]
}

// ---------------- Helpers (no allocs) ----------------

// ewmaAlpha computes the alpha parameter for EWMA from a half-life.
// EWMA (Exponentially Weighted Moving Average) formula:
//
//	next = (1-α) × previous + α × new_value
//
// Alpha is derived from half-life using:
//
//	α = 1 - exp(-ln(2) / halfLife)
//
// After 'halfLife' iterations, the influence of the original value
// drops to approximately 50%.
//
// Examples:
//
//	halfLife=1  → α≈0.693 (fast decay, 50% influence after 1 step)
//	halfLife=10 → α≈0.067 (slow decay, 50% influence after 10 steps)
//	halfLife≤0  → α=1.0   (no smoothing, use new value directly)
func ewmaAlpha(halfLife float64) float64 {
	if halfLife <= 0 {
		return 1 // No smoothing
	}
	return 1 - math.Exp(-math.Ln2/halfLife)
}

// ewmaUpdate applies one EWMA update step.
// Formula: new = (1-α) × old + α × x
//
// Parameters:
//
//	prev: previous aggregated value
//	x: new measurement
//	a: alpha parameter (0 to 1)
//
// Returns:
//
//	Updated aggregated value
func ewmaUpdate(prev, x, a float64) float64 {
	return (1-a)*prev + a*x
}

// clamp01 restricts a float to the [0, 1] range.
// Used to keep evidence scores and probabilities in valid range.
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// clampOdd ensures a value is odd and within [lo, hi] range.
// This is used for median filter window sizes, which must be odd
// to have a well-defined center point.
//
// Algorithm:
// 1. Clamp to [lo, hi]
// 2. If even, try to decrement (if > lo) or increment (if < hi)
// 3. Ensure result is at least 1
//
// Examples:
//
//	clampOdd(10, 1, 20) → 9 (made odd by decrementing)
//	clampOdd(2, 1, 10) → 3 (made odd by incrementing)
//	clampOdd(5, 1, 10) → 5 (already odd)
func clampOdd(val, lo, hi int) int {
	if hi <= 0 {
		return 1
	}
	// Clamp to range
	if val < lo {
		val = lo
	}
	if val > hi {
		val = hi
	}
	// Make odd
	if val%2 == 0 {
		if val > lo {
			val-- // Prefer smaller odd value
		} else if val < hi {
			val++ // Can't go lower, go higher
		}
	}
	// Ensure at least 1
	if val < 1 {
		val = 1
	}
	return val
}

// ensureF64 ensures a float64 slice has at least n capacity.
// Reuses existing buffer if large enough, otherwise allocates new.
// Returns a slice of exactly n elements.
// This pattern avoids repeated allocations in hot paths.
func ensureF64(buf []float64, n int) []float64 {
	if cap(buf) < n {
		buf = make([]float64, n)
	}
	return buf[:n]
}

// ensureU64 ensures a uint64 slice has at least n capacity.
// Reuses existing buffer if large enough, otherwise allocates new.
// Returns a slice of exactly n elements.
func ensureU64(buf []uint64, n int) []uint64 {
	if cap(buf) < n {
		buf = make([]uint64, n)
	}
	return buf[:n]
}

// ensureKV ensures a key-value slice has at least n capacity.
// Used for Spearman rank correlation calculations.
func ensureKV(buf []kv, n int) []kv {
	if cap(buf) < n {
		buf = make([]kv, n)
	}
	return buf[:n]
}

// relTimesInto converts absolute timestamps to relative times in seconds.
// The first probe's time becomes 0.0, subsequent times are seconds elapsed.
// This improves numerical stability in calculations and simplifies the math.
//
// Parameters:
//
//	rows: slice of probes with timestamps
//	out: output buffer for relative times (must be same length as rows)
func relTimesInto(rows []Probe, out []float64) {
	t0 := rows[0].Time
	for i := range rows {
		out[i] = rows[i].Time.Sub(t0).Seconds()
	}
}

// takeMetricInto extracts one metric's values from all probes.
// Fills output buffer with values[m] from each probe.
//
// Parameters:
//
//	rows: slice of probes
//	m: metric index (0=heap, 1=rss, etc.)
//	out: output buffer (must be same length as rows)
func takeMetricInto(rows []Probe, m int, out []uint64) {
	for i := range rows {
		out[i] = rows[i].Values[m]
	}
}

// toF64Into converts uint64 values to float64.
// Simple conversion with no scaling or transformation.
func toF64Into(u []uint64, out []float64) {
	for i := range u {
		out[i] = float64(u[i])
	}
}

// medianFilterInto applies a median filter to remove noise spikes.
//
// A median filter replaces each value with the median of a surrounding window.
// This is highly effective at removing outliers while preserving trends:
// - A single spike doesn't affect the median
// - Gradually changing values are preserved
// - Sharp edges are somewhat smoothed
//
// Algorithm:
// For each position i:
//  1. Extract window of values centered at i
//  2. Sort the window
//  3. Take the middle value (median)
//  4. Replace values[i] with this median
//
// Edge handling:
// - At edges, use asymmetric windows (can't center perfectly)
// - Window is always odd-sized for well-defined median
//
// Parameters:
//
//	values: input data to filter
//	windowSize: size of median window (will be made odd if even)
//	out: output buffer for filtered values (must be same length as values)
//	win: scratch buffer for sorting window (must be at least windowSize long)
//
// Returns:
//
//	Slice of filtered values (points to out buffer)
//
// Performance:
//
//	O(n × w × log(w)) where n=len(values), w=windowSize
//	No allocations (uses provided buffers)
func medianFilterInto(values []uint64, windowSize int, out, win []uint64) []uint64 {
	if Profiling() {
		defer Profile("imm.median")()
	}

	// Handle edge cases
	if windowSize < 1 {
		copy(out, values)
		return out[:len(values)]
	}

	// Ensure window size is odd (needed for well-defined median)
	if windowSize%2 == 0 {
		windowSize++
	}

	n := len(values)
	if windowSize == 1 || windowSize > n {
		// No filtering needed or window too large
		copy(out, values)
		return out[:n]
	}

	out = out[:n]
	half := windowSize / 2 // Half-width of window

	// Process each position
	for i := range n {
		// Determine window bounds [start, end]
		// Try to center window at i, but adjust at edges
		start := i - half
		if start < 0 {
			start = 0
		}
		end := i + half
		if end >= n {
			end = n - 1
		}

		// Extract window and sort it
		k := end - start + 1
		tmp := win[:k]
		copy(tmp, values[start:end+1])
		sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })

		// Take median (middle element of sorted window)
		out[i] = tmp[k/2]
	}

	return out
}

// theilSenSlopeWithBuf computes the Theil-Sen slope estimator.
//
// The Theil-Sen estimator is a robust method for linear regression that
// is resistant to outliers. Unlike least squares, a few bad data points
// don't significantly affect the result.
//
// Algorithm:
// 1. Compute the slope between every pair of points: (y[j]-y[i])/(x[j]-x[i])
// 2. Take the median of all these pairwise slopes
//
// Why it's robust:
// - Outliers contribute only a few extreme slopes
// - The median ignores these extremes
// - Breakdown point: can handle up to ~29% outliers
//
// For large datasets (>50k pairs), we sample randomly to stay within memory limits.
// Even with sampling, the median is a good estimate of the true slope.
//
// Parameters:
//
//	xs: X values (typically time in seconds)
//	ys: Y values (typically memory in bytes)
//	slopes: reusable buffer for pairwise slopes (will grow as needed)
//
// Returns:
//
//	Median slope (bytes per second if xs is time and ys is memory)
//
// Performance:
//
//	O(n²) for n < ~300 points (exact calculation)
//	O(1) for larger n (fixed sample size of 50k pairs)
//	Sorting: O(k log k) where k = number of slopes
func theilSenSlopeWithBuf(xs, ys []float64, slopes *[]float64) float64 {
	if Profiling() {
		defer Profile("imm.theilsen")()
	}
	n := len(xs)
	if n < 2 {
		return 0 // Need at least 2 points for a slope
	}

	const maxPairs = 50000   // Memory limit: ~400KB for float64 slopes
	total := n * (n - 1) / 2 // Total number of pairs

	s := *slopes
	if cap(s) < min(maxPairs, total) {
		// Allocate buffer if needed
		s = make([]float64, 0, min(maxPairs, total))
	} else {
		// Reuse existing buffer
		s = s[:0]
	}

	if total <= maxPairs {
		// Small dataset: compute all pairwise slopes exactly
		for i := range n - 1 {
			xi := xs[i]
			yi := ys[i]
			for j := i + 1; j < n; j++ {
				dx := xs[j] - xi
				if dx == 0 {
					continue // Avoid division by zero
				}
				// Slope = rise / run
				s = append(s, (ys[j]-yi)/dx)
			}
		}
	} else {
		// Large dataset: randomly sample pairs to limit memory usage
		// Use simple LCG (Linear Congruential Generator) for reproducible randomness
		seed := int64(1)
		rng := func() int {
			seed = (1103515245*seed + 12345) & 0x7fffffff
			return int(seed)
		}

		// Sample maxPairs random pairs
		for range maxPairs {
			// Pick random i and j where i < j
			i := rng() % (n - 1)
			j := i + 1 + rng()%(n-i-1)

			dx := xs[j] - xs[i]
			if dx == 0 {
				continue
			}
			s = append(s, (ys[j]-ys[i])/dx)
		}
	}

	if len(s) == 0 {
		return 0 // No valid slopes (all dx == 0)
	}

	// Sort and take median
	sort.Float64s(s)
	*slopes = s
	return s[len(s)/2] // Median is middle element of sorted array
}

// pearsonR2 computes the Pearson correlation coefficient squared (R²).
//
// R² measures how well a linear model fits the data:
// - R² = 1.0: perfect linear relationship (all points on a line)
// - R² = 0.0: no linear relationship
// - R² between 0 and 1: partial linear relationship
//
// R² is the square of the Pearson correlation coefficient (r):
//
//	r = Cov(X,Y) / (σ_X × σ_Y)
//
// Where:
//
//	Cov(X,Y) = covariance of X and Y
//	σ_X, σ_Y = standard deviations of X and Y
//
// We use the computational formula to avoid numerical issues:
//
//	numerator = n×Σ(xy) - Σ(x)×Σ(y)
//	denominator = sqrt[(n×Σ(x²) - (Σx)²) × (n×Σ(y²) - (Σy)²)]
//	r = numerator / denominator
//	R² = r²
//
// Parameters:
//
//	xs: X values
//	ys: Y values (must be same length as xs)
//
// Returns:
//
//	R² value between 0 and 1
//
// Performance: O(n) - single pass through data
func pearsonR2(xs, ys []float64) float64 {
	if Profiling() {
		defer Profile("imm.pearsonR2")()
	}
	n := float64(len(xs))
	if n < 2 {
		return 0
	}
	var sx, sy, sxx, syy, sxy float64
	for i := range xs {
		x, y := xs[i], ys[i]
		sx += x
		sy += y
		sxx += x * x
		syy += y * y
		sxy += x * y
	}
	num := n*sxy - sx*sy
	den := math.Sqrt((n*sxx - sx*sx) * (n*syy - sy*sy))
	if den == 0 {
		return 0
	}
	r := num / den
	return r * r
}

// Ranking without allocs (uses provided buffers)
func rankInto(v []float64, kvBuf []kv, rBuf []float64) {
	n := len(v)
	for i := range n {
		kvBuf[i] = kv{v: v[i], i: i}
	}
	sort.Slice(kvBuf[:n], func(i, j int) bool { return kvBuf[i].v < kvBuf[j].v })
	for i := 0; i < n; {
		j := i + 1
		for j < n && kvBuf[j].v == kvBuf[i].v {
			j++
		}
		avg := 0.5*float64(i+j-1) + 1.0
		for k := i; k < j; k++ {
			rBuf[kvBuf[k].i] = avg
		}
		i = j
	}
}

// spearmanRhoWithBuf computes the Spearman rank correlation coefficient (ρ).
//
// Spearman ρ measures monotonic relationships (consistently increasing or decreasing)
// unlike Pearson which only measures linear relationships.
//
// Key difference from Pearson:
// - Pearson: detects linear trends (y = mx + b)
// - Spearman: detects any monotonic trend (e.g., y = x², y = log(x), etc.)
//
// Algorithm:
// 1. Convert X values to ranks (1st smallest = rank 1, etc.)
// 2. Convert Y values to ranks
// 3. Compute Pearson correlation on the ranks
//
// Interpretation:
// - ρ = +1: perfect monotonic increase
// - ρ = -1: perfect monotonic decrease
// - ρ = 0: no monotonic relationship
//
// Advantages:
// - Resistant to outliers (works on ranks, not raw values)
// - Detects non-linear but consistent growth
// - Useful for memory that grows in bursts (not smoothly linear)
//
// Parameters:
//
//	xs, ys: input data
//	kvBuf: buffer for key-value pairs (for ranking)
//	r1, r2: buffers for ranks
//
// Returns:
//
//	Spearman ρ between -1 and +1
func spearmanRhoWithBuf(xs, ys []float64, kvBuf *[]kv, r1, r2 *[]float64) float64 {
	if Profiling() {
		defer Profile("imm.spearman")()
	}
	n := len(xs)
	if n < 2 {
		return 0
	}
	*kvBuf = ensureKV(*kvBuf, n)
	*r1 = ensureF64(*r1, n)
	*r2 = ensureF64(*r2, n)
	rankInto(xs, *kvBuf, *r1)
	rankInto(ys, *kvBuf, *r2)

	N := float64(n)
	var sx, sy, sxx, syy, sxy float64
	for i := range n {
		x, y := (*r1)[i], (*r2)[i]
		sx += x
		sy += y
		sxx += x * x
		syy += y * y
		sxy += x * y
	}
	num := N*sxy - sx*sy
	den := math.Sqrt((N*sxx - sx*sx) * (N*syy - sy*sy))
	if den == 0 {
		return 0
	}
	return num / den
}

// Percentile on sorted slice
func percentileSorted(x []float64, p float64) float64 {
	n := len(x)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return x[0]
	}
	if p >= 1 {
		return x[n-1]
	}
	pos := p * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return x[lo]
	}
	w := pos - float64(lo)
	return x[lo]*(1-w) + x[hi]*w
}

func robustNoiseBpsWithBuf(xs, ys []float64, diffs *[]float64) (float64, float64) {
	if Profiling() {
		defer Profile("imm.noise.robust")()
	}
	if len(xs) < 2 {
		return 0, 0
	}
	d := *diffs
	d = d[:0]
	for i := 1; i < len(xs); i++ {
		dt := xs[i] - xs[i-1]
		if dt <= 0 {
			continue
		}
		d = append(d, (ys[i]-ys[i-1])/dt)
	}
	if len(d) == 0 {
		*diffs = d
		return 0, 0
	}
	sort.Float64s(d)
	med := d[len(d)/2]
	const p16 = 0.15865525393145707
	const p84 = 0.8413447460685429
	sigma := 0.5 * (percentileSorted(d, p84) - percentileSorted(d, p16))
	*diffs = d
	return med, sigma
}

func growthNoiseBpsWithBuf(xs, ys []float64, diffs *[]float64) (float64, float64) {
	if Profiling() {
		defer Profile("imm.noise.growth")()
	}
	if len(xs) < 2 {
		return 0, 0
	}
	d := *diffs
	d = d[:0]
	for i := 1; i < len(xs); i++ {
		dt := xs[i] - xs[i-1]
		if dt <= 0 {
			continue
		}
		v := (ys[i] - ys[i-1]) / dt
		if v < 0 {
			v = 0
		}
		d = append(d, v)
	}
	if len(d) == 0 {
		*diffs = d
		return 0, 0
	}
	sort.Float64s(d)
	med := d[len(d)/2]
	const p16 = 0.15865525393145707
	const p84 = 0.8413447460685429
	sigma := 0.5 * (percentileSorted(d, p84) - percentileSorted(d, p16))
	*diffs = d
	return med, sigma
}

// evidenceWith calculates evidence score for memory leak detection.
//
// This is the heart of the leak detection algorithm. It combines:
// - Trend slope (how fast memory is growing)
// - Threshold (minimum growth rate to consider significant)
// - Noise level (how variable the data is)
// - Quality (how reliable the trend is)
//
// Into a single evidence score from 0 to 1.
//
// Algorithm:
//  1. If quality is bad (low R² and low Spearman), return 0 (don't trust the trend)
//  2. Compute z-score: how many standard deviations above threshold is the slope?
//     z = (slope - effectiveThreshold) / (sigma × sigmaFactor)
//  3. If z <= deadband, return 0 (slope not significant enough)
//  4. Otherwise, compute evidence = 1 - exp(-beta × (z - deadband))
//
// The z-score formula:
//
//	z = (observed - expected) / standardError
//
// This tells us: "How unusual is this slope?"
// - z < 0: slope below threshold (no leak)
// - z = 0: slope exactly at threshold (borderline)
// - z > 0: slope above threshold (potential leak)
// - z > deadband: statistically significant leak
//
// The evidence formula:
//
//	evidence = 1 - exp(-beta × (z - deadband))
//
// This maps z-score to [0,1]:
// - z <= deadband: evidence = 0
// - z >> deadband: evidence → 1
// - beta controls how fast evidence saturates
//
// Parameters:
//
//	slope: detected trend slope (bytes/second)
//	eff: effective threshold (max of fixed threshold and noise-based threshold)
//	sigma: noise level estimate
//	qualityOK: whether trend is reliable (R² or Spearman passed threshold)
//	sigmaFactor: multiplier for sigma in z-score denominator
//	zDead: deadband - minimum z-score to trigger detection
//	beta: evidence saturation rate
//
// Returns:
//
//	Evidence score from 0.0 (no leak) to 1.0 (strong leak signal)
//
// Example:
//
//	slope = 300 bytes/sec (observed growth)
//	eff = 200 bytes/sec (threshold)
//	sigma = 50 bytes/sec (noise)
//	sigmaFactor = 2.0
//	zDead = 1.0
//	beta = 0.8
//
//	z = (300 - 200) / (50 × 2) = 100 / 100 = 1.0
//	Since z = zDead, we're right at the edge
//	evidence = 1 - exp(-0.8 × (1.0 - 1.0)) = 1 - exp(0) = 1 - 1 = 0
//
//	If slope were 400:
//	z = (400 - 200) / 100 = 2.0
//	evidence = 1 - exp(-0.8 × (2.0 - 1.0)) = 1 - exp(-0.8) ≈ 0.55
func evidenceWith(slope, eff, sigma float64, qualityOK bool, sigmaFactor, zDead, beta float64) float64 {
	// Quality check: if trend is not reliable, return 0
	// This happens when both R² and Spearman are below thresholds
	// Means the data doesn't follow a clear trend (too noisy or random)
	if !qualityOK {
		return 0
	}

	// Compute denominator for z-score: sigma × sigmaFactor
	// This is the "standard error" we use to normalize the slope
	den := sigma * sigmaFactor
	if den <= 0 {
		// Fallback if we can't estimate noise properly
		// Use half the threshold as a conservative estimate
		den = eff * 0.5
		if den <= 0 {
			den = 1 // Last resort: use 1 to avoid division by zero
		}
	}

	// Compute z-score: how many "standard errors" above threshold?
	// z > 0: slope exceeds threshold
	// z > deadband: slope significantly exceeds threshold (statistically significant)
	z := (slope - eff) / den

	// Deadband check: if z-score below deadband, no evidence
	// Deadband prevents triggering on marginally above-threshold slopes
	// Only trigger when we're confident it's a real leak
	if z <= zDead {
		return 0
	}

	// Compute evidence using exponential saturation formula
	// As z increases above deadband, evidence approaches 1
	// Beta controls saturation speed:
	// - High beta: fast saturation (aggressive detection)
	// - Low beta: slow saturation (conservative detection)
	return 1 - math.Exp(-beta*(z-zDead))
}
