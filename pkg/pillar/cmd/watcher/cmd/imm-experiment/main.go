// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	immcore "github.com/lf-edge/eve/pkg/pillar/cmd/watcher/internal/immcore"
)

var (
	// I/O
	inPath  = flag.String("in", "memory_usage.csv", "input CSV exported by IMM")
	outPath = flag.String("out", "memory_usage.recalc.csv", "output CSV")

	// Combiner
	recentMix = flag.Float64("recent-mix", 0.0, "Recent mix weight (applied only if provided)")
	entireMix = flag.Float64("entire-mix", 0.0, "Entire mix weight (applied only if provided)")
	kScore    = flag.Float64("k-score", 0.0, "Score mapping factor (applied only if provided)")

	// Windows / cadence
	analysis  = flag.Duration("analysis-window", 0, "Analysis window (e.g. 10m)")
	interval  = flag.Duration("probe-interval", 0, "Probe interval (e.g. 5s)")
	slopeTh   = flag.Float64("slope-threshold-bps", 0, "Absolute slope threshold in B/s")
	smoothWin = flag.Duration("smoothing-window", 0, "Median smoothing window for RECENT (duration). If set, derives SmoothingProbeCount from probe interval")
	smoothCnt = flag.Int("smoothing-probe-count", 0, "Median smoothing length for RECENT (probes). If set, overrides smoothing-window")
	entEvery  = flag.Int("entire-every-win", 0, "Run ENTIRE pass once per N analysis windows")
	entMedian = flag.Int("entire-median-cap", 0, "Max median window used by ENTIRE pass")
	entHold   = flag.Float64("entire-hold-ttl-windows", 0, "Keep ENTIRE evidence for this many analysis windows before decay")
	entStale  = flag.Float64("entire-stale-half-life", 0, "ENTIRE stale decay half-life (in analysis windows)")
	recHL     = flag.Float64("recent-half-life-windows", 0, "EWMA half-life for RECENT (in analysis windows)")
	entHL     = flag.Float64("entire-half-life-windows", 0, "EWMA half-life for ENTIRE (in analysis windows)")

	// Evidence gates / sensitivity
	minR2      = flag.Float64("min-r2-gate", 0, "Quality gate: minimum R^2")
	minRho     = flag.Float64("min-spearman-gate", 0, "Quality gate: minimum Spearman rho")
	zDeadRec   = flag.Float64("z-deadband-recent", 0, "Deadband for RECENT evidence")
	zDeadEnt   = flag.Float64("z-deadband-entire", 0, "Deadband for ENTIRE evidence")
	sigmaRec   = flag.Float64("sigma-factor-recent", 0, "Sigma factor for RECENT noise normalization")
	sigmaEnt   = flag.Float64("sigma-factor-entire", 0, "Sigma factor for ENTIRE noise normalization")
	evidBeta   = flag.Float64("evidence-beta", 0, "Evidence curve steepness beta")
	maxRiseRec = flag.Float64("max-rise-recent", 0, "Max RECENT rise per probe")
	maxRiseEnt = flag.Float64("max-rise-entire", 0, "Max ENTIRE rise per probe")

	// Weights & history
	weightsStr = flag.String("metric-weights", "", "Per-metric weights, e.g. heap=1.0,rss=0.3 (names must match CSV header)")
	maxHist    = flag.Int("max-history", 0, "Max history length (probes) for the engine (0 = unlimited)")
)

func main() {
	// Manually detect -h/-help/--help first and strip it so we can do custom help.
	wantHelp := stripHelpFromArgs()

	flag.Parse()
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Resolve metrics from input header (if possible).
	metricNames, _ := detectMetricNames(*inPath)
	nm := len(metricNames)
	// Note: if wantHelp is true and err != nil, we still continue to print help

	// Build weights (by name) if requested.
	var weights []float64
	if set["metric-weights"] && nm > 0 {
		weights = parseWeights(*weightsStr, metricNames)
	}

	// Effective config: defaults overridden by provided flags.
	cfg := makeEffectiveConfig(set, weights)

	// If help was requested: print usage + semantics + *current* effective values, then exit.
	if wantHelp {
		printUsageWithSemanticsAndValues(os.Args[0], *inPath, *outPath, metricNames, cfg)
		return
	}

	// Normal run: ingest, recalc, write.
	f, err := os.Open(*inPath)
	must(err)
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)

	hdr, err := r.Read()
	must(err)

	timeIdx := indexOf(hdr, "time")
	if timeIdx < 0 {
		fatal("no time column")
	}
	scoreIdx := indexOf(hdr, "score")
	if scoreIdx < 0 {
		fatal("no score column (expected IMM export)")
	}
	if nm == 0 {
		for i := timeIdx + 1; i < scoreIdx; i++ {
			metricNames = append(metricNames, hdr[i])
		}
	}

	engine := immcore.NewState(cfg)

	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		must(err)

		t, err := time.Parse(time.RFC3339, rec[timeIdx])
		must(err)

		var vals [immcore.NumMetrics]uint64
		for i := range immcore.NumMetrics {
			u, _ := parseU64(rec[timeIdx+1+i])
			vals[i] = u
		}
		engine.Step(immcore.Input{Time: t, Values: vals})
	}

	if err := writeOut(*outPath, metricNames, engine.History()); err != nil {
		fatal(err.Error())
	}
}

// ---------- help & printing ----------

func stripHelpFromArgs() bool {
	args := os.Args[1:]
	newArgs := make([]string, 0, len(args))
	want := false
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			want = true
			continue
		}
		newArgs = append(newArgs, a)
	}
	if want {
		os.Args = append([]string{os.Args[0]}, newArgs...)
	}
	return want
}

func printUsageWithSemanticsAndValues(bin, in, out string, metricNames []string, cfg immcore.Config) {
	// Show standard usage/defaults:
	log.Printf("Usage: %s [flags]\n\n", filepath.Base(bin))
	log.Println("Flags:")
	flag.CommandLine.PrintDefaults()

	// Derived values (mirror engine math).
	winProbes := 1
	if cfg.ProbingInterval > 0 {
		winProbes = int(cfg.AnalysisWindow / cfg.ProbingInterval)
		if winProbes < 1 {
			winProbes = 1
		}
	}
	entireEveryProbes := cfg.EntireUpdateEveryWin * winProbes
	if entireEveryProbes < 1 {
		entireEveryProbes = 1
	}
	smoothingWindow := time.Duration(cfg.SmoothingProbeCount) * cfg.ProbingInterval

	// Effective metric weights (if we know metrics).
	effW := effectiveWeights(cfg.Weights, len(metricNames))

	log.Println("\n--- Current effective values (this run) ---")
	log.Printf("Input file:                 %s\n", in)
	log.Printf("Output file:                %s\n", out)
	if len(metricNames) > 0 {
		log.Printf("Metrics (%d):               %s\n", len(metricNames), strings.Join(metricNames, ", "))
	} else {
		log.Printf("Metrics:                    (could not detect; open %q to infer names)\n", in)
	}

	// Group: Windows / cadence
	log.Println("\n[Windows / cadence]")
	log.Printf("  AnalysisWindow [-analysis-window]:         %s\n", cfg.AnalysisWindow)
	log.Printf("    ↑ steadier, fewer false positives; ↓ more reactive, noisier\n")
	log.Printf("  ProbingInterval [-probe-interval]:        %s\n", cfg.ProbingInterval)
	log.Printf("    ↑ fewer points/slower; ↓ more points/faster (more CPU/GC)\n")
	log.Printf("  ProbesPerWindow (derived):                %d\n", winProbes)
	log.Printf("  SlopeThresholdBps [-slope-threshold-bps]: %.6f\n", cfg.SlopeThresholdBps)
	log.Printf("    ↑ harder to trigger; ↓ easier, more sensitive\n")
	log.Printf("  SmoothingProbeCount [-smoothing-probe-count]: %d\n", cfg.SmoothingProbeCount)
	log.Printf("  SmoothingWindow≈ [-smoothing-window]:         %s\n", smoothingWindow)
	log.Printf("    ↑ stronger spike filtering; ↓ more twitchy\n")
	log.Printf("  EntireUpdateEveryWin [-entire-every-win]: %d  (≈ every %d probes)\n", cfg.EntireUpdateEveryWin, entireEveryProbes)
	log.Printf("    ↑ ENTIRE less often (slower); ↓ more often (CPU↑, responsiveness↑)\n")
	log.Printf("  EntireMedianCap [-entire-median-cap]:     %d\n", cfg.EntireMedianCap)
	log.Printf("    ↑ very stable long-term; ↓ more responsive ENTIRE\n")
	log.Printf("  EntireHoldTTLWindows [-entire-hold-ttl-windows]: %.6f\n", cfg.EntireHoldTTLWindows)
	log.Printf("    ↑ stickier ENTIRE evidence; ↓ decays sooner between runs\n")
	log.Printf("  EntireStaleHalfLife [-entire-stale-half-life]:  %.6f windows\n", cfg.EntireStaleHalfLife)
	log.Printf("    ↑ slower decay; ↓ faster normalization\n")
	log.Printf("  RecentHalfLifeWindows [-recent-half-life-windows]: %.6f\n", cfg.RecentHalfLifeWindows)
	log.Printf("    ↑ smoother RECENT; ↓ more twitchy RECENT\n")
	log.Printf("  EntireHalfLifeWindows [-entire-half-life-windows]: %.6f\n", cfg.EntireHalfLifeWindows)
	log.Printf("    ↑ steadier ENTIRE; ↓ faster adapting ENTIRE\n")

	// Group: Evidence & gates
	log.Println("\n[Evidence gates / sensitivity]")
	log.Printf("  MinR2Gate [-min-r2-gate]:                 %.6f\n", cfg.MinR2Gate)
	log.Printf("  MinSpearmanGate [-min-spearman-gate]:     %.6f\n", cfg.MinSpearmanGate)
	log.Printf("    ↑ stricter quality requirement; ↓ looser/more sensitive\n")
	log.Printf("  ZDeadbandRecent [-z-deadband-recent]:     %.6f\n", cfg.ZDeadbandRecent)
	log.Printf("  ZDeadbandEntire [-z-deadband-entire]:     %.6f\n", cfg.ZDeadbandEntire)
	log.Printf("    ↑ larger deadband → less sensitive; ↓ smaller → more sensitive\n")
	log.Printf("  SigmaFactorRecent [-sigma-factor-recent]: %.6f\n", cfg.SigmaFactorRecent)
	log.Printf("  SigmaFactorEntire [-sigma-factor-entire]: %.6f\n", cfg.SigmaFactorEntire)
	log.Printf("    ↑ bigger denom (z↓) → less sensitive; ↓ more sensitive\n")
	log.Printf("  EvidenceBeta [-evidence-beta]:            %.6f\n", cfg.EvidenceBeta)
	log.Printf("    ↑ faster ramp after deadband; ↓ softer ramp\n")
	log.Printf("  MaxRiseRecent [-max-rise-recent]:         %.6f\n", cfg.MaxRiseRecent)
	log.Printf("  MaxRiseEntire [-max-rise-entire]:         %.6f\n", cfg.MaxRiseEntire)
	log.Printf("    ↑ faster jumps per probe; ↓ slower, controlled growth\n")

	// Group: Combiner
	log.Println("\n[Combiner]")
	log.Printf("  RecentMixWeight [-recent-mix]:            %.6f\n", cfg.RecentMixWeight)
	log.Printf("    ↑ more short-term sensitivity; ↓ more stable\n")
	log.Printf("  EntireMixWeight [-entire-mix]:            %.6f\n", cfg.EntireMixWeight)
	log.Printf("    ↑ more long-term stability; ↓ more volatile\n")
	log.Printf("  KScore [-k-score]:                        %.6f\n", cfg.KScore)
	log.Printf("    ↑ steeper score mapping; ↓ flatter mapping\n")

	// Group: Weights & history
	log.Println("\n[Weights & history]")
	if len(metricNames) > 0 {
		for i, n := range metricNames {
			w := 0.5
			if i < len(effW) {
				w = effW[i]
			}
			log.Printf("  metric weight for %s [-metric-weights]:  %.6f\n", n, w)
		}
	} else {
		log.Println("  metric weights [-metric-weights]:         (unknown metrics)")
	}
	log.Printf("  MaxHistory [-max-history]:                %d (affects memory, not score directly)\n", cfg.MaxHistory)

	log.Printf("\nLimits\n")
	log.Printf("  immcore.NumMetrics:                       %d\n", immcore.NumMetrics)

	log.Println("\n(End of help)")
}

// ---------- config building ----------

func makeEffectiveConfig(set map[string]bool, weights []float64) immcore.Config {
	cfg := immcore.DefaultConfig()

	// Windows / cadence
	if set["analysis-window"] {
		cfg.AnalysisWindow = *analysis
	}
	if set["probe-interval"] {
		cfg.ProbingInterval = *interval
	}
	if set["slope-threshold-bps"] {
		cfg.SlopeThresholdBps = *slopeTh
	}
	if set["smoothing-probe-count"] {
		cfg.SmoothingProbeCount = *smoothCnt
	} else if set["smoothing-window"] {
		if cfg.ProbingInterval <= 0 {
			cfg.ProbingInterval = immcore.DefaultConfig().ProbingInterval
		}
		cfg.SmoothingProbeCount = int(((*smoothWin) + cfg.ProbingInterval/2) / cfg.ProbingInterval)
	}
	if set["entire-every-win"] {
		cfg.EntireUpdateEveryWin = *entEvery
	}
	if set["entire-median-cap"] {
		cfg.EntireMedianCap = *entMedian
	}
	if set["entire-hold-ttl-windows"] {
		cfg.EntireHoldTTLWindows = *entHold
	}
	if set["entire-stale-half-life"] {
		cfg.EntireStaleHalfLife = *entStale
	}
	if set["recent-half-life-windows"] {
		cfg.RecentHalfLifeWindows = *recHL
	}
	if set["entire-half-life-windows"] {
		cfg.EntireHalfLifeWindows = *entHL
	}

	// Evidence gates / sensitivity
	if set["min-r2-gate"] {
		cfg.MinR2Gate = *minR2
	}
	if set["min-spearman-gate"] {
		cfg.MinSpearmanGate = *minRho
	}
	if set["z-deadband-recent"] {
		cfg.ZDeadbandRecent = *zDeadRec
	}
	if set["z-deadband-entire"] {
		cfg.ZDeadbandEntire = *zDeadEnt
	}
	if set["sigma-factor-recent"] {
		cfg.SigmaFactorRecent = *sigmaRec
	}
	if set["sigma-factor-entire"] {
		cfg.SigmaFactorEntire = *sigmaEnt
	}
	if set["evidence-beta"] {
		cfg.EvidenceBeta = *evidBeta
	}
	if set["max-rise-recent"] {
		cfg.MaxRiseRecent = *maxRiseRec
	}
	if set["max-rise-entire"] {
		cfg.MaxRiseEntire = *maxRiseEnt
	}

	// Combiner
	if set["recent-mix"] {
		cfg.RecentMixWeight = *recentMix
	}
	if set["entire-mix"] {
		cfg.EntireMixWeight = *entireMix
	}
	if set["k-score"] {
		cfg.KScore = *kScore
	}

	// Weights & history
	if len(weights) != 0 {
		cfg.Weights = weights
	}
	if set["max-history"] {
		cfg.MaxHistory = *maxHist
	}
	return cfg
}

// ---------- header & weights ----------

func detectMetricNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	hdr, err := r.Read()
	if err != nil {
		return nil, err
	}
	timeIdx := indexOf(hdr, "time")
	if timeIdx < 0 {
		return nil, errors.New("no time column")
	}
	scoreIdx := indexOf(hdr, "score")
	if scoreIdx < 0 {
		return nil, errors.New("no score column (expected IMM export)")
	}
	var metricNames []string
	for i := timeIdx + 1; i < scoreIdx; i++ {
		metricNames = append(metricNames, hdr[i])
	}
	return metricNames, nil
}

func effectiveWeights(w []float64, nm int) []float64 {
	if nm == 0 {
		return nil
	}
	if len(w) == nm {
		return w
	}
	out := make([]float64, nm)
	for i := range out {
		out[i] = 0.5
	}
	return out
}

// ---------- CSV output (normal run) ----------

func writeOut(path string, metrics []string, probes []immcore.Probe) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	w := csv.NewWriter(out)

	// header
	h := []string{"time"}
	h = append(h, metrics...)
	h = append(h, "score", "recent_feature", "entire_feature")
	for _, m := range metrics {
		h = append(h, "s_recent:"+m)
	}
	for _, m := range metrics {
		h = append(h, "s_entire:"+m)
	}
	if err := w.Write(h); err != nil {
		return err
	}

	for _, p := range probes {
		rec := []string{p.Time.Format(time.RFC3339)}
		for i := range metrics {
			rec = append(rec, strconv.FormatUint(p.Values[i], 10))
		}
		rec = append(rec,
			fmt.Sprintf("%.3f", p.Score),
			fmt.Sprintf("%.4f", p.RecentFeature),
			fmt.Sprintf("%.4f", p.EntireFeature),
		)
		for i := range metrics {
			rec = append(rec, fmt.Sprintf("%.4f", p.SRecent[i]))
		}
		for i := range metrics {
			rec = append(rec, fmt.Sprintf("%.4f", p.SEntire[i]))
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	w.Flush()
	log.Printf("Wrote %s\n", path)
	return w.Error()
}

// ---------- misc helpers ----------

func parseWeights(spec string, names []string) []float64 {
	m := map[string]float64{}
	for _, kv := range strings.Split(spec, ",") {
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(parts[1], "%f", &v); err != nil {
			continue
		}
		m[parts[0]] = v
	}
	out := make([]float64, len(names))
	for i, n := range names {
		if w, ok := m[n]; ok {
			out[i] = w
		} else {
			switch {
			case strings.EqualFold(n, "heap"):
				out[i] = 1.0
			case strings.EqualFold(n, "rss"):
				out[i] = 0.3
			default:
				out[i] = 0.5
			}
		}
	}
	return out
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func fatal(s string) { panic(s) }
func parseU64(s string) (uint64, error) {
	var u uint64
	_, err := fmt.Sscanf(s, "%d", &u)
	return u, err
}
