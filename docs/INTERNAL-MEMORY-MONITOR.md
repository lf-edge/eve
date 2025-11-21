# Internal Memory Monitor (IMM) Algorithm

## Overview

The Internal Memory Monitor (IMM) algorithm is designed to detect abnormal
upward trends in a system's memory usage (e.g.,
potential [memory leaks](https://en.wikipedia.org/wiki/Memory_leak)) by
analyzing [time-series data](https://en.wikipedia.org/wiki/Time_series).
Implemented in the `immcore` package of the EVE codebase (
`pkg/pillar/cmd/watcher/internal/immcore`), IMM processes incoming memory usage
samples and produces a risk **score** (0 to 10) indicating the likelihood of a
leak. To do this, IMM examines memory usage over two timescales – a short-term *
*recent window** and a long-term **entire window** – and applies statistical
techniques to differentiate genuine growth trends from normal noise.

## Dual Windows for Recent and Entire Trend Analysis

IMM maintains two sliding windows of data: a **recent window** capturing
short-term behavior, and an **entire window** capturing long-term behavior. The
recent window (configured via `AnalysisWindow`, default: 10 minutes) provides
sensitivity to sudden changes, while the entire window (all available history)
establishes a baseline of typical memory usage trends. By comparing metrics from
these two windows, IMM can tell if a current rise is anomalously steep relative
to historical behavior.

In each window, IMM computes a **slope** representing the rate of memory
change (in bytes per second). It uses the non-parametric *
*[Theil-Sen estimator](https://en.wikipedia.org/wiki/Theil%E2%80%93Sen_estimator)
** to calculate this slope robustly. Theil-Sen finds
the [median](https://en.wikipedia.org/wiki/Median) slope of all line pairs
through the data points, which makes it resistant
to [outlier](https://en.wikipedia.org/wiki/Outlier) points that might otherwise
skew
a [least-squares linear regression](https://en.wikipedia.org/wiki/Ordinary_least_squares).
In practice, this means even if memory usage has occasional spikes or dips, the
estimated slope still reflects the underlying trend (the median of pairwise
slopes ignores isolated aberrations). Theil-Sen is "insensitive to outliers" and
often called *"the most popular nonparametric technique for estimating a linear
trend"*, making it ideal for detecting slow leaks hidden in noisy data.

For each window, along with the slope, IMM also evaluates **trend quality**
metrics:

- **[Pearson R²](https://en.wikipedia.org/wiki/Pearson_correlation_coefficient) (
  coefficient of determination)** – how well a straight line fits the data in
  that window. This is essentially the squared Pearson correlation of time vs
  memory. An R² near 1.0 means the points lie almost perfectly on some line (a
  very linear trend), whereas a low R² means the data is widely scattered around
  the best-fit line (noisy or non-linear behavior).

- **[Spearman ρ](https://en.wikipedia.org/wiki/Spearman%27s_rank_correlation_coefficient) (
  rank correlation)** – how strongly monotonic the trend is. Spearman's rho is
  the Pearson correlation of the *ranks* of the data; it measures if memory
  consistently moves in one direction (upwards) without requiring a strict
  linear relationship. A high Spearman ρ close to 1 indicates a strong monotonic
  increase (memory usage rising steadily, even if not at a constant rate),
  whereas a lower value indicates reversals or irregular changes. Spearman's ρ
  is less sensitive to outliers and captures monotonic trends even when the
  exact linear fit is poor.

By checking R² and ρ in the **recent window**, IMM ensures that it responds to
*meaningful* upward trends rather than random fluctuations. For example, if
memory usage jumps up and down erratically, the recent R²/ρ will be low and IMM
will treat the high short-term slope with skepticism. Only when memory usage
climbs in a relatively smooth, one-directional way will both R² and ρ be high,
confirming a clear upward trend.

## Preprocessing: Median Filter for Noise Reduction

Before computing the slopes, IMM applies a *
*[median filter](https://en.wikipedia.org/wiki/Median_filter)** to the raw
memory usage series (especially in the recent window). A median filter replaces
each sample with the median of its neighbors (configured via
`SmoothingProbeCount`, default: 60 probes), which smooths out transient spikes
or dips. This is a classic noise-reduction technique: by taking the median,
short-lived outlier values are removed while the general trend is preserved. In
other words, the median filter "filters out noise and maintains the integrity of
signal transitions."

For IMM, this step is crucial to avoid false alarms from jitter. For instance,
if
a [garbage collection](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science))
frees a large chunk of memory momentarily, raw usage might dip then rise,
creating a temporary negative and positive slope. The median filter will blunt
such a one-off dip/spike so that the calculated slope doesn't wildly swing. The
result is a cleaner time-series where the Theil-Sen slope captures the gradual
trend of memory growth rather than every oscillation.

## Robust Variability Estimation (Sigma via Percentiles)

Using the long-term **entire window** data, IMM computes a robust estimate of
the **typical slope variability**, denoted here as σ (sigma). Rather than using
a [standard deviation](https://en.wikipedia.org/wiki/Standard_deviation) (which
can be skewed by outliers), IMM uses a *
*[percentile](https://en.wikipedia.org/wiki/Percentile)-based approach** to
derive sigma. In practice this involves looking at the 16th and 84th percentiles
of growth rates, which correspond roughly to ±1 standard deviation in
a [normal distribution](https://en.wikipedia.org/wiki/Normal_distribution). By
taking half the difference between the 84th and 16th percentile, one obtains a
robust sigma estimate that is *insensitive to extreme outliers*.

IMM's **`SigmaFactorRecent`** config parameter (default: 12.0) comes into play
here: it scales this robust σ for determining significance of recent changes.

Concretely, IMM uses the long-term window to gauge "normal" memory growth rates.
The algorithm defines an effective threshold as:

```text
effective_threshold = max(SlopeThresholdBps, SigmaFactorRecent × σ)
```

Here, **`SlopeThresholdBps`** (default: 208 bytes per second) is a minimum
baseline growth rate below which we consider growth negligible. This guards
against trivial slopes (e.g., a few bytes/sec) that might statistically register
as >0 but are not practically concerning. The **`SigmaFactorRecent`** multiplies
the baseline variability – effectively saying how many σ above the norm the
recent slope must be to be considered an anomaly.

This percentile-based sigma method ensures the threshold adapts to the noise
level of the system: on a very stable system even a small rise might be
significant, whereas on a noisy system we require a larger absolute rise to
reach the same number of standard deviations. It's a robust way to compute
variability because percentiles (like 16th–84th) are outlier-resistant.

By comparing the **recent window slope** to this threshold, IMM essentially
computes a **[z-score](https://en.wikipedia.org/wiki/Standard_score)** for the
recent trend: how many sigma is the current rise above the expected norm. If the
z-score is high (and beyond a configurable **deadband**, `ZDeadbandRecent`,
default: 1.25), it indicates a likely memory leak.

## Accumulating Evidence with Exponential Weighting (EWMA)

Raw detection of a high slope in one interval might not be enough to declare a
leak – memory might plateau or drop later. IMM therefore accumulates **evidence
** of a leak over time using
an [Exponentially Weighted Moving Average (EWMA)](https://en.wikipedia.org/wiki/Exponential_smoothing)
of a "leak evidence" signal. This is a form of temporal smoothing: each time
step, IMM *updates an internal evidence score* based on the new observation, and
*decays* older evidence exponentially.

Two key parameters in Config control this behavior, expressed as *
*[half-life](https://en.wikipedia.org/wiki/Half-life)** values:

- **`RecentHalfLifeWindows`** (default: 12.0) – Controls the EWMA for recent
  evidence. After this many analysis windows, the influence of old evidence
  drops to 50%.
- **`EntireHalfLifeWindows`** (default: 8.0) – Controls the EWMA for entire
  evidence. Smaller than recent because entire updates less frequently.

The half-life is the period over which evidence naturally diminishes by 50% if
no further supporting data is seen. A shorter half-life makes the evidence score
drop quickly (forgetting past alerts faster), whereas a longer half-life makes
evidence persist (integrating more history before fading).

IMM maintains separate evidence accumulators for:

- **Recent evidence** – Responds quickly to short-term trends
- **Entire evidence** – Accumulates confidence over longer periods

Mathematically, an EWMA applies a weight λ^k to data k steps old, where λ is a
decay factor related to the half-life τ by **λ = 0.5^(1/τ)**. After τ time
units, weights shrink to 50%. Thus, these half-life parameters let one tune *
*how quickly IMM forgets past behavior**.

The **`EvidenceBeta`** parameter (default: 0.8) influences how evidence
accumulates. When a z-score exceeds the deadband, evidence is updated as:

```text
evidence = 1 - exp(-EvidenceBeta × (z - zDeadband))
```

A higher `EvidenceBeta` would amplify each contribution (making evidence build
up faster), whereas a lower value makes the accumulation more gradual.

Crucially, IMM uses a **deadband** around zero to avoid integrating noise into
the evidence. The config fields **`ZDeadbandRecent`** (default: 1.25) and *
*`ZDeadbandEntire`** (default: 0.01) define z-score thresholds below which the
algorithm will treat the signal as essentially zero. This means if the recent
slope is only, say, 0.5σ above baseline and `ZDeadbandRecent` is 1.25, IMM adds
nothing to evidence – it's considered within normal "bounce" range. Only when
the z-score exceeds the deadband does IMM start accumulating evidence. The
deadband creates a **[hysteresis](https://en.wikipedia.org/wiki/Hysteresis)**:
minor fluctuations cause evidence to decay (or remain at zero) rather than
flip-flopping or slowly ratcheting up on noise.

Additionally, IMM caps how fast evidence can rise per update:

- **`MaxRiseRecent`** (default: 0.05) – Recent evidence can only increase by 5%
  per window
- **`MaxRiseEntire`** (default: 0.15) – Entire evidence can increase by 15% per
  window

In summary, IMM's evidence accumulator acts like a leaky integrator: it
*integrates positive indications* of a leak (significant z-scores) and
*exponentially forgets* indications over time. The half-life parameters control
the forgetting rate, **preventing noise amplification** by smoothing out
short-term spikes.

## Final Leak Scoring (Saturating Exponential Mapping)

After updating the internal evidence scores for both recent and entire windows,
IMM produces a final **leak risk score** between 0 and 10. This is done in two
steps:

1. **Combine evidence from both windows** using weighted sum:

   ```text
   finalEvidence = RecentMixWeight × recentEvidence + EntireMixWeight × entireEvidence
   ```

    - **`RecentMixWeight`** (default: 0.05 = 5%) – Recent contribution
    - **`EntireMixWeight`** (default: 0.95 = 95%) – Entire contribution

   This means the long-term entire evidence dominates (95%), while recent
   evidence provides quick reaction (5%).

2. **Map to 0-10 scale** using a saturating exponential function:

   ```text
   score = (1 - exp(-KScore × finalEvidence)) × 10
   ```

   where **`KScore`** (default: 2.6) controls how quickly the score saturates.

This formula yields a curve that starts at 0 when evidence is 0 (no sign of
leak), and asymptotically approaches 10 as evidence grows large. The exponential
ensures diminishing returns: the first units of evidence cause the score to rise
rapidly, but additional evidence eventually saturates the score toward 10. The *
*saturating exponential** is a smooth way to compress an unbounded evidence sum
into a 0–10 range.

By tuning `KScore`, one can adjust how quickly the score saturates as evidence
accumulates. A higher value means the score will approach 10 with less
evidence (a more aggressive alarm), whereas a smaller value requires more
accumulated evidence to get the same score (a conservative alarm).

The result is the **IMM output score**:

- **0.0** – No leak risk detected
- **1-3** – Low evidence of a leak
- **4-7** – Moderate evidence of a leak
- **8-10** – Very strong evidence of a memory leak trend

This score can be reported or used to trigger alerts in the EVE system.

## Configuration Parameters and Their Effects

The behavior of IMM can be adjusted via the `Config` struct in code, which
contains various fields controlling thresholds and weights. Key fields include:

### Time Windows and Cadence

- **`AnalysisWindow`** (default: 10 minutes) – How far back the "recent"
  analysis looks. Shorter windows detect leaks faster but may have more false
  positives.

- **`ProbingInterval`** (default: 5 seconds) – How often memory metrics are
  collected. Determines the granularity of time series data.

- **`SlopeThresholdBps`** (default: 208 bytes/second) – Absolute slope floor.
  This is the minimum growth rate that must be exceeded before IMM considers any
  trend significant. For instance, if `SlopeThresholdBps = 208`, then even if
  usage is trending up, IMM will treat slopes below 208 Bps as essentially zero
  growth.

- **`SmoothingProbeCount`** (default: 60) – How many probes to use for median
  filtering. Higher values = smoother data but slower to react to real changes.

- **`EntireUpdateEveryWin`** (default: 2) – Run entire analysis once per N
  analysis windows. E.g., if `AnalysisWindow=10min` and
  `EntireUpdateEveryWin=2`, run entire every 20 minutes.

- **`EntireMedianCap`** (default: 241) – Limits median smoothing window for
  entire analysis. Entire uses ~5x recent smoothing but capped at this value.

- **`EntireHoldTTLWindows`** (default: 12.0) – How long to trust entire results
  before starting to decay them (in number of analysis windows).

- **`EntireStaleHalfLife`** (default: 32.0) – Controls decay rate when entire
  becomes stale.

### Evidence Gates and Sensitivity

- **`SigmaFactorRecent`** (default: 12.0) – Multiplier for robust sigma in
  recent slope significance. Higher values mean IMM is more conservative (
  requiring a more extreme deviation from historical trends), whereas lower
  values make it more sensitive.

- **`SigmaFactorEntire`** (default: 2.0) – Similar to recent but for entire
  analysis. Lower because entire uses more smoothing.

- **`ZDeadbandRecent`** (default: 1.25) – Deadband threshold for z-score in
  recent analysis. Z-scores below this value contribute zero to the leak
  evidence.

- **`ZDeadbandEntire`** (default: 0.01) – Deadband for entire analysis. Much
  lower because even small sustained growth over entire history is significant.

- **`MinR2Gate`** (default: 0.40) – Minimum R² (Pearson correlation squared) to
  trust a trend. Only trends with R² >= this OR Spearman >= `MinSpearmanGate`
  are considered valid.

- **`MinSpearmanGate`** (default: 0.50) – Minimum Spearman rank correlation to
  trust a trend.

- **`EvidenceBeta`** (default: 0.8) – Evidence accumulation rate. Higher values
  make the algorithm quicker to escalate the score for a given trend.

- **`MaxRiseRecent`** (default: 0.05) – Limits how fast recent evidence can
  increase per window (5% max).

- **`MaxRiseEntire`** (default: 0.15) – Limits how fast entire evidence can
  increase per window (15% max).

### Final Score Combiner

- **`RecentMixWeight`** (default: 0.05) – How much recent evidence contributes
  to final score (5%).

- **`EntireMixWeight`** (default: 0.95) – How much entire evidence contributes
  to final score (95%).

- **`KScore`** (default: 2.6) – Controls final score saturation curve.

### Per-Metric Weights

- **`Weights`** – Relative importance of each metric (heap, rss). Default:
  heap=1.0, rss=0.8.

Together, these Config fields let engineers calibrate IMM's sensitivity. For
example:

- To catch even slight memory leaks early, one might lower `SlopeThresholdBps`
  and `SigmaFactorRecent`, and perhaps lower `ZDeadbandRecent` and increase
  `EvidenceBeta` – making IMM trigger on smaller upward trends and accumulate
  evidence faster. However, this raises the risk of false alarms from benign
  usage growth.

- To be very sure before alerting, one could raise `SigmaFactorRecent` (require
  more sigma deviation) and raise `ZDeadbandRecent` (ignore small z), and maybe
  lengthen half-lives so that only a prolonged consistent rise triggers a high
  score.

IMM's default configuration is chosen to strike a balance between false
positives and false negatives based on observed system behavior. But because
memory usage patterns can differ widely between workloads, these parameters are
exposed for tuning.

## Noise Mitigation and Stability Features

The IMM engine is specifically designed to **avoid noise amplification** – it
shouldn't raise the alarm due to random jitter or one-off events:

- **Slope gating** – By requiring the recent slope to exceed both an absolute
  threshold (`SlopeThresholdBps`) and a relative threshold (
  `SigmaFactorRecent` × σ) before contributing evidence, IMM gates out small
  wiggles.

- **Correlation checks** – Using R² and Spearman's ρ as secondary conditions
  means that even if memory is drifting upward, if the pattern is erratic (low
  R²/ρ) IMM can choose to hold off.

- **Deadband around zero** – The `ZDeadband` parameters ensure that evidence
  isn't nudged upward by every tiny positive z-score.

- **Exponential decay of evidence** – If a leak trend stops (e.g., memory
  flattens out or the process restarts), IMM's evidence will exponentially decay
  over time. The half-life tuning ensures that after a certain period of normal
  behavior, the past evidence is largely forgotten and the score falls back
  down.

- **Capping rise rate** – The `MaxRiseRecent` and `MaxRiseEntire` parameters
  limit how much a single interval's data can change the evidence. Multiple
  consistent steps are needed to get to a full alarm.

- **Hysteresis via EWMA** – The dual-window evidence accumulation (fast vs slow)
  acts like hysteresis, requiring continuous confirmation of the trend. If the
  trend was a fluke, the fast evidence will decay quickly and the slow component
  never fully ramps up.

Thanks to these measures, IMM avoids amplifying random noise. A momentary jump
in memory might trip one part of the logic, but other checks (low R², median
filter smoothing, etc.) will prevent the score from spiking. Only a genuine
pattern of continuous growth (memory usage rising steadily over multiple
samples) will surmount all the barriers and accumulate enough evidence to
produce a high score indicating a likely memory leak.

## imm-experiment: Testing IMM on Real Data

To aid in tuning and validating the IMM algorithm, the EVE project provides a
utility called **imm-experiment** (located in
`pkg/pillar/cmd/watcher/cmd/imm-experiment`). This is a test harness that allows
engineers to run the IMM logic offline against recorded memory usage traces. One
can feed in stored time-series CSV data (for example, memory usage logs from a
device that experienced a leak, or from a normal device as a control) and
simulate how IMM would score it with various configuration settings.

The imm-experiment tool lets you specify an IMM Config and then processes the
trace data through the IMM algorithm (using the same core functions like `Step`
and the `IMMState` logic). It produces output showing how the internal metrics (
slopes, z-scores, evidence, final score, etc.) evolve over time for that trace.

By using imm-experiment, engineers can answer questions like:

- *Does the current configuration detect the known leak in this trace quickly
  enough, and does the score clearly ramp up?*
- *Does the algorithm remain quiet (low score) on this normal workload trace
  without leaks?*
- *What is the impact of adjusting `SigmaFactorRecent` or `ZDeadbandRecent` on
  false positives or detection latency in these scenarios?*

This experimentation is invaluable for refining the Config defaults. For
example, if imm-experiment shows that a certain bursty but harmless workload
always triggers a medium score, one might raise the deadband or sigma factor
until that trace yields low scores (improving specificity). Or if a known slow
leak only gives a late warning, one might increase sensitivity (higher
`EvidenceBeta` or lower thresholds) until imm-experiment demonstrates earlier
detection.

In summary, imm-experiment functions as a "replay" environment to test IMM
internals against real data, without having to deploy new code to a device. It
provides confidence that IMM's parameters are tuned correctly and helps
illustrate how the algorithm reacts step-by-step.

## Implementation Overview

IMM's implementation (in types like `IMMState`, `Probe`, `Config` and the `Step`
update method) embodies the above logic. At each time step, a new memory
measurement (from an `Input` struct containing usage info) is fed into
`IMMState.Step()`. The algorithm then:

1. **Updates the windows** – Manages ring buffer, dropping oldest data and
   adding newest for recent and entire windows.

2. **Applies median filtering** – Smooths the recent sequence to remove noise
   spikes.

3. **Computes Theil-Sen slopes** – For recent and entire windows, calculating
   robust trend lines.

4. **Calculates R² and Spearman ρ** – For the recent window's fit quality.

5. **Estimates baseline σ** – From the entire window using percentile-based
   robust statistics.

6. **Determines z-score** – How far the recent slope is above baseline, in σ
   units.

7. **Checks thresholds** – Slope must exceed `SlopeThresholdBps` and z must
   exceed `SigmaFactorRecent` and `ZDeadband` criteria, plus require decent
   R²/ρ.

8. **Updates evidence** – If above thresholds, converts the z-score (minus
   deadband) into an evidence increment (scaled by `EvidenceBeta`) and adds to
   the EWMA evidence accumulators. If below threshold, evidence simply decays
   this round.

9. **Applies decay** – Multiplies existing evidence by the EWMA decay factor for
   one interval (implementing the half-life).

10. **Caps/limits** – Ensures evidence doesn't change too abruptly using
    `MaxRiseRecent` and `MaxRiseEntire`.

11. **Computes final score** – Plugs the current evidence into the saturating
    exponential function to get a 0–10 score.

12. **Outputs the score** – Returns a `Probe` result struct containing current
    slope, R², ρ, z-score, evidence values, and final score.

Through these steps, IMM continuously monitors memory usage in a robust manner.
Each component contributes to reliability:

- The **Theil-Sen slope** focuses on the core trend (robustly ignoring outliers)
- **R² and Spearman ρ** validate that trend's consistency (linear and monotonic
  behavior)
- **Median filtering** and **robust sigma** calculations ensure noise doesn't
  mislead trend detection
- **Exponential decay (EWMA)** and **half-life** settings stabilize the response
  over time
- **Deadbands and thresholds** introduce deliberate insensitivity to small
  fluctuations
- The **saturating exponential score** mapping keeps the output bounded and
  interpretable

All these pieces work in concert to yield a smooth risk score that climbs from 0
to 10 only when a genuine, sustained memory leak is likely happening, and
otherwise stays low. By adjusting the Config knobs, one can tailor IMM to
different environments, trading off sensitivity vs. specificity as needed.

## Visualization Tool

The EVE project provides a Python-based visualization tool to analyze IMM's CSV
output and understand memory trends visually.

### Running Locally

**Prerequisites:**

```bash
cd pkg/debug/collect-info-extra-content/imm-visualizer
pip install -r requirements.txt
```

**Usage:**

```bash
python3 visualize.py path/to/memory_usage.csv
```

**Options:**

```bash
# Specify custom output file
python3 visualize.py path/to/memory_usage.csv -o custom_report.html

# Don't auto-open browser
python3 visualize.py path/to/memory_usage.csv --no-show
```

### Running from collect-info Archive

After extracting a `collect-info` archive:

```bash
tar -xzf collect-info-TIMESTAMP.tar.gz
cd collect-info-TIMESTAMP/
./collect-info.sh --mem-usage-visualize
```

This will list available memory usage CSV files, prompt you to select one,
download dependencies if needed, and generate an interactive HTML report.

## Profiling

To analyze IMM performance, build EVE with profiling enabled:

```bash
IMM_PROFILING=1 make eve
```

This enables profiling instrumentation that writes timing data to
`/persist/memory-monitor/output/imm-profile.dat`.

### Analyzing Profile Data

Use the **`immprof_plot.py`** tool:

```bash
cd tools
python3 immprof_plot.py -i ../pkg/memory-monitor/results/imm-profile.dat
```

The tool generates an interactive HTML report showing time spent in each
operation and performance bottlenecks.

## Testing with Artificial Leaks

To verify IMM detection capabilities, build EVE with an artificial memory leak:

```bash
ARTIFICIAL_LEAK=1 make eve
```

This enables a controlled leak (2KB every 10 seconds) that provides a
predictable pattern for testing. The IMM should detect the trend within minutes
and gradually increase the score toward 8-10.

**Warning:** Do not enable artificial leaks in production builds!
