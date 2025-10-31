#!/usr/bin/env python3
import argparse
from typing import Dict

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sklearn.linear_model import LinearRegression


def is_mem_metric(name: str) -> bool:
    base = {"heap", "rss"}
    return (name in base) or name.endswith("_bytes") or name.endswith(":bytes")


def to_mb(series: pd.Series) -> pd.Series:
    return series / (1024.0 * 1024.0)


def main():
    parser = argparse.ArgumentParser(
        description="Memory monitor visualizer: top=memory, bottom=evidence; heatmap on bottom row only."
    )
    parser.add_argument("filepath", help="CSV from the monitor (time, metrics, score, recent_feature, entire_feature, s_recent:*, s_entire:*)")
    parser.add_argument("-o", "--output", default="memory_usage_with_score.html", help="Output HTML path")
    parser.add_argument("--no-show", action="store_true", help="Do not open a browser window")
    args = parser.parse_args()

    # Load
    df = pd.read_csv(args.filepath, parse_dates=["time"])
    if df.empty:
        raise SystemExit("CSV is empty")

    # Identify columns
    base_cols = {"time", "score", "recent_feature", "entire_feature"}
    s_recent_cols = [c for c in df.columns if c.startswith("s_recent:")]
    s_entire_cols = [c for c in df.columns if c.startswith("s_entire:")]
    metric_cols = [c for c in df.columns if c not in base_cols and not c.startswith("s_recent:") and not c.startswith("s_entire:")]

    # Select memory metrics (bytes to MB)
    mem_cols = [c for c in metric_cols if is_mem_metric(c)]
    if not mem_cols:
        mem_cols = [c for c in metric_cols if pd.api.types.is_numeric_dtype(df[c])][:2]

    mb_map: Dict[str, str] = {}
    for m in mem_cols:
        mb = f"{m}_mb"
        df[mb] = to_mb(df[m]) if is_mem_metric(m) else df[m].astype(float)
        mb_map[m] = mb

    # Smoothing windows (tweak as needed)
    small_w = 12 * 5
    large_w = 24 * 5

    # Medians & big-window fits for first two memory metrics
    mem_for_median = mem_cols[:2]
    med_small_cols, med_large_cols = {}, {}
    fits: Dict[str, pd.Series] = {}
    df_huge = None

    for m in mem_for_median:
        mb = mb_map[m]
        ms, ml = f"{mb}_med", f"{mb}_med_lg"
        df[ms] = df[mb].rolling(window=small_w, center=True).median()
        df[ml] = df[mb].rolling(window=large_w, center=True).median()
        med_small_cols[m], med_large_cols[m] = ms, ml

    needed = [v for v in med_large_cols.values() if v in df.columns]
    if needed:
        df_huge = df.dropna(subset=needed)
        if not df_huge.empty:
            for m in mem_for_median:
                ml = med_large_cols.get(m)
                if not ml:
                    continue
                X = df_huge.index.values.reshape(-1, 1)
                y = df_huge[ml].values.reshape(-1, 1)
                model = LinearRegression().fit(X, y)
                y_fit = model.predict(X).flatten()
                fits[m] = pd.Series(y_fit, index=df_huge.index)
                print(f"{m} (lg) slope: {model.coef_[0][0]:.6f} units/index-step")

    # Figure: two rows, shared X
    fig = make_subplots(
        rows=2, cols=1, shared_xaxes=True,
        row_heights=[0.62, 0.38],
        specs=[[{"secondary_y": False}], [{"secondary_y": False}]],
        vertical_spacing=0.08,
        subplot_titles=("Memory (MB)", "Evidence / Features (0..1+)")
    )

    # Colors (simple, consistent)
    COLOR_HEAP = "#2ca02c"
    COLOR_RSS = "#d62728"
    COLOR_HEAP_MED = "#98df8a"
    COLOR_RSS_MED = "#ff9896"
    COLOR_FIT = "#7f7f7f"
    COLOR_RECENT_FEAT = "#1f77b4"
    COLOR_ENTIRE_FEAT = "#ff7f0e"

    # Heatmaps (bottom row only) — no legend entries
    if "score" not in df.columns:
        raise SystemExit("CSV must include a 'score' column")

    z_score = [df["score"].tolist(), df["score"].tolist()]
    fig.add_trace(go.Heatmap(
        x=df["time"], y=[0.0, 1.0], z=z_score,
        colorscale=[[0.0, "rgba(0,255,0,0.08)"], [0.5, "rgba(255,255,0,0.45)"], [1.0, "rgba(255,0,0,0.80)"]],
        zmin=0, zmax=10, opacity=1.0,
        showscale=True, showlegend=False,
        colorbar=dict(title="Leak Score", x=1.02, thickness=16, tick0=0, dtick=1.0),
        hovertemplate="Leak Score: %{z:.3f}<extra></extra>",
        name="Leak Score (score)",
        visible=True,
    ), row=2, col=1)

    # Top row: memory (legend group "memory")
    first_memory = True
    for m in mem_cols:
        mb = mb_map[m]
        color = COLOR_HEAP if m == "heap" else COLOR_RSS
        fig.add_trace(go.Scatter(
            x=df["time"], y=df[mb],
            mode="lines", name=f"{m.upper()} (MB)",
            line=dict(width=1.4, color=color),
            hovertemplate=f"{m.upper()} (MB): %{{y:.3f}}<extra></extra>",
            legendgroup="memory",
            legendgrouptitle_text="Memory (MB)" if first_memory else None,
            showlegend=True,
        ), row=1, col=1)
        first_memory = False

    # Medians (small), dashed, grouped under "memory"
    for m in mem_for_median:
        ms = med_small_cols.get(m)
        if not ms:
            continue
        color = COLOR_HEAP_MED if m == "heap" else COLOR_RSS_MED
        fig.add_trace(go.Scatter(
            x=df["time"], y=df[ms],
            mode="lines", name=f"{m.upper()} — median (short)",
            line=dict(width=1.1, dash="dot", color=color),
            hoverinfo="skip",
            legendgroup="memory",
            showlegend=True,
        ), row=1, col=1)

    # Fits (hidden by default), grouped under "memory"
    if df_huge is not None and not df_huge.empty:
        for m, fit_series in fits.items():
            fig.add_trace(go.Scatter(
                x=df_huge.loc[fit_series.index, "time"], y=fit_series.values,
                mode="lines", name=f"{m.upper()} — fit (large window)",
                line=dict(width=1.0, dash="dash", color=COLOR_FIT),
                hoverinfo="skip",
                legendgroup="memory",
                showlegend=True,
                visible=False,
            ), row=1, col=1)

    # Bottom row: features (legend group "evidence")
    first_evidence = True
    if "recent_feature" in df.columns:
        fig.add_trace(go.Scatter(
            x=df["time"], y=df["recent_feature"], mode="lines", name="recent_feature",
            line=dict(width=2.0, color=COLOR_RECENT_FEAT),
            hovertemplate="recent_feature: %{y:.3f}<extra></extra>",
            legendgroup="evidence",
            legendgrouptitle_text="Evidence / Features" if first_evidence else None,
            showlegend=True,
            visible=True,
        ), row=2, col=1)
        first_evidence = False
    if "entire_feature" in df.columns:
        fig.add_trace(go.Scatter(
            x=df["time"], y=df["entire_feature"], mode="lines", name="entire_feature",
            line=dict(width=2.0, color=COLOR_ENTIRE_FEAT),
            hovertemplate="entire_feature: %{y:.3f}<extra></extra>",
            legendgroup="evidence",
            legendgrouptitle_text="Evidence / Features" if first_evidence else None,
            showlegend=True,
            visible=True,
        ), row=2, col=1)
        first_evidence = False

    # Per-metric EWMAs (hidden by default; no legend entries to avoid clutter)
    for c in s_recent_cols:
        metric_name = c.split("s_recent:", 1)[1]
        fig.add_trace(go.Scatter(
            x=df["time"], y=df[c], mode="lines",
            name=f"recent:{metric_name}", line=dict(width=1.0),
            hovertemplate=f"recent:{metric_name}: "+"%{y:.3f}<extra></extra>",
            showlegend=False, visible=False,
        ), row=2, col=1)
    for c in s_entire_cols:
        metric_name = c.split("s_entire:", 1)[1]
        fig.add_trace(go.Scatter(
            x=df["time"], y=df[c], mode="lines",
            name=f"entire:{metric_name}", line=dict(width=1.0),
            hovertemplate=f"entire:{metric_name}: "+"%{y:.3f}<extra></extra>",
            showlegend=False, visible=False,
        ), row=2, col=1)

    # Layout
    fig.update_layout(
        title="Memory Usage Over Time (heatmap only on evidence row)",
        hovermode="x unified",
        margin=dict(t=90, r=130, b=70, l=80),
        height=740,
        legend=dict(
            orientation="h",
            x=0.0, y=1.18, xanchor="left", yanchor="top",
            traceorder="grouped",
            bgcolor="rgba(255,255,255,0.6)",
            bordercolor="rgba(0,0,0,0.1)",
            borderwidth=1
        ),
        legend_tracegroupgap=20,
    )
    fig.update_xaxes(title_text="Time", row=2, col=1, showspikes=True, spikemode="across", spikesnap="cursor", spikethickness=1)
    fig.update_yaxes(title_text="Memory (MB)", row=1, col=1, rangemode="tozero", showspikes=True, spikethickness=1)
    fig.update_yaxes(title_text="Evidence / Features", row=2, col=1, rangemode="tozero", showspikes=True, spikethickness=1)

    # Range slider (thin) on bottom row; add an annotation so it’s clearly a slider.
    fig.update_xaxes(rangeslider_visible=True, row=2, col=1)
    fig.update_layout(
        xaxis2_rangeslider_thickness=0.05,
        xaxis2_rangeselector=dict(
            buttons=[
                dict(count=15, label="15m", step="minute", stepmode="backward"),
                dict(count=1, label="1h", step="hour", stepmode="backward"),
                dict(step="all")
            ]
        ),
        annotations=[
            dict(
                text="Range slider: drag handles to zoom",
                xref="paper", yref="paper",
                x=0.5, y=0.04, showarrow=False,
                font=dict(size=11, color="rgba(0,0,0,0.65)")
            )
        ]
    )

    # Visibility presets (Overview / Details)
    total = len(fig.data)
    idx_heat_score = 0
    idx_first_after_heat = 1

    n_mem = len(mem_cols)
    n_meds = len(mem_for_median)
    n_fits = len(fits)
    idx_features_start = idx_first_after_heat + n_mem + n_meds + n_fits
    n_features = (1 if "recent_feature" in df.columns else 0) + (1 if "entire_feature" in df.columns else 0)
    idx_evidences_start = idx_features_start + n_features
    n_evidences = len(s_recent_cols) + len(s_entire_cols)

    # overview: heat(score)+memory+medians+features
    vis_overview = [False] * total
    vis_overview[idx_heat_score] = True
    for i in range(idx_first_after_heat, idx_first_after_heat + n_mem + n_meds):
        vis_overview[i] = True
    for i in range(idx_features_start, idx_features_start + n_features):
        vis_overview[i] = True

    # details: overview + fits + per-metric evidences
    vis_details = vis_overview[:]
    for i in range(idx_first_after_heat + n_mem + n_meds, idx_first_after_heat + n_mem + n_meds + n_fits):
        vis_details[i] = True
    for i in range(idx_evidences_start, idx_evidences_start + n_evidences):
        vis_details[i] = True

    fig.update_layout(
        updatemenus=[
            dict(
                type="dropdown", direction="down", showactive=True,
                x=0.5, y=1.25, xanchor="center", yanchor="top",
                buttons=[
                    dict(label="Overview", method="update", args=[{"visible": vis_overview}]),
                    dict(label="Details",  method="update", args=[{"visible": vis_details}]),
                ]
            )
        ]
    )

    # Save & show
    fig.write_html(args.output, include_plotlyjs="cdn", full_html=True)
    if not args.no_show:
        fig.show()


if __name__ == "__main__":
    main()
