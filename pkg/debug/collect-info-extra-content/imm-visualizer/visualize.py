#!/usr/bin/env python3
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Memory monitor visualizer for IMM data."""

import argparse
from typing import Dict

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sklearn.linear_model import LinearRegression


def is_mem_metric(name: str) -> bool:
    """Check if a metric name represents a memory metric."""
    base = {"heap", "rss"}
    return (name in base) or name.endswith("_bytes") or name.endswith(":bytes")


def to_mb(series: pd.Series) -> pd.Series:
    """Convert bytes to megabytes."""
    return series / (1024.0 * 1024.0)


def _parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Memory monitor visualizer: top=memory, bottom=evidence; "
            "heatmap on bottom row only."
        )
    )
    parser.add_argument(
        "filepath",
        help=(
            "CSV from the monitor (time, metrics, score, recent_feature, "
            "entire_feature, s_recent:*, s_entire:*)"
        )
    )
    parser.add_argument(
        "-o", "--output",
        default="memory_usage_with_score.html",
        help="Output HTML path"
    )
    parser.add_argument("--no-show", action="store_true", help="Do not open a browser window")
    return parser.parse_args()


def _identify_columns(dataframe):
    """Identify column types from dataframe."""
    base_cols = {"time", "score", "recent_feature", "entire_feature"}
    s_recent_cols = [c for c in dataframe.columns if c.startswith("s_recent:")]
    s_entire_cols = [c for c in dataframe.columns if c.startswith("s_entire:")]
    metric_cols = [
        c for c in dataframe.columns
        if c not in base_cols
        and not c.startswith("s_recent:")
        and not c.startswith("s_entire:")
    ]
    return s_recent_cols, s_entire_cols, metric_cols


def _select_memory_metrics(dataframe, metric_cols):
    """Select memory metrics and convert to MB."""
    mem_cols = [c for c in metric_cols if is_mem_metric(c)]
    if not mem_cols:
        mem_cols = [c for c in metric_cols if pd.api.types.is_numeric_dtype(dataframe[c])][:2]

    mb_map: Dict[str, str] = {}
    for metric in mem_cols:
        mb_col = f"{metric}_mb"
        if is_mem_metric(metric):
            dataframe[mb_col] = to_mb(dataframe[metric])
        else:
            dataframe[mb_col] = dataframe[metric].astype(float)
        mb_map[metric] = mb_col

    return mem_cols, mb_map


def _compute_medians_and_fits(dataframe, mem_cols, mb_map,
                              small_window, large_window):
    """Compute rolling medians and linear fits for memory metrics."""
    # pylint: disable=too-many-locals
    mem_for_median = mem_cols[:2]
    med_small_cols = {}
    med_large_cols = {}
    fits: Dict[str, pd.Series] = {}
    df_huge = None

    for metric in mem_for_median:
        mb_col = mb_map[metric]
        med_small, med_large = f"{mb_col}_med", f"{mb_col}_med_lg"
        dataframe[med_small] = dataframe[mb_col].rolling(
            window=small_window, center=True).median()
        dataframe[med_large] = dataframe[mb_col].rolling(
            window=large_window, center=True).median()
        med_small_cols[metric] = med_small
        med_large_cols[metric] = med_large

    needed = [v for v in med_large_cols.values() if v in dataframe.columns]
    if needed:
        df_huge = dataframe.dropna(subset=needed)
        if not df_huge.empty:
            for metric in mem_for_median:
                med_large = med_large_cols.get(metric)
                if not med_large:
                    continue
                x_values = df_huge.index.values.reshape(-1, 1)
                y_values = df_huge[med_large].values.reshape(-1, 1)
                model = LinearRegression().fit(x_values, y_values)
                y_fit = model.predict(x_values).flatten()
                fits[metric] = pd.Series(y_fit, index=df_huge.index)
                print(
                    f"{metric} (lg) slope: "
                    f"{model.coef_[0][0]:.6f} units/index-step"
                )

    return mem_for_median, med_small_cols, fits, df_huge


def main():
    """Main function to generate memory visualization from CSV data."""
    # pylint: disable=too-many-locals
    args = _parse_arguments()

    # Load
    dataframe = pd.read_csv(args.filepath, parse_dates=["time"])
    if dataframe.empty:
        raise SystemExit("CSV is empty")

    # Identify columns
    s_recent_cols, s_entire_cols, metric_cols = _identify_columns(dataframe)

    # Select memory metrics (bytes to MB)
    mem_cols, mb_map = _select_memory_metrics(dataframe, metric_cols)

    # Smoothing windows (tweak as needed)
    small_window = 12 * 5
    large_window = 24 * 5

    # Medians & big-window fits for first two memory metrics
    mem_for_median, med_small_cols, fits, df_huge = _compute_medians_and_fits(
        dataframe, mem_cols, mb_map, small_window, large_window
    )

    # Create figure
    fig = _create_figure(dataframe, mem_cols, mb_map, mem_for_median, med_small_cols,
                         fits, df_huge, s_recent_cols, s_entire_cols)

    # Configure layout and save
    _configure_layout(fig, dataframe, s_recent_cols, s_entire_cols, mem_cols,
                      mem_for_median, fits)

    # Save & show
    fig.write_html(args.output, include_plotlyjs="cdn", full_html=True)
    if not args.no_show:
        fig.show()


def _add_heatmap(fig, dataframe):
    """Add heatmap trace to figure."""
    if "score" not in dataframe.columns:
        raise SystemExit("CSV must include a 'score' column")

    z_score = [dataframe["score"].tolist(), dataframe["score"].tolist()]
    fig.add_trace(go.Heatmap(
        x=dataframe["time"], y=[0.0, 1.0], z=z_score,
        colorscale=[
            [0.0, "rgba(0,255,0,0.08)"],
            [0.5, "rgba(255,255,0,0.45)"],
            [1.0, "rgba(255,0,0,0.80)"]
        ],
        zmin=0, zmax=10, opacity=1.0,
        showscale=True, showlegend=False,
        colorbar={
            "title": "Leak Score", "x": 1.02, "thickness": 16, "tick0": 0, "dtick": 1.0
        },
        hovertemplate="Leak Score: %{z:.3f}<extra></extra>",
        name="Leak Score (score)",
        visible=True,
    ), row=2, col=1)


def _add_memory_traces(fig, dataframe, mem_cols, mb_map):
    """Add memory traces to figure."""
    color_heap = "#2ca02c"
    color_rss = "#d62728"

    first_memory = True
    for metric in mem_cols:
        mb_col = mb_map[metric]
        color = color_heap if metric == "heap" else color_rss
        fig.add_trace(go.Scatter(
            x=dataframe["time"], y=dataframe[mb_col],
            mode="lines", name=f"{metric.upper()} (MB)",
            line={"width": 1.4, "color": color},
            hovertemplate=f"{metric.upper()} (MB): %{{y:.3f}}<extra></extra>",
            legendgroup="memory",
            legendgrouptitle_text="Memory (MB)" if first_memory else None,
            showlegend=True,
        ), row=1, col=1)
        first_memory = False


def _add_median_traces(fig, dataframe, mem_for_median, med_small_cols):
    """Add median traces to figure."""
    color_heap_med = "#98df8a"
    color_rss_med = "#ff9896"

    for metric in mem_for_median:
        med_small = med_small_cols.get(metric)
        if not med_small:
            continue
        color = color_heap_med if metric == "heap" else color_rss_med
        fig.add_trace(go.Scatter(
            x=dataframe["time"], y=dataframe[med_small],
            mode="lines", name=f"{metric.upper()} — median (short)",
            line={"width": 1.1, "dash": "dot", "color": color},
            hoverinfo="skip",
            legendgroup="memory",
            showlegend=True,
        ), row=1, col=1)


def _add_fit_traces(fig, df_huge, fits):
    """Add fit traces to figure."""
    color_fit = "#7f7f7f"

    if df_huge is not None and not df_huge.empty:
        for metric, fit_series in fits.items():
            fig.add_trace(go.Scatter(
                x=df_huge.loc[fit_series.index, "time"], y=fit_series.values,
                mode="lines", name=f"{metric.upper()} — fit (large window)",
                line={"width": 1.0, "dash": "dash", "color": color_fit},
                hoverinfo="skip",
                legendgroup="memory",
                showlegend=True,
                visible=False,
            ), row=1, col=1)


def _add_feature_traces(fig, dataframe):
    """Add feature traces to figure."""
    color_recent_feat = "#1f77b4"
    color_entire_feat = "#ff7f0e"

    first_evidence = True
    if "recent_feature" in dataframe.columns:
        fig.add_trace(go.Scatter(
            x=dataframe["time"], y=dataframe["recent_feature"], mode="lines", name="recent_feature",
            line={"width": 2.0, "color": color_recent_feat},
            hovertemplate="recent_feature: %{y:.3f}<extra></extra>",
            legendgroup="evidence",
            legendgrouptitle_text="Evidence / Features" if first_evidence else None,
            showlegend=True,
            visible=True,
        ), row=2, col=1)
        first_evidence = False
    if "entire_feature" in dataframe.columns:
        fig.add_trace(go.Scatter(
            x=dataframe["time"], y=dataframe["entire_feature"], mode="lines", name="entire_feature",
            line={"width": 2.0, "color": color_entire_feat},
            hovertemplate="entire_feature: %{y:.3f}<extra></extra>",
            legendgroup="evidence",
            legendgrouptitle_text="Evidence / Features" if first_evidence else None,
            showlegend=True,
            visible=True,
        ), row=2, col=1)


def _add_ewma_traces(fig, dataframe, s_recent_cols, s_entire_cols):
    """Add EWMA traces to figure."""
    for col in s_recent_cols:
        metric_name = col.split("s_recent:", 1)[1]
        fig.add_trace(go.Scatter(
            x=dataframe["time"], y=dataframe[col], mode="lines",
            name=f"recent:{metric_name}", line={"width": 1.0},
            hovertemplate=f"recent:{metric_name}: "+"%{y:.3f}<extra></extra>",
            showlegend=False, visible=False,
        ), row=2, col=1)
    for col in s_entire_cols:
        metric_name = col.split("s_entire:", 1)[1]
        fig.add_trace(go.Scatter(
            x=dataframe["time"], y=dataframe[col], mode="lines",
            name=f"entire:{metric_name}", line={"width": 1.0},
            hovertemplate=f"entire:{metric_name}: "+"%{y:.3f}<extra></extra>",
            showlegend=False, visible=False,
        ), row=2, col=1)


def _create_figure(dataframe, mem_cols, mb_map, mem_for_median, med_small_cols,
                   fits, df_huge, s_recent_cols, s_entire_cols):
    # pylint: disable=too-many-arguments
    """Create the plotly figure with all traces."""
    # Figure: two rows, shared X
    fig = make_subplots(
        rows=2, cols=1, shared_xaxes=True,
        row_heights=[0.62, 0.38],
        specs=[[{"secondary_y": False}], [{"secondary_y": False}]],
        vertical_spacing=0.08,
        subplot_titles=("Memory (MB)", "Evidence / Features (0..1+)")
    )

    # Add all traces
    _add_heatmap(fig, dataframe)
    _add_memory_traces(fig, dataframe, mem_cols, mb_map)
    _add_median_traces(fig, dataframe, mem_for_median, med_small_cols)
    _add_fit_traces(fig, df_huge, fits)
    _add_feature_traces(fig, dataframe)
    _add_ewma_traces(fig, dataframe, s_recent_cols, s_entire_cols)

    return fig


def _configure_layout(fig, dataframe, s_recent_cols, s_entire_cols, mem_cols,
                      mem_for_median, fits):
    # pylint: disable=too-many-arguments
    """Configure figure layout and interactivity."""
    # Basic layout
    fig.update_layout(
        title="Memory Usage Over Time (heatmap only on evidence row)",
        hovermode="x unified",
        margin={"t": 90, "r": 130, "b": 70, "l": 80},
        height=740,
        legend={
            "orientation": "h",
            "x": 0.0, "y": 1.18, "xanchor": "left", "yanchor": "top",
            "traceorder": "grouped",
            "bgcolor": "rgba(255,255,255,0.6)",
            "bordercolor": "rgba(0,0,0,0.1)",
            "borderwidth": 1
        },
        legend_tracegroupgap=20,
    )
    fig.update_xaxes(
        title_text="Time", row=2, col=1, showspikes=True,
        spikemode="across", spikesnap="cursor", spikethickness=1
    )
    fig.update_yaxes(
        title_text="Memory (MB)", row=1, col=1, rangemode="tozero",
        showspikes=True, spikethickness=1
    )
    fig.update_yaxes(
        title_text="Evidence / Features", row=2, col=1,
        rangemode="tozero", showspikes=True, spikethickness=1
    )

    # Range slider
    fig.update_xaxes(rangeslider_visible=True, row=2, col=1)
    fig.update_layout(
        xaxis2_rangeslider_thickness=0.05,
        xaxis2_rangeselector={
            "buttons": [
                {
                    "count": 15, "label": "15m", "step": "minute",
                    "stepmode": "backward"
                },
                {
                    "count": 1, "label": "1h", "step": "hour",
                    "stepmode": "backward"
                },
                {"step": "all"}
            ]
        },
        annotations=[
            {
                "text": "Range slider: drag handles to zoom",
                "xref": "paper", "yref": "paper",
                "x": 0.5, "y": 0.04, "showarrow": False,
                "font": {"size": 11, "color": "rgba(0,0,0,0.65)"}
            }
        ]
    )

    # Visibility presets
    _add_visibility_presets(fig, dataframe, s_recent_cols, s_entire_cols, mem_cols,
                            mem_for_median, fits)


def _add_visibility_presets(fig, dataframe, s_recent_cols, s_entire_cols, mem_cols,
                            mem_for_median, fits):
    # pylint: disable=too-many-arguments,too-many-locals
    """Add visibility presets (Overview / Details) to figure."""
    total = len(fig.data)
    idx_heat_score = 0
    idx_first_after_heat = 1

    n_mem = len(mem_cols)
    n_meds = len(mem_for_median)
    n_fits = len(fits)
    idx_features_start = idx_first_after_heat + n_mem + n_meds + n_fits
    n_features = (
        (1 if "recent_feature" in dataframe.columns else 0)
        + (1 if "entire_feature" in dataframe.columns else 0)
    )
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
    for i in range(
        idx_first_after_heat + n_mem + n_meds,
        idx_first_after_heat + n_mem + n_meds + n_fits
    ):
        vis_details[i] = True
    for i in range(idx_evidences_start, idx_evidences_start + n_evidences):
        vis_details[i] = True

    fig.update_layout(
        updatemenus=[
            {
                "type": "dropdown", "direction": "down", "showactive": True,
                "x": 0.5, "y": 1.25, "xanchor": "center", "yanchor": "top",
                "buttons": [
                    {
                        "label": "Overview", "method": "update",
                        "args": [{"visible": vis_overview}]
                    },
                    {
                        "label": "Details",  "method": "update",
                        "args": [{"visible": vis_details}]
                    },
                ]
            }
        ]
    )


if __name__ == "__main__":
    main()
