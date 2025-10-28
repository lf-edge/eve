#!/usr/bin/env python3
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
immprof_plot.py — simple interactive plot of IMM profiling durations.

Default input: ../memory-monitor/results/imm-profile.dat
Each line is key=value fields, e.g.:
  ts=... start_ts=... end_ts=... gid=123 label=imm.step dur_ms=1.234
  depth=1 span=42 parent=41 file=engine.go line=123 func=...

Usage examples:
  # Open interactive HTML
  # (default: lines mode, auto-select top labels by total ms)
  ./immprof_plot.py

  # Save HTML for specific labels
  ./immprof_plot.py -o immprof.html -L imm.step,imm.entire.pass

  # Timeline mode (nested spans)
  ./immprof_plot.py --mode timeline
"""
from __future__ import annotations

import argparse
import math
import sys
import re
from dataclasses import dataclass
from typing import Dict, List, Iterable, Optional
from datetime import datetime, timedelta

import plotly.graph_objects as go
import plotly.express as px

DEFAULT_INPUT = "../memory-monitor/results/imm-profile.dat"
FALLBACK_INPUTS = [
    "../pkg/memory-monitor/results/imm-profile.dat",
    "/persist/memory-monitor/output/imm-profile.dat",
]

# Extract key=value pairs from each line (assumes file contains only immprof records)
_KV_RE = re.compile(r"(\w+)=([^\s]+)")


@dataclass
class Record:  # pylint: disable=too-many-instance-attributes
    """Profiling record with timing and metadata."""
    timestamp: datetime
    start_ts: datetime
    end_ts: datetime
    gid: int
    label: str
    dur_ms: float
    depth: int
    span: int
    parent: int
    file: str = ""
    line: int = 0
    func: str = ""


def parse_ts(val: str) -> datetime:
    """Parse timestamp string to datetime object."""
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    if "." in val:
        head, tail = val.split(".", 1)
        timezone = ""
        for sep in ["+", "-"]:
            if sep in tail[1:]:
                frac, rest = tail.split(sep, 1)
                timezone = sep + rest
                break
        else:
            frac = tail
        frac = (frac + "000000")[:6]
        val = f"{head}.{frac}{timezone}"
    return datetime.fromisoformat(val)


def parse_int(kvs: Dict[str, str], key: str, default: int = 0) -> int:
    """Parse integer from key-value dict with fallback."""
    try:
        return int(kvs.get(key, default))
    except (ValueError, TypeError):
        try:
            return int(float(kvs.get(key, default)))
        except (ValueError, TypeError):
            return default


def parse_float(kvs: Dict[str, str], key: str, default: float = float("nan")) -> float:
    """Parse float from key-value dict with fallback."""
    try:
        return float(kvs.get(key, default))
    except (ValueError, TypeError):
        return default


def parse_immprof_lines(lines: Iterable[str]) -> List[Record]:
    """Parse profiling lines into Record objects."""
    # pylint: disable=too-many-locals
    recs: List[Record] = []
    for raw in lines:
        stripped_line = raw.strip()
        if not stripped_line:
            continue
        kvs = dict(_KV_RE.findall(stripped_line))
        try:
            end_ts_s = kvs.get("ts") or kvs.get("end_ts") or ""
            end_ts = parse_ts(end_ts_s) if end_ts_s else None
            start_ts_s = kvs.get("start_ts", "")
            start_ts = parse_ts(start_ts_s) if start_ts_s else None
            label = kvs.get("label", "")
            dur_ms = parse_float(kvs, "dur_ms")
            gid = parse_int(kvs, "gid", 0)
            depth = parse_int(kvs, "depth", 0)
            span = parse_int(kvs, "span", 0)
            parent = parse_int(kvs, "parent", 0)
            file = kvs.get("file", "")
            line = parse_int(kvs, "line", 0)
            func = kvs.get("func", "")
            # Fallbacks if older format
            if end_ts is None:
                timestamp = parse_ts(kvs.get("ts", ""))
                end_ts = timestamp
            if start_ts is None and end_ts is not None and not math.isnan(dur_ms):
                start_ts = end_ts - timedelta(milliseconds=dur_ms)
            if not label or end_ts is None or start_ts is None or math.isnan(dur_ms):
                continue
            recs.append(Record(
                timestamp=end_ts, start_ts=start_ts, end_ts=end_ts, gid=gid, label=label,
                dur_ms=dur_ms, depth=depth, span=span, parent=parent,
                file=file, line=line, func=func,
            ))
        except (ValueError, KeyError):
            continue
    return recs


def group_by_label(recs: List[Record]) -> Dict[str, List[Record]]:
    """Group records by label."""
    groups: Dict[str, List[Record]] = {}
    for record in recs:
        groups.setdefault(record.label, []).append(record)
    for arr in groups.values():
        arr.sort(key=lambda rec: rec.timestamp)
    return groups


def totals_by_label(recs: List[Record]) -> Dict[str, float]:
    """Calculate total duration by label."""
    tot: Dict[str, float] = {}
    for record in recs:
        tot[record.label] = tot.get(record.label, 0.0) + record.dur_ms
    return tot


def select_labels_simple(recs: List[Record], include: Optional[List[str]], top: int) -> List[str]:
    """Select labels to display based on include list or top N."""
    if include:
        return include
    tot = totals_by_label(recs)
    labels = sorted(tot.keys(), key=lambda k: tot[k], reverse=True)
    return labels[:top]


def moving_avg(vals: List[float], window_size: int) -> List[float]:
    """Calculate moving average with given window size."""
    if window_size <= 1 or not vals:
        return vals
    window_size = min(window_size, len(vals))
    out: List[float] = []
    window_sum = sum(vals[:window_size])
    out.append(window_sum / window_size)
    for i in range(window_size, len(vals)):
        window_sum += vals[i] - vals[i - window_size]
        out.append(window_sum / window_size)
    return [out[0]] * (window_size - 1) + out


def plot_lines(
    recs: List[Record], labels: List[str], smooth: int,
    out: Optional[str], title: Optional[str]
) -> None:
    """Plot duration lines for selected labels."""
    if not labels:
        sys.stderr.write("no labels selected.\n")
        return
    groups = group_by_label(recs)
    fig = go.Figure()
    palette = [
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b",
        "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
    ]
    for idx, label in enumerate(labels):
        arr = groups.get(label, [])
        if not arr:
            continue
        x_values = [rec.timestamp for rec in arr]
        y_values = [rec.dur_ms for rec in arr]
        color = palette[idx % len(palette)]
        if smooth > 1:
            y_smoothed = moving_avg(y_values, smooth)
            fig.add_trace(go.Scatter(
                x=x_values, y=y_values, mode="lines", name=f"{label} (raw)",
                line={"width": 1.0, "color": color}, opacity=0.25,
                hovertemplate=f"{label} raw: %{{y:.3f}} ms<extra></extra>",
                showlegend=False
            ))
            fig.add_trace(go.Scatter(
                x=x_values, y=y_smoothed, mode="lines", name=label,
                line={"width": 1.8, "color": color},
                hovertemplate=f"{label}: %{{y:.3f}} ms<extra></extra>"
            ))
        else:
            fig.add_trace(go.Scatter(
                x=x_values, y=y_values, mode="lines+markers", name=label,
                line={"width": 1.6, "color": color}, marker={"size": 3},
                hovertemplate=f"{label}: %{{y:.3f}} ms<extra></extra>"
            ))
    fig.update_layout(
        title=title or "IMM profiling durations (ms)",
        xaxis_title="Time",
        yaxis_title="Duration (ms)",
        hovermode="x unified",
        template="plotly_white",
        margin={"t": 60, "r": 40, "b": 50, "l": 60},
        height=520,
    )
    fig.update_xaxes(
        rangeslider_visible=True, showspikes=True, spikemode="across",
        spikesnap="cursor", spikethickness=1
    )
    fig.update_yaxes(rangemode="tozero")
    if out:
        fig.write_html(out, include_plotlyjs="cdn", full_html=True)
        print(f"Wrote {out}")
    else:
        fig.show()


def plot_timeline(
    recs: List[Record], include: Optional[List[str]],
    out: Optional[str], title: Optional[str]
) -> None:
    """Plot timeline visualization of profiling spans."""
    if include:
        inc = set(include)
        recs = [rec for rec in recs if rec.label in inc]
    if not recs:
        sys.stderr.write("no matching records to plot.\n")
        return
    rows = []
    for record in recs:
        lane = f"G{record.gid} d{record.depth}"
        rows.append({
            "start": record.start_ts, "end": record.end_ts, "lane": lane,
            "label": record.label, "dur_ms": record.dur_ms, "gid": record.gid,
            "depth": record.depth, "span": record.span, "parent": record.parent,
            "file": record.file, "line": record.line, "func": record.func,
        })
    fig = px.timeline(
        rows, x_start="start", x_end="end", y="lane", color="label",
        hover_data=[
            "label", "dur_ms", "gid", "depth", "span", "parent",
            "file", "line", "func"
        ],
        title=title or "IMM profiling timeline"
    )
    fig.update_layout(
        template="plotly_white", height=640,
        margin={"t": 60, "r": 40, "b": 50, "l": 100}
    )
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(
        rangeslider_visible=True, showspikes=True, spikemode="across",
        spikesnap="cursor", spikethickness=1
    )
    if out:
        fig.write_html(out, include_plotlyjs="cdn", full_html=True)
        print(f"Wrote {out}")
    else:
        fig.show()


def parse_args(argv: List[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Interactive IMM profiling plot (simple)"
    )
    parser.add_argument(
        '-i', '--input',
        help=f'input dat file (default: {DEFAULT_INPUT})',
        default=DEFAULT_INPUT
    )
    parser.add_argument(
        '-o', '--out',
        help='output HTML (if omitted, open interactively)'
    )
    parser.add_argument(
        '-L', '--labels',
        help='comma-separated labels to include (default: auto by total ms)'
    )
    parser.add_argument(
        '--top', type=int, default=6,
        help='when no labels specified, show top N by total duration '
             '(default: 6)'
    )
    parser.add_argument(
        '--smooth', type=int, default=1,
        help='moving average window (in points) to smooth lines'
    )
    parser.add_argument('--title', help='plot title')
    parser.add_argument(
        '--mode', choices=['lines', 'timeline'], default='lines',
        help='plot mode: lines (default) or timeline'
    )
    parser.add_argument(
        '--list-labels', action='store_true',
        help='list available labels and counts, then exit'
    )
    return parser.parse_args(argv)


def open_input(path: str):
    """Open input file with fallback options."""
    try:
        # pylint: disable=consider-using-with
        file_handle = open(path, 'r', encoding='utf-8', errors='ignore')
        return file_handle, path
    except (OSError, IOError):
        for fallback_path in FALLBACK_INPUTS:
            try:
                # pylint: disable=consider-using-with
                file_handle = open(fallback_path, 'r', encoding='utf-8', errors='ignore')
                sys.stderr.write(f"using fallback input: {fallback_path}\n")
                return file_handle, fallback_path
            except (OSError, IOError):
                continue
        raise


def main(argv: List[str]) -> int:
    """Main entry point for the profiling plot tool."""
    args = parse_args(argv)
    try:
        file_handle, _ = open_input(args.input)
    except (OSError, IOError) as error:
        sys.stderr.write(f"failed to open {args.input}: {error}\n")
        return 2

    recs = parse_immprof_lines(file_handle)
    try:
        file_handle.close()
    except (OSError, IOError):
        # Ignore errors when closing the file handle, as cleanup is non-critical here.
        pass

    if not recs:
        sys.stderr.write("no immprof lines found.\n")
        return 1

    if args.list_labels:
        groups = group_by_label(recs)
        print("Available labels (label: count, total_ms, max_ms):")
        for label, arr in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
            tot = sum(rec.dur_ms for rec in arr)
            max_dur = max((rec.dur_ms for rec in arr), default=0.0)
            print(f"  {label}: {len(arr)} spans, total={tot:.3f} ms, max={max_dur:.3f} ms")
        return 0

    include = [s for s in (args.labels.split(',') if args.labels else []) if s]
    labels = select_labels_simple(recs, include if include else None, args.top)

    if args.mode == 'timeline':
        plot_timeline(recs, labels if include else None, args.out, args.title)
    else:
        plot_lines(recs, labels, args.smooth, args.out, args.title)

    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
