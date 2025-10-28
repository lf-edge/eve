#!/usr/bin/env python3
"""
immprof_plot.py — simple interactive plot of IMM profiling durations.

Default input: ../memory-monitor/results/imm-profile.dat
Each line is key=value fields, e.g.:
  ts=... start_ts=... end_ts=... gid=123 label=imm.step dur_ms=1.234 depth=1 span=42 parent=41 file=engine.go line=123 func=...

Usage examples:
  # Open interactive HTML (default: lines mode, auto-select top labels by total ms)
  ./immprof_plot.py

  # Save HTML for specific labels
  ./immprof_plot.py -o immprof.html -L imm.step,imm.entire.pass

  # Timeline mode (nested spans)
  ./immprof_plot.py --mode timeline
"""
from __future__ import annotations

import argparse
import sys
import re
from dataclasses import dataclass
from typing import Dict, List, Iterable, Optional, Tuple
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
class Record:
    ts: datetime
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
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    if "." in val:
        head, tail = val.split(".", 1)
        tz = ""
        for sep in ["+", "-"]:
            if sep in tail[1:]:
                frac, rest = tail.split(sep, 1)
                tz = sep + rest
                break
        else:
            frac = tail
        frac = (frac + "000000")[:6]
        val = f"{head}.{frac}{tz}"
    return datetime.fromisoformat(val)


def parse_int(kvs: Dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(kvs.get(key, default))
    except Exception:
        try:
            return int(float(kvs.get(key, default)))
        except Exception:
            return default


def parse_float(kvs: Dict[str, str], key: str, default: float = float("nan")) -> float:
    try:
        return float(kvs.get(key, default))
    except Exception:
        return default


def parse_immprof_lines(lines: Iterable[str]) -> List[Record]:
    recs: List[Record] = []
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        kvs = dict(_KV_RE.findall(s))
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
                ts = parse_ts(kvs.get("ts", ""))
                end_ts = ts
            if start_ts is None and end_ts is not None and dur_ms == dur_ms:
                start_ts = end_ts - timedelta(milliseconds=dur_ms)
            if not label or end_ts is None or start_ts is None or not (dur_ms == dur_ms):
                continue
            recs.append(Record(
                ts=end_ts, start_ts=start_ts, end_ts=end_ts, gid=gid, label=label,
                dur_ms=dur_ms, depth=depth, span=span, parent=parent,
                file=file, line=line, func=func,
            ))
        except Exception:
            continue
    return recs


def group_by_label(recs: List[Record]) -> Dict[str, List[Record]]:
    groups: Dict[str, List[Record]] = {}
    for r in recs:
        groups.setdefault(r.label, []).append(r)
    for arr in groups.values():
        arr.sort(key=lambda r: r.ts)
    return groups


def totals_by_label(recs: List[Record]) -> Dict[str, float]:
    tot: Dict[str, float] = {}
    for r in recs:
        tot[r.label] = tot.get(r.label, 0.0) + r.dur_ms
    return tot


def select_labels_simple(recs: List[Record], include: Optional[List[str]], top: int) -> List[str]:
    if include:
        return include
    tot = totals_by_label(recs)
    labels = sorted(tot.keys(), key=lambda k: tot[k], reverse=True)
    return labels[:top]


def moving_avg(vals: List[float], k: int) -> List[float]:
    if k <= 1 or not vals:
        return vals
    k = min(k, len(vals))
    out: List[float] = []
    s = sum(vals[:k])
    out.append(s / k)
    for i in range(k, len(vals)):
        s += vals[i] - vals[i - k]
        out.append(s / k)
    return [out[0]] * (k - 1) + out


def plot_lines(recs: List[Record], labels: List[str], smooth: int, out: Optional[str], title: Optional[str]) -> None:
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
        xs = [r.ts for r in arr]
        ys = [r.dur_ms for r in arr]
        color = palette[idx % len(palette)]
        if smooth > 1:
            ys_s = moving_avg(ys, smooth)
            fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines", name=f"{label} (raw)",
                                     line=dict(width=1.0, color=color), opacity=0.25,
                                     hovertemplate=f"{label} raw: %{{y:.3f}} ms<extra></extra>",
                                     showlegend=False))
            fig.add_trace(go.Scatter(x=xs, y=ys_s, mode="lines", name=label,
                                     line=dict(width=1.8, color=color),
                                     hovertemplate=f"{label}: %{{y:.3f}} ms<extra></extra>"))
        else:
            fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines+markers", name=label,
                                     line=dict(width=1.6, color=color), marker=dict(size=3),
                                     hovertemplate=f"{label}: %{{y:.3f}} ms<extra></extra>"))
    fig.update_layout(
        title=title or "IMM profiling durations (ms)",
        xaxis_title="Time",
        yaxis_title="Duration (ms)",
        hovermode="x unified",
        template="plotly_white",
        margin=dict(t=60, r=40, b=50, l=60),
        height=520,
    )
    fig.update_xaxes(rangeslider_visible=True, showspikes=True, spikemode="across", spikesnap="cursor", spikethickness=1)
    fig.update_yaxes(rangemode="tozero")
    if out:
        fig.write_html(out, include_plotlyjs="cdn", full_html=True)
        print(f"Wrote {out}")
    else:
        fig.show()


def plot_timeline(recs: List[Record], include: Optional[List[str]], out: Optional[str], title: Optional[str]) -> None:
    if include:
        inc = set(include)
        recs = [r for r in recs if r.label in inc]
    if not recs:
        sys.stderr.write("no matching records to plot.\n")
        return
    rows = []
    for r in recs:
        rows.append({
            "start": r.start_ts, "end": r.end_ts, "lane": f"G{r.gid} d{r.depth}",
            "label": r.label, "dur_ms": r.dur_ms, "gid": r.gid,
            "depth": r.depth, "span": r.span, "parent": r.parent,
            "file": r.file, "line": r.line, "func": r.func,
        })
    fig = px.timeline(rows, x_start="start", x_end="end", y="lane", color="label",
                      hover_data=["label", "dur_ms", "gid", "depth", "span", "parent", "file", "line", "func"],
                      title=title or "IMM profiling timeline")
    fig.update_layout(template="plotly_white", height=640, margin=dict(t=60, r=40, b=50, l=100))
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(rangeslider_visible=True, showspikes=True, spikemode="across", spikesnap="cursor", spikethickness=1)
    if out:
        fig.write_html(out, include_plotlyjs="cdn", full_html=True)
        print(f"Wrote {out}")
    else:
        fig.show()


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Interactive IMM profiling plot (simple)")
    p.add_argument('-i', '--input', help=f'input dat file (default: {DEFAULT_INPUT})', default=DEFAULT_INPUT)
    p.add_argument('-o', '--out', help='output HTML (if omitted, open interactively)')
    p.add_argument('-L', '--labels', help='comma-separated labels to include (default: auto by total ms)')
    p.add_argument('--top', type=int, default=6, help='when no labels specified, show top N by total duration (default: 6)')
    p.add_argument('--smooth', type=int, default=1, help='moving average window (in points) to smooth lines')
    p.add_argument('--title', help='plot title')
    p.add_argument('--mode', choices=['lines', 'timeline'], default='lines', help='plot mode: lines (default) or timeline')
    p.add_argument('--list-labels', action='store_true', help='list available labels and counts, then exit')
    return p.parse_args(argv)


def open_input(path: str):
    try:
        return open(path, 'r', encoding='utf-8', errors='ignore'), path
    except Exception:
        for fb in FALLBACK_INPUTS:
            try:
                f = open(fb, 'r', encoding='utf-8', errors='ignore')
                sys.stderr.write(f"using fallback input: {fb}\n")
                return f, fb
            except Exception:
                continue
        raise


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    try:
        lines, used = open_input(args.input)
    except Exception as e:
        sys.stderr.write(f"failed to open {args.input}: {e}\n")
        return 2

    recs = parse_immprof_lines(lines)
    try:
        lines.close()
    except Exception:
        pass

    if not recs:
        sys.stderr.write("no immprof lines found.\n")
        return 1

    if args.list_labels:
        groups = group_by_label(recs)
        print("Available labels (label: count, total_ms, max_ms):")
        for l, arr in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
            tot = sum(r.dur_ms for r in arr)
            mx = max((r.dur_ms for r in arr), default=0.0)
            print(f"  {l}: {len(arr)} spans, total={tot:.3f} ms, max={mx:.3f} ms")
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
