#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""
Plot FrameReader statistics from CSV produced by socketdriver.StartStatsLogger.

Usage:
    # Copy CSV from device:
    scp device:/persist/pubsub-frame-stats.csv .

    # Plot all graphs:
    python3 plot_frame_stats.py pubsub-frame-stats.csv

    # Plot specific topics only:
    python3 plot_frame_stats.py pubsub-frame-stats.csv \
        --topics DeviceNetworkStatus AppInstanceStatus

    # Save to file instead of showing:
    python3 plot_frame_stats.py pubsub-frame-stats.csv -o stats.png

Produces a multi-panel figure with:
    1. Total arena memory vs old pool memory over time (log/log axes)
    2. Per-topic buffer sizes over time
    3. Cumulative buffer reallocations (grows) over time
    4. Size bucket distribution (stacked bar per topic)
"""

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime

try:
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    _HAVE_MATPLOTLIB = True
except ImportError:
    _HAVE_MATPLOTLIB = False

try:
    import numpy as np
except ImportError:
    _HAVE_MATPLOTLIB = False  # numpy is also required; reuse the same flag


def parse_csv(path):
    """Parse the stats CSV into per-topic timeseries and totals timeseries."""
    topics = defaultdict(
        lambda: {
            "timestamps": [],
            "frames": [],
            "bytes": [],
            "grows": [],
            "max_frame": [],
            "buf_size": [],
            "old_pool_mem": [],
            "arena_mem": [],
            "saved_bytes": [],
            "arena_allocs": [],
            "buckets": [],
        }
    )

    with open(path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        bucket_cols = [col for col in reader.fieldnames if col.startswith("bucket_")]
        for row in reader:
            topic = row["topic"]
            timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            data = topics[topic]
            data["timestamps"].append(timestamp)
            data["frames"].append(int(row["frames"]))
            data["bytes"].append(int(row["bytes"]))
            data["grows"].append(int(row["grows"]))
            data["max_frame"].append(int(row["max_frame"]))
            data["buf_size"].append(int(row["buf_size"]))
            data["old_pool_mem"].append(int(row["old_pool_mem"]))
            data["arena_mem"].append(int(row["arena_mem"]))
            data["saved_bytes"].append(int(row["saved_bytes"]))
            data["arena_allocs"].append(int(row["arena_allocs"]))
            data["buckets"].append({col: int(row[col]) for col in bucket_cols})

    return dict(topics), bucket_cols


def human_bytes(nbytes):
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f}{unit}"
        nbytes /= 1024
    return f"{nbytes:.1f}TB"


def _plot_memory(axis, totals):
    """Panel 1: total arena vs old-pool memory (log/log axes)."""
    if not totals:
        return
    start_time = totals["timestamps"][0]
    elapsed = [(ts - start_time).total_seconds() + 1 for ts in totals["timestamps"]]
    axis.plot(
        elapsed,
        [mem / 1024 for mem in totals["old_pool_mem"]],
        label="Old pool (65KB × readers)",
        color="red",
        linestyle="--",
        linewidth=2,
    )
    axis.plot(
        elapsed,
        [mem / 1024 for mem in totals["arena_mem"]],
        label="Arena (actual)",
        color="green",
        linewidth=2,
    )
    axis.fill_between(
        elapsed,
        [mem / 1024 for mem in totals["arena_mem"]],
        [mem / 1024 for mem in totals["old_pool_mem"]],
        alpha=0.15,
        color="green",
        label="Saved",
    )
    axis.set_title("Total Buffer Memory: Arena vs Old Pool")
    axis.set_xlabel("Elapsed time (s)")
    axis.set_ylabel("Memory (KB)")
    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.legend(loc="upper left", fontsize=8)
    axis.grid(True, alpha=0.3, which="both")


def _plot_buf_sizes(axis, sorted_topics, topics, date_fmt):
    """Panel 2: per-topic buffer sizes over time."""
    for topic in sorted_topics:
        data = topics[topic]
        if not data["timestamps"]:
            continue
        # Only label topics that grew beyond the initial 1 KB buffer;
        # flat topics clutter the legend without adding information.
        grew = data["buf_size"] and max(data["buf_size"]) > 1024
        axis.plot(
            data["timestamps"],
            [mem / 1024 for mem in data["buf_size"]],
            label=topic if grew else "_nolegend_",
            linewidth=1.5 if grew else 0.8,
            alpha=1.0 if grew else 0.3,
        )
    axis.set_title("Per-Topic Buffer Size Over Time")
    axis.set_ylabel("Buffer Size (KB)")
    axis.axhline(y=64, color="red", linestyle=":", alpha=0.5, label="Old pool (64KB)")
    axis.legend(bbox_to_anchor=(1.01, 1), loc="upper left", fontsize=7, borderaxespad=0)
    axis.grid(True, alpha=0.3)
    axis.xaxis.set_major_formatter(date_fmt)


def _plot_grows(axis, sorted_topics, topics, totals, date_fmt):
    """Panel 3: cumulative buffer reallocations over time."""
    if totals:
        axis.plot(
            totals["timestamps"],
            totals["grows"],
            label="Total grows",
            color="orange",
            linewidth=2,
        )
        ax2 = axis.twinx()
        ax2.plot(
            totals["timestamps"],
            totals["arena_allocs"],
            label="Total allocs (initial+grows)",
            color="blue",
            linewidth=1.5,
            linestyle="--",
        )
        ax2.set_ylabel("Total Allocations", color="blue")
        ax2.tick_params(axis="y", labelcolor="blue")
        ax2.legend(loc="upper right", fontsize=8)
    for topic in sorted_topics:
        data = topics[topic]
        if not data["timestamps"] or max(data["grows"]) == 0:
            continue
        axis.plot(data["timestamps"], data["grows"], label=topic, linewidth=1, alpha=0.7)
    axis.set_title("Buffer Reallocations (GC Pressure)")
    axis.set_ylabel("Cumulative Grows")
    axis.set_xlabel("Time")
    axis.legend(loc="upper left", fontsize=6, ncol=2)
    axis.grid(True, alpha=0.3)
    axis.xaxis.set_major_formatter(date_fmt)


def _plot_buckets(axis, sorted_topics, topics, bucket_cols):  # pylint: disable=too-many-locals
    """Panel 4: frame size bucket distribution (last snapshot, stacked bar)."""
    bucket_labels = [col.replace("bucket_", "") for col in bucket_cols]

    # Collect data and sort by total frame count descending so the busiest
    # topics appear first. Use only the topic type (strip agent/ prefix) as
    # the x-axis label to keep bars readable.
    rows = []
    for topic in sorted_topics:
        data = topics[topic]
        if not data["buckets"]:
            continue
        last_buckets = data["buckets"][-1]
        total = sum(last_buckets.values())
        if total == 0:
            continue
        short_name = topic.split("/")[-1]
        rows.append((total, short_name, last_buckets))
    rows.sort(key=lambda row: row[0], reverse=True)

    # Keep only the top 20 busiest topics; fold the rest into "other".
    top_n = 20
    top_rows = rows[:top_n]
    rest_rows = rows[top_n:]

    topic_names = [row[1] for row in top_rows]
    bucket_data = defaultdict(list)
    for _, _, last_buckets in top_rows:
        for col, label in zip(bucket_cols, bucket_labels):
            bucket_data[label].append(last_buckets[col])

    if rest_rows:
        topic_names.append(f"other ({len(rest_rows)})")
        for col, label in zip(bucket_cols, bucket_labels):
            bucket_data[label].append(sum(row[2][col] for row in rest_rows))

    if topic_names:
        xpos = np.arange(len(topic_names))
        bottom = np.zeros(len(topic_names))
        colors = plt.cm.viridis(np.linspace(0.1, 0.9, len(bucket_labels)))
        for label, color in zip(bucket_labels, colors):
            values = np.array(bucket_data[label], dtype=float)
            if values.sum() == 0:
                continue
            axis.bar(xpos, values, 0.7, bottom=bottom, label=label, color=color)
            bottom += values
        axis.set_xticks(xpos)
        axis.set_xticklabels(topic_names, rotation=60, ha="right", fontsize=6)
    axis.set_title("Frame Size Distribution (Last Snapshot)")
    axis.set_ylabel("Frame Count")
    axis.legend(loc="upper right", fontsize=7, title="Size Bucket")
    axis.grid(True, alpha=0.3, axis="y")


def plot(topics, bucket_cols, filter_topics=None, output=None):
    """Produce the four-panel stats figure."""
    if not _HAVE_MATPLOTLIB:
        print(
            "ERROR: matplotlib and numpy are required. "
            "Install with: pip install matplotlib numpy",
            file=sys.stderr,
        )
        sys.exit(1)

    if output:
        plt.switch_backend("Agg")

    totals = topics.pop("__totals__", None)
    if filter_topics:
        topics = {key: val for key, val in topics.items() if key in filter_topics}

    if not topics and not totals:
        print("No data to plot.", file=sys.stderr)
        sys.exit(1)

    sorted_topics = sorted(
        topics.keys(),
        key=lambda topic: topics[topic]["buf_size"][-1] if topics[topic]["buf_size"] else 0,
        reverse=True,
    )

    fig, axes = plt.subplots(2, 2, figsize=(18, 12))
    fig.suptitle("PubSub FrameReader Statistics", fontsize=14, fontweight="bold")
    date_fmt = mdates.DateFormatter("%H:%M:%S")

    _plot_memory(axes[0][0], totals)
    _plot_buf_sizes(axes[0][1], sorted_topics, topics, date_fmt)
    _plot_grows(axes[1][0], sorted_topics, topics, totals, date_fmt)
    _plot_buckets(axes[1][1], sorted_topics, topics, bucket_cols)

    plt.tight_layout()

    if output:
        fig.savefig(output, dpi=150, bbox_inches="tight")
        print(f"Saved to {output}")
    else:
        plt.show()


def main():
    """Parse arguments, load CSV, and produce the stats plot."""
    parser = argparse.ArgumentParser(description="Plot FrameReader stats from CSV")
    parser.add_argument("csv", help="Path to pubsub-frame-stats.csv")
    parser.add_argument(
        "--topics", nargs="*", help="Only show these topics (default: all)"
    )
    parser.add_argument(
        "-o", "--output", help="Save plot to file instead of showing (e.g. stats.png)"
    )
    args = parser.parse_args()

    topics, bucket_cols = parse_csv(args.csv)
    if not topics:
        print("No data found in CSV.", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(topics)} topics from {args.csv}")
    for topic in sorted(topics.keys()):
        if topic == "__totals__":
            continue
        data = topics[topic]
        num_samples = len(data["timestamps"])
        last_buf = human_bytes(data["buf_size"][-1]) if data["buf_size"] else "N/A"
        last_grows = data["grows"][-1] if data["grows"] else 0
        print(f"  {topic}: {num_samples} samples, buf={last_buf}, grows={last_grows}")

    plot(topics, bucket_cols, filter_topics=args.topics, output=args.output)


if __name__ == "__main__":
    main()
