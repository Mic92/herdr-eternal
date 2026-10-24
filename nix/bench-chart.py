#!/usr/bin/env python3
"""Render docs/bench.svg from nix/bench-netem.sh output.

usage: for t in ssh ws quic; do nix/bench-netem.sh $t 50 > $t.log; done
       nix shell --impure --expr \
         '(import <nixpkgs> {}).python3.withPackages (ps: [ ps.matplotlib ])' \
         -c python3 nix/bench-chart.py ssh.log ws.log quic.log > docs/bench.svg
"""

import re
import sys
from pathlib import Path

import matplotlib.pyplot as plt

LABELS = {
    "lan": "LAN",
    "dsl": "DSL\n24 ms",
    "lte": "LTE\n60 ms · 1% loss",
    "lossy": "Lossy\n60 ms · 5% loss",
    "bad": "Bad\n150 ms · 3% loss\n1 Mbit/s",
}
SERIES = {
    "ssh": ("OpenSSH (-C)", "#9aa3ad"),
    "ws": ("herdr-eternal · WebSocket", "#7fb3e0"),
    "quic": ("herdr-eternal · QUIC", "#1f6fbf"),
}


def parse(text: str) -> dict[str, tuple[float, float]]:
    """Profile -> (connect p50 ms, bulk MiB/s)."""
    results = {}
    for block in re.split(r"^== ", text, flags=re.MULTILINE)[1:]:
        profile = block.split()[0]
        connect = re.search(r"^connect .*?p50=\s*([\d.]+)ms", block, re.MULTILINE)
        bulk = re.search(r"^bulk .*= ([\d.]+) MiB/s", block, re.MULTILINE)
        if connect and bulk:
            results[profile] = (float(connect[1]), float(bulk[1]))
    return results


def style(ax: plt.Axes, ticks: list[str], title: str, subtitle: str) -> None:
    ax.set_xticks(range(len(ticks)), ticks, fontsize=7.5, color="#555")
    ax.set_title(title, fontsize=10.5, loc="left", fontweight="bold", pad=16)
    ax.text(0, 1.025, subtitle, transform=ax.transAxes, fontsize=8, color="#777")
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#ccc")
    ax.set_yticks([])
    ax.tick_params(axis="x", length=0)


def main() -> None:
    runs = {}
    for path in map(Path, sys.argv[1:]):
        text = path.read_text()
        transport = re.search(r"^transport=(\w+)", text, re.MULTILINE)
        if not transport:
            sys.exit(f"{path}: no transport= line")
        runs[transport[1]] = parse(text)
    if set(runs) != set(SERIES):
        sys.exit(f"need runs for {', '.join(SERIES)}")
    profiles = [p for p in LABELS if all(p in r for r in runs.values())]
    ticks = [LABELS[p] for p in profiles]
    x = range(len(profiles))

    plt.rcParams.update(
        {"font.family": "DejaVu Sans", "svg.fonttype": "none", "svg.hashsalt": "bench"}
    )
    fig, (left, right) = plt.subplots(
        1, 2, figsize=(10, 3.3), gridspec_kw={"wspace": 0.1}
    )

    width = 0.27
    for i, (key, (label, color)) in enumerate(SERIES.items()):
        values = [runs[key][p][0] for p in profiles]
        bars = left.bar(
            [v + (i - 1) * width for v in x],
            values,
            width * 0.92,
            label=label,
            color=color,
        )
        left.bar_label(
            bars, [f"{v:.0f}" for v in values], fontsize=6.5, padding=1.5, color="#555"
        )

    # Relative throughput; OpenSSH is the 1× reference line.
    width = 0.34
    for i, key in enumerate(("ws", "quic")):
        values = [runs[key][p][1] / runs["ssh"][p][1] for p in profiles]
        bars = right.bar(
            [v + (i - 0.5) * width for v in x],
            values,
            width * 0.92,
            color=SERIES[key][1],
        )
        right.bar_label(
            bars, [f"{v:.1f}×" for v in values], fontsize=6.5, padding=1.5, color="#555"
        )
    right.axhline(1, color=SERIES["ssh"][1], lw=1.2, ls="--", zorder=0)
    right.set_xlim(-0.5, len(profiles) + 0.05)
    right.text(
        len(profiles) + 0.05, 1.08, "OpenSSH", fontsize=7, color="#888", ha="right"
    )

    style(
        left, ticks, "Connect and run a command", "p50 latency in ms · lower is better"
    )
    style(
        right, ticks, "Bulk output throughput", "relative to OpenSSH · higher is better"
    )
    fig.legend(
        *left.get_legend_handles_labels(),
        loc="lower center",
        ncol=3,
        frameon=False,
        fontsize=8.5,
        handlelength=1,
        columnspacing=2,
    )
    fig.subplots_adjust(left=0.02, right=0.98, top=0.83, bottom=0.24)
    fig.savefig(sys.stdout.buffer, format="svg", facecolor="white")


if __name__ == "__main__":
    main()
