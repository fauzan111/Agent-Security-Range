"""The Pareto plot renders to a valid PNG. Skipped when the plot extra is not installed."""

from __future__ import annotations

import struct

import pytest

pytest.importorskip("matplotlib")

from agentsec.experiment import summarise_all
from agentsec.plotting import pareto_plot


def test_pareto_plot_writes_a_png(tmp_path):
    out = tmp_path / "pareto.png"
    summaries = summarise_all(seeds=2)
    path = pareto_plot(summaries, str(out), subtitle="test")
    assert out.exists() and str(out) == path
    # PNG magic number, so we know it is a real image and not an empty or error file.
    with open(out, "rb") as f:
        assert f.read(8) == struct.pack("8B", 137, 80, 78, 71, 13, 10, 26, 10)
    assert out.stat().st_size > 1000
