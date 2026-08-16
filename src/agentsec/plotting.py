"""Render the security-utility Pareto frontier to an image.

Kept separate from the experiment engine so the core stays installable without matplotlib.
The plot shows every defense preset as a point with Wilson confidence intervals on both axes
(security = 1 - attack-success rate, utility = benign-task success rate) and highlights the
non-dominated set. It is the picture the README leads with.
"""

from __future__ import annotations

from agentsec.experiment import DefenseSummary, pareto_frontier


def pareto_plot(summaries: list[DefenseSummary], out_path: str,
                title: str = "AgentSec Range: security-utility frontier",
                subtitle: str = "") -> str:
    """Write a Pareto scatter to ``out_path``. Raises a clear error if matplotlib is absent."""
    try:
        import matplotlib
        matplotlib.use("Agg")           # headless: no display needed, works in CI
        import matplotlib.pyplot as plt
    except ImportError as exc:          # pragma: no cover - only when extra not installed
        raise RuntimeError(
            "matplotlib is required for plotting. Install it with: pip install -e \".[plot]\""
        ) from exc

    frontier = {s.defense for s in pareto_frontier(summaries)}
    fig, ax = plt.subplots(figsize=(8.5, 6.0))

    for s in summaries:
        x, y = s.utility, s.security
        xerr = [[max(0.0, x - s.benign_success.low)], [max(0.0, s.benign_success.high - x)]]
        # security interval is the mirror of the attack-success interval
        y_low, y_high = 1 - s.attack_success.high, 1 - s.attack_success.low
        yerr = [[max(0.0, y - y_low)], [max(0.0, y_high - y)]]
        on = s.defense in frontier
        color = "#1a9850" if on else ("#d73027" if s.defense == "paranoid" else "#4575b4")
        ax.errorbar(x, y, xerr=xerr, yerr=yerr, fmt="o", ms=9, color=color, ecolor=color,
                    elinewidth=1, capsize=3, zorder=3,
                    label="Pareto-optimal" if on else None)
        dy = -14 if s.defense in ("classifier_only", "combined") else 10
        ax.annotate(s.defense, (x, y), textcoords="offset points", xytext=(8, dy),
                    fontsize=9, color=color)

    # staircase through the non-dominated points (top-right is best on both axes)
    fpts = sorted((s.utility, s.security) for s in summaries if s.defense in frontier)
    if len(fpts) >= 2:
        ax.plot([p[0] for p in fpts], [p[1] for p in fpts], "--", color="#1a9850",
                lw=1.2, zorder=2)

    ax.set_xlabel("Utility  (benign-task success rate)")
    ax.set_ylabel("Security  (1 - attack-success rate)")
    ax.set_xlim(0.0, 1.12)
    ax.set_ylim(0.0, 1.08)
    ax.grid(True, ls=":", alpha=0.5)
    full_title = title if not subtitle else f"{title}\n{subtitle}"
    ax.set_title(full_title, fontsize=12)
    ax.legend(loc="upper left", frameon=False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out_path


__all__ = ["pareto_plot"]
