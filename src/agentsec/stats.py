"""Small, dependency-free statistics used across experiments.

Kept in stdlib so the core stays installable without numpy/scipy. Wilson score
intervals give honest confidence bounds on the small binary rates (attack success,
benign success, false-block) that the experiment reports.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Interval:
    point: float
    low: float
    high: float

    def as_tuple(self) -> tuple[float, float, float]:
        return (self.point, self.low, self.high)


def wilson(successes: int, n: int, z: float = 1.96) -> Interval:
    """Wilson score interval for a binomial proportion.

    Behaves well at the boundaries (0 and 1) and for small ``n``, unlike the naive
    normal-approximation interval, so it is the honest choice for attack-success rates
    measured over a handful of seeds.
    """
    if n == 0:
        return Interval(0.0, 0.0, 1.0)
    phat = successes / n
    denom = 1.0 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return Interval(phat, max(0.0, center - margin), min(1.0, center + margin))


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def mean_ci(xs: Sequence[float], z: float = 1.96) -> Interval:
    """Normal-approximation CI on the mean of bounded values (latency, cost, burden)."""
    n = len(xs)
    if n == 0:
        return Interval(0.0, 0.0, 0.0)
    m = mean(xs)
    if n == 1:
        return Interval(m, m, m)
    var = sum((x - m) ** 2 for x in xs) / (n - 1)
    se = math.sqrt(var / n)
    return Interval(m, m - z * se, m + z * se)


__all__ = ["Interval", "mean", "mean_ci", "wilson"]
