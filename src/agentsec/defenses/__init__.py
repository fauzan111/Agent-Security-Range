"""Defense presets: the five configurations the experiment compares, plus a paranoid point.

The presets are the columns of the security-utility study:

* ``no_defense``       - baseline: every attack that a compromised agent attempts succeeds.
* ``classifier_only``  - a content classifier scans inputs. Catches visible injection text,
                         but is blind to authorization and delayed-memory attacks.
* ``deterministic``    - authorization, provenance/taint, budgets, delegation, approval,
                         signed manifests, memory hygiene, and a circuit breaker.
* ``combined``         - deterministic controls plus the classifier.
* ``combined_monitor`` - combined plus a trajectory monitor.
* ``paranoid``         - combined_monitor with strict taint (higher security, some false
                         blocks on legitimate external-data-driven actions).
"""

from __future__ import annotations

from agentsec.defenses.control_plane import (
    Context,
    ControlPlane,
    DefenseConfig,
    sign_delegation,
)


def no_defense() -> DefenseConfig:
    return DefenseConfig(name="no_defense")


def classifier_only() -> DefenseConfig:
    return DefenseConfig(name="classifier_only", classifier=True)


def deterministic() -> DefenseConfig:
    return DefenseConfig(
        name="deterministic", authorization=True, taint=True, budget=True, delegation=True,
        approval=True, manifests=True, memory_hygiene=True, circuit_breaker=True)


def combined() -> DefenseConfig:
    cfg = deterministic()
    cfg.name = "combined"
    cfg.classifier = True
    return cfg


def combined_monitor() -> DefenseConfig:
    cfg = combined()
    cfg.name = "combined_monitor"
    cfg.monitor = True
    return cfg


def paranoid() -> DefenseConfig:
    cfg = combined_monitor()
    cfg.name = "paranoid"
    cfg.taint_strict = True
    return cfg


PRESETS = {
    "no_defense": no_defense,
    "classifier_only": classifier_only,
    "deterministic": deterministic,
    "combined": combined,
    "combined_monitor": combined_monitor,
    "paranoid": paranoid,
}


def get_preset(name: str) -> DefenseConfig:
    return PRESETS[name]()


__all__ = [
    "PRESETS",
    "Context",
    "ControlPlane",
    "DefenseConfig",
    "classifier_only",
    "combined",
    "combined_monitor",
    "deterministic",
    "get_preset",
    "no_defense",
    "paranoid",
    "sign_delegation",
]
