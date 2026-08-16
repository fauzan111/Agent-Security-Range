"""Experiment engine: sweep defenses against attacks across models, then summarise.

The study compares each defense preset on two axes at once: how much attack it stops
(security) and how much benign work it preserves (utility), plus the operational costs
(approval burden, latency, tool cost). ``pareto_frontier`` returns the non-dominated set so a
reader can see the security-utility trade at a glance, with Wilson intervals on every rate.

``verify_gate`` is the acceptance gate: for every attack it confirms the attack succeeds with
no defense, is stopped by its mapped mitigation alone, and is stopped by the combined stack.
That is the "every mitigation maps to a reproducible attack test" contract, executable.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.agent import PROFILES, ModelProfile, RunOutcome, run_scenario
from agentsec.attacks import CATALOG as ATTACKS
from agentsec.attacks import Attack
from agentsec.defenses import PRESETS
from agentsec.defenses.control_plane import DefenseConfig
from agentsec.stats import Interval, mean, wilson
from agentsec.tasks import CATALOG as TASKS
from agentsec.tasks import get_task


@dataclass
class DefenseSummary:
    defense: str
    attack_runs: int
    attack_success: Interval
    benign_runs: int
    benign_success: Interval
    false_block: Interval
    approval_burden: float
    latency: float
    cost: float
    exfiltration: Interval
    time_to_compromise: float | None

    @property
    def security(self) -> float:
        return 1.0 - self.attack_success.point

    @property
    def utility(self) -> float:
        return self.benign_success.point


def _models(models: list[str] | None) -> list[ModelProfile]:
    names = models or list(PROFILES)
    return [PROFILES[n] for n in names]


def run_attack_matrix(config: DefenseConfig, models: list[str] | None,
                      seeds: int) -> list[RunOutcome]:
    out: list[RunOutcome] = []
    for attack in ATTACKS.values():
        task = get_task(attack.task_id)
        for profile in _models(models):
            for s in range(seeds):
                out.append(run_scenario(task, attack, config, profile, seed=s))
    return out


def run_benign_matrix(config: DefenseConfig, models: list[str] | None,
                      seeds: int) -> list[RunOutcome]:
    out: list[RunOutcome] = []
    for task in TASKS.values():
        for profile in _models(models):
            for s in range(seeds):
                out.append(run_scenario(task, None, config, profile, seed=s))
    return out


def summarise(config: DefenseConfig, models: list[str] | None = None,
              seeds: int = 5) -> DefenseSummary:
    atk = run_attack_matrix(config, models, seeds)
    ben = run_benign_matrix(config, models, seeds)

    a_succ = sum(1 for o in atk if o.attack_success)
    exfil = sum(1 for o in atk if o.exfiltration)
    b_succ = sum(1 for o in ben if o.benign_success)
    fb = sum(1 for o in ben if o.false_blocks > 0)
    ttc = [o.time_to_compromise for o in atk if o.time_to_compromise is not None]

    return DefenseSummary(
        defense=config.name,
        attack_runs=len(atk), attack_success=wilson(a_succ, len(atk)),
        benign_runs=len(ben), benign_success=wilson(b_succ, len(ben)),
        false_block=wilson(fb, len(ben)),
        approval_burden=mean([o.approval_burden for o in ben]),
        latency=mean([o.latency for o in atk + ben]),
        cost=mean([o.cost for o in atk + ben]),
        exfiltration=wilson(exfil, len(atk)),
        time_to_compromise=(mean(ttc) if ttc else None))


def summarise_all(models: list[str] | None = None, seeds: int = 5) -> list[DefenseSummary]:
    return [summarise(PRESETS[name](), models, seeds) for name in PRESETS]


def pareto_frontier(summaries: list[DefenseSummary]) -> list[DefenseSummary]:
    """Non-dominated set on (security up, utility up). Higher is better on both axes."""
    frontier = []
    for s in summaries:
        dominated = any(
            other is not s and other.security >= s.security and other.utility >= s.utility
            and (other.security > s.security or other.utility > s.utility)
            for other in summaries)
        if not dominated:
            frontier.append(s)
    return sorted(frontier, key=lambda x: x.security)


# --------------------------------------------------------------------------- #
# Acceptance gate
# --------------------------------------------------------------------------- #
@dataclass
class GateResult:
    attack_id: str
    asi: str
    mitigation: str
    baseline_success: bool          # succeeds under no defense
    mitigated_blocked: bool         # blocked by the mapped mitigation alone
    combined_blocked: bool          # blocked by the full combined stack

    @property
    def passed(self) -> bool:
        return self.baseline_success and self.mitigated_blocked and self.combined_blocked


def _single_guard_config(guard: str) -> DefenseConfig:
    cfg = DefenseConfig(name=f"only:{guard}")
    setattr(cfg, guard, True)
    return cfg


def _attack_succeeds(attack: Attack, config: DefenseConfig, seeds: int) -> bool:
    task = get_task(attack.task_id)
    profile = PROFILES["weak-model"]                # most susceptible, for a clear signal
    return any(run_scenario(task, attack, config, profile, seed=s).attack_success
               for s in range(seeds))


def verify_gate(seeds: int = 8) -> list[GateResult]:
    from agentsec.defenses import combined_monitor
    results = []
    for attack in ATTACKS.values():
        mitigation = attack.primary_mitigations[0]
        baseline = _attack_succeeds(attack, DefenseConfig(name="no_defense"), seeds)
        mitigated = not _attack_succeeds(attack, _single_guard_config(mitigation), seeds)
        combined = not _attack_succeeds(attack, combined_monitor(), seeds)
        results.append(GateResult(
            attack_id=attack.id, asi=attack.asi.value, mitigation=mitigation,
            baseline_success=baseline, mitigated_blocked=mitigated, combined_blocked=combined))
    return results


__all__ = [
    "DefenseSummary",
    "GateResult",
    "pareto_frontier",
    "run_attack_matrix",
    "run_benign_matrix",
    "summarise",
    "summarise_all",
    "verify_gate",
]
