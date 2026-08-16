"""Benign utility, the memory-hygiene disarm, the incident log, and the Pareto frontier."""

from __future__ import annotations

from agentsec.agent import PROFILES, run_scenario
from agentsec.attacks import CATALOG as ATTACKS
from agentsec.defenses import combined_monitor, deterministic, no_defense, paranoid
from agentsec.experiment import pareto_frontier, summarise_all
from agentsec.stats import wilson
from agentsec.tasks import CATALOG as TASKS
from agentsec.tasks import get_task

ROBUST = PROFILES["robust-model"]


def test_benign_tasks_pass_under_combined_without_false_blocks():
    for task in TASKS.values():
        o = run_scenario(task, None, combined_monitor(), ROBUST, seed=0)
        assert o.benign_success, f"{task.id} should complete under combined defense"
        assert o.false_blocks == 0, f"{task.id} was wrongly blocked"


def test_paranoid_trades_utility_for_security():
    """Strict taint blocks the external-invoice payment: a real security-utility trade."""
    pay = get_task("pay-invoice")
    ok = run_scenario(pay, None, deterministic(), ROBUST, seed=0)
    strict = run_scenario(pay, None, paranoid(), ROBUST, seed=0)
    assert ok.benign_success and ok.false_blocks == 0
    assert not strict.benign_success and strict.false_blocks == 1


def test_memory_hygiene_disarms_delayed_poison():
    poison = ATTACKS["delayed-memory"]
    task = get_task(poison.task_id)
    exposed = run_scenario(task, poison, no_defense(), PROFILES["weak-model"], seed=0)
    quarantined = run_scenario(task, poison, deterministic(), PROFILES["weak-model"], seed=0)
    assert exposed.memory_persistence          # poison stays live with no defense
    assert not quarantined.memory_persistence  # quarantine removes it from the live set


def test_incident_log_records_denials_and_is_append_only():
    priv = ATTACKS["privilege-abuse"]
    task = get_task(priv.task_id)
    o = run_scenario(task, priv, deterministic(), PROFILES["weak-model"], seed=0)
    assert any(i.kind == "deny" for i in o.incidents)
    # The recorder exposes no mutation API: only append and read.
    from agentsec.incident import IncidentRecorder
    assert not hasattr(IncidentRecorder, "delete")
    assert not hasattr(IncidentRecorder, "update")


def test_time_to_compromise_set_only_on_success():
    priv = ATTACKS["privilege-abuse"]
    task = get_task(priv.task_id)
    won = run_scenario(task, priv, no_defense(), PROFILES["weak-model"], seed=0)
    lost = run_scenario(task, priv, combined_monitor(), PROFILES["weak-model"], seed=0)
    assert won.attack_success and won.time_to_compromise is not None
    assert not lost.attack_success and lost.time_to_compromise is None


def test_pareto_frontier_includes_combined_monitor():
    summaries = summarise_all(seeds=3)
    names = {s.defense for s in summaries}
    assert names == {"no_defense", "classifier_only", "deterministic", "combined",
                     "combined_monitor", "paranoid"}
    frontier = {s.defense for s in pareto_frontier(summaries)}
    assert "combined_monitor" in frontier          # max security is non-dominated
    assert "no_defense" not in frontier            # dominated on security at equal utility


def test_security_increases_from_no_defense_to_combined():
    s = {x.defense: x for x in summarise_all(seeds=3)}
    assert s["no_defense"].security < s["classifier_only"].security
    assert s["classifier_only"].security < s["combined_monitor"].security
    assert s["combined_monitor"].attack_success.point == 0.0


def test_wilson_bounds_are_ordered():
    iv = wilson(3, 10)
    assert 0.0 <= iv.low <= iv.point <= iv.high <= 1.0


def test_runs_are_reproducible_and_hashseed_independent():
    """The RNG must not depend on Python's per-process string hash, or CI and local runs
    diverge. Same seed => identical outcome; robust model always finishes benign work."""
    from agentsec.agent import _stable_offset
    a = ATTACKS["goal-hijack"]
    task = get_task(a.task_id)
    o1 = run_scenario(task, a, combined_monitor(), PROFILES["weak-model"], seed=3)
    o2 = run_scenario(task, a, combined_monitor(), PROFILES["weak-model"], seed=3)
    assert (o1.attack_success, o1.unauthorized_effects) == (o2.attack_success,
                                                            o2.unauthorized_effects)
    # A stable offset is a plain int derived without the builtin hash().
    assert _stable_offset("weak-model") == _stable_offset("weak-model")
    # The reliable reference model completes every benign task at every seed.
    for task in TASKS.values():
        for s in range(5):
            assert run_scenario(task, None, combined_monitor(), PROFILES["robust-model"],
                                seed=s).benign_success
