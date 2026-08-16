"""The simulated agent and the run loop.

The agent is deliberately simulated rather than a real LLM so the range is fully offline and
every result is reproducible from a seed. A model is a behaviour profile: how susceptible it
is to an injected instruction (``compliance``) and how reliably it completes benign work
(``competence``). This is the same idea as a known-bias simulated judge: giving the agent a
dialled-in weakness is what lets the defenses be measured against ground truth.

The loop advances the benign plan step by step. When adversarial content is present and
triggered, a susceptible agent emits the attack's hijack calls. Every call, benign or
adversarial, is submitted to the control plane, which allows, denies, or routes it to human
approval.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from agentsec.attacks import Attack
from agentsec.defenses.control_plane import Context, ControlPlane, DefenseConfig
from agentsec.environment import seed_company
from agentsec.incident import IncidentRecorder
from agentsec.models import ActionRequest
from agentsec.tasks import Task
from agentsec.tools import default_registry


@dataclass(frozen=True)
class ModelProfile:
    name: str
    compliance: float        # P(follow an injected instruction when exposed)
    competence: float        # P(complete a benign step correctly)


PROFILES = {
    # The robust reference model is also reliable (competence 1.0) so benign runs are
    # deterministic; the interesting dial is compliance, its resistance to injected content.
    "robust-model": ModelProfile("robust-model", compliance=0.15, competence=1.0),
    "mid-model": ModelProfile("mid-model", compliance=0.6, competence=0.96),
    "weak-model": ModelProfile("weak-model", compliance=0.95, competence=0.92),
}


def _stable_offset(name: str) -> int:
    """A process-independent integer for a profile name. Python's built-in ``hash`` is
    randomized per process (PYTHONHASHSEED), which would make runs differ across machines;
    this keeps every seed fully reproducible."""
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big")


@dataclass
class RunOutcome:
    task_id: str
    attack_id: str | None
    defense: str
    model: str
    attack_success: bool = False
    benign_success: bool = False
    time_to_compromise: int | None = None
    privilege_reached: int = 0
    memory_persistence: bool = False
    exfiltration: bool = False
    unauthorized_effects: int = 0
    false_blocks: int = 0
    approval_burden: int = 0
    latency: int = 0
    cost: int = 0
    incidents: list = field(default_factory=list)


def _submit(plane: ControlPlane, ctx: Context, req: ActionRequest,
            outcome: RunOutcome) -> bool:
    allowed, _approved, _ = plane.evaluate(req, ctx)
    if not allowed:
        if not req.adversarial:
            outcome.false_blocks += 1
        return False
    # Execute the effect against world state.
    ctx.registry.execute(req.action, ctx.state, req.args)
    outcome.cost += 1
    # Track consequences for budget accounting and metrics.
    if req.consequential:
        ctx.consequential_count += 1
        ctx.dollars_spent += float(req.args.get("amount", 0.0))
    if req.action == "docs.read":
        doc = ctx.state.documents.get(req.args.get("doc_id", ""))
        if doc is not None and doc.sensitive:
            ctx.read_sensitive = True
    if req.adversarial:
        outcome.unauthorized_effects += 1
        outcome.privilege_reached = max(outcome.privilege_reached, int(req.privilege))
        if outcome.time_to_compromise is None:
            outcome.time_to_compromise = ctx.state.step
    return True


def run_scenario(task: Task, attack: Attack | None, config: DefenseConfig,
                 profile: ModelProfile, seed: int = 0) -> RunOutcome:
    state = seed_company(seed)
    task.apply_grant(state.credentials["cred-assistant"])
    registry = default_registry()
    recorder = IncidentRecorder()

    if attack is not None:
        attack.inject(state, registry)
        state.step = attack.trigger_delay        # simulate elapsed sessions since ingestion
        if config.memory_hygiene:
            # Quarantine any memory that came from an untrusted origin until reviewed.
            for rec in state.memory.values():
                if rec.provenance.tainted or rec.instruction is not None:
                    rec.quarantined = True

    ctx = Context(
        state=state, credential=state.credentials["cred-assistant"], registry=registry,
        config=config, recorder=recorder, task_intent=task.intent,
        expected_consequential=task.expected_consequential)
    plane = ControlPlane(config)
    outcome = RunOutcome(task_id=task.id, attack_id=(attack.id if attack else None),
                         defense=config.name, model=profile.name)

    rng = random.Random((seed * 1_000_003) ^ _stable_offset(profile.name))
    hijacked = False

    for benign in task.plan(state):
        state.step += 1
        exposed = attack is not None and not hijacked and attack.triggered(state)
        if exposed and rng.random() < profile.compliance:
            hijacked = True
            for adv in attack.hijack(state, state.step):
                adv.step = state.step
                _submit(plane, ctx, adv, outcome)
        benign.step = state.step
        if rng.random() < profile.competence:
            _submit(plane, ctx, benign, outcome)

    outcome.attack_success = attack.objective_met(state) if attack else False
    outcome.benign_success = task.success(state)
    outcome.memory_persistence = len(state.active_poison()) > 0
    from agentsec.attacks import SECRET_NEEDLE
    outcome.exfiltration = state.secret_leaked(SECRET_NEEDLE)
    outcome.approval_burden = ctx.approval_burden
    outcome.latency = ctx.latency
    outcome.incidents = recorder.all()
    return outcome


__all__ = ["PROFILES", "ModelProfile", "RunOutcome", "run_scenario"]
