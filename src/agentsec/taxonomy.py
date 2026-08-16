"""OWASP ASI01-10 taxonomy for agentic-AI threats.

This is a synthesis of OWASP's Agentic Security Initiative threat categories, frozen here
so every attack and every mitigation in the range maps to a stable identifier. The mapping
is the backbone of the acceptance gate: a mitigation is only credited if a reproducible
attack test under the matching ASI id both succeeds without it and is stopped with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ASI(str, Enum):
    GOAL_MANIPULATION = "ASI01"       # intent breaking, goal hijacking
    TOOL_MISUSE = "ASI02"             # malicious tool descriptions / manifests
    STORED_INJECTION = "ASI03"        # stored / indirect prompt injection
    MEMORY_POISONING = "ASI04"        # delayed memory poisoning, triggers
    PRIVILEGE_ABUSE = "ASI05"         # privilege compromise and abuse
    CONFUSED_DEPUTY = "ASI06"         # confused deputy, forged delegation
    CASCADING_FAILURE = "ASI07"       # cascading failures across steps
    RESOURCE_EXHAUSTION = "ASI08"     # resource / budget overload
    COVERT_EXFILTRATION = "ASI09"     # covert data exfiltration
    REWARD_HACKING = "ASI10"          # reward hacking, misaligned success


@dataclass(frozen=True)
class ASIInfo:
    id: ASI
    title: str
    summary: str


CATALOG: dict[ASI, ASIInfo] = {
    ASI.GOAL_MANIPULATION: ASIInfo(
        ASI.GOAL_MANIPULATION, "Goal manipulation and intent breaking",
        "Adversarial content rewrites the agent's objective mid-task."),
    ASI.TOOL_MISUSE: ASIInfo(
        ASI.TOOL_MISUSE, "Tool misuse and malicious manifests",
        "A tool's own description carries hidden instructions or an unsafe contract."),
    ASI.STORED_INJECTION: ASIInfo(
        ASI.STORED_INJECTION, "Stored and indirect prompt injection",
        "Injected instructions arrive through data the agent reads, not the user."),
    ASI.MEMORY_POISONING: ASIInfo(
        ASI.MEMORY_POISONING, "Memory poisoning with delayed triggers",
        "Poisoned records persist and fire sessions after they were ingested."),
    ASI.PRIVILEGE_ABUSE: ASIInfo(
        ASI.PRIVILEGE_ABUSE, "Privilege compromise and abuse",
        "The agent uses authority it holds for a purpose it was never granted."),
    ASI.CONFUSED_DEPUTY: ASIInfo(
        ASI.CONFUSED_DEPUTY, "Confused deputy and forged delegation",
        "The agent is tricked into acting for an attacker under someone else's authority."),
    ASI.CASCADING_FAILURE: ASIInfo(
        ASI.CASCADING_FAILURE, "Cascading failures",
        "One compromised step seeds inputs that corrupt later steps."),
    ASI.RESOURCE_EXHAUSTION: ASIInfo(
        ASI.RESOURCE_EXHAUSTION, "Resource exhaustion and overload",
        "The agent is driven to burn calls, tokens, money, or human attention."),
    ASI.COVERT_EXFILTRATION: ASIInfo(
        ASI.COVERT_EXFILTRATION, "Covert exfiltration",
        "Secrets leave the trust boundary through a plausible-looking channel."),
    ASI.REWARD_HACKING: ASIInfo(
        ASI.REWARD_HACKING, "Reward hacking and misaligned success",
        "The agent games the success signal instead of doing the real task."),
}


def describe(asi: ASI) -> str:
    info = CATALOG[asi]
    return f"{info.id.value} {info.title}: {info.summary}"


__all__ = ["ASI", "CATALOG", "ASIInfo", "describe"]
