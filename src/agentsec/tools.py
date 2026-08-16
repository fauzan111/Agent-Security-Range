"""MCP-style tool layer: email, docs, calendar, memory, ticketing, payments.

Each tool ships a signed manifest (an HMAC over its declared contract). A guard can verify
the manifest before trusting the tool's description, which is how the range models the
"malicious tool description" attack: an attacker can rewrite a description, but cannot forge
the signature, so a tampered manifest is detectable.

Execution is deliberately thin: a tool applies an effect to ``RangeState`` and returns a
short description. All policy lives in the control plane, never in the tool.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field

from agentsec.environment.state import RangeState, is_external_address
from agentsec.models import MemoryRecord, Origin, Payment, Privilege, Provenance

# Signing key for manifests. In a real system this is an org secret; here it is fixed so
# tests are deterministic. Attacks never get to read it.
_MANIFEST_KEY = b"northwind-tool-signing-key"


def sign_manifest(name: str, description: str, actions: tuple[str, ...]) -> str:
    body = name + "|" + description + "|" + ",".join(sorted(actions))
    return hmac.new(_MANIFEST_KEY, body.encode(), hashlib.sha256).hexdigest()


@dataclass
class ToolManifest:
    name: str
    description: str
    actions: tuple[str, ...]
    signature: str = ""

    def sign(self) -> ToolManifest:
        self.signature = sign_manifest(self.name, self.description, self.actions)
        return self

    def verify(self) -> bool:
        expected = sign_manifest(self.name, self.description, self.actions)
        return hmac.compare_digest(expected, self.signature)


# Each action maps to (privilege, consequential, executor).
Executor = Callable[[RangeState, dict], str]


@dataclass
class Action:
    privilege: Privilege
    consequential: bool
    execute: Executor


# --------------------------------------------------------------------------- #
# Executors
# --------------------------------------------------------------------------- #
def _email_send(state: RangeState, args: dict) -> str:
    to = args.get("to", "")
    body = args.get("body", "")
    if is_external_address(to):
        state.send_external("email", to, body)
        return f"external email sent to {to}"
    state.sent_internal.append({"to": to, "body": body})
    return f"internal email sent to {to}"


def _docs_read(state: RangeState, args: dict) -> str:
    doc = state.documents.get(args.get("doc_id", ""))
    return f"read doc {doc.id}" if doc else "doc not found"


def _calendar_write(state: RangeState, args: dict) -> str:
    from agentsec.models import CalendarEvent, Origin, Provenance
    ev = CalendarEvent(
        id=args.get("id", f"c-{len(state.calendar)}"), title=args.get("title", ""),
        attendees=args.get("attendees", []), notes=args.get("notes", ""),
        provenance=args.get("provenance") or Provenance(origin=Origin.MEMORY, tainted=False))
    state.calendar[ev.id] = ev
    return f"calendar updated: {ev.title}"


def _memory_write(state: RangeState, args: dict) -> str:
    rec = MemoryRecord(
        id=args.get("id", f"m-{len(state.memory)}"),
        key=args.get("key", ""), value=args.get("value", ""),
        provenance=args.get("provenance") or Provenance(origin=Origin.MEMORY, tainted=False),
        instruction=args.get("instruction"),
        written_at_step=state.step,
        expires_at_step=args.get("expires_at_step"))
    state.write_memory(rec)
    return f"memory written: {rec.key}"


def _ticket_write(state: RangeState, args: dict) -> str:
    tid = args.get("id", "")
    tk = state.tickets.get(tid)
    if tk is not None and "status" in args:
        tk.status = args["status"]
    return f"ticket updated: {tid}"


def _payment_send(state: RangeState, args: dict) -> str:
    to_account = args.get("to_account", "")
    amount = float(args.get("amount", 0.0))
    external = bool(args.get("external", True))
    state.send_payment(Payment(id=f"p-{len(state.payments)}", to_account=to_account,
                               amount=amount, memo=args.get("memo", ""), external=external))
    return f"payment {amount} sent to {to_account}"


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
@dataclass
class ToolRegistry:
    actions: dict[str, Action] = field(default_factory=dict)
    manifests: dict[str, ToolManifest] = field(default_factory=dict)

    def action(self, name: str) -> Action | None:
        return self.actions.get(name)

    def execute(self, name: str, state: RangeState, args: dict) -> str:
        act = self.actions.get(name)
        if act is None:
            return f"unknown action {name}"
        return act.execute(state, args)


def default_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.actions = {
        "email.read": Action(Privilege.READ, False, lambda s, a: "read inbox"),
        "email.send_internal": Action(Privilege.WRITE, False, _email_send),
        "email.send_external": Action(Privilege.SEND_EXTERNAL, True, _email_send),
        "docs.read": Action(Privilege.READ, False, _docs_read),
        "calendar.read": Action(Privilege.READ, False, lambda s, a: "read calendar"),
        "calendar.write": Action(Privilege.WRITE, False, _calendar_write),
        "memory.read": Action(Privilege.READ, False, lambda s, a: "read memory"),
        "memory.write": Action(Privilege.WRITE, False, _memory_write),
        "ticket.read": Action(Privilege.READ, False, lambda s, a: "read tickets"),
        "ticket.write": Action(Privilege.WRITE, False, _ticket_write),
        "payments.send": Action(Privilege.PAYMENT, True, _payment_send),
    }
    for tool, desc, acts in [
        ("email", "Read and send company email.",
         ("email.read", "email.send_internal", "email.send_external")),
        ("docs", "Read company documents.", ("docs.read",)),
        ("calendar", "Read and write calendar events.", ("calendar.read", "calendar.write")),
        ("memory", "Read and write agent memory.", ("memory.read", "memory.write")),
        ("ticketing", "Read and write support tickets.", ("ticket.read", "ticket.write")),
        ("payments", "Send payments to vendor accounts.", ("payments.send",)),
    ]:
        reg.manifests[tool] = ToolManifest(tool, desc, acts).sign()
    return reg


_DEFAULT_META: dict[str, Action] | None = None


def action_meta(name: str) -> tuple[Privilege, bool]:
    """(privilege, consequential) for an action, from the canonical registry."""
    global _DEFAULT_META
    if _DEFAULT_META is None:
        _DEFAULT_META = default_registry().actions
    act = _DEFAULT_META.get(name)
    if act is None:
        return (Privilege.NONE, False)
    return (act.privilege, act.consequential)


def make_request(action: str, step: int = 0, args: dict | None = None, intent: str = "",
                 adversarial: bool = False, attack_id: str | None = None,
                 source_provenance: Provenance | None = None,
                 delegation_id: str | None = None):
    """Build a fully-typed ActionRequest, filling privilege/consequential from the registry."""
    from agentsec.models import ActionRequest
    priv, conseq = action_meta(action)
    tool = action.split(".", 1)[0]
    return ActionRequest(
        step=step, tool=tool, action=action, args=args or {}, privilege=priv,
        consequential=conseq, source_provenance=source_provenance, delegation_id=delegation_id,
        adversarial=adversarial, attack_id=attack_id, intent=intent)


__all__ = [
    "Action",
    "ToolManifest",
    "ToolRegistry",
    "action_meta",
    "default_registry",
    "make_request",
    "sign_manifest",
]
