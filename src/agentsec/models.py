"""Typed domain model for the cyber range.

Everything the agent, the attacks, and the defenses reason about is one of these types.
Provenance and taint travel with content so a defense can ask "where did the data that
motivated this action come from" without guessing from the raw string.
"""

from __future__ import annotations

from enum import Enum, IntEnum

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Provenance and privilege
# --------------------------------------------------------------------------- #
class Origin(str, Enum):
    """Where a piece of content came from. The trust boundary runs between the first two
    (trusted) and the rest (untrusted / attacker-controllable)."""
    USER = "user"                 # typed by the human principal
    INTERNAL_DOC = "internal"     # first-party company document
    EXTERNAL_EMAIL = "email"      # inbound mail from outside the org
    WEB = "web"                   # fetched web content
    MEMORY = "memory"             # recalled from the agent's own memory store
    TOOL_MANIFEST = "manifest"    # text shipped inside a tool description


TRUSTED_ORIGINS = {Origin.USER, Origin.INTERNAL_DOC}


class Privilege(IntEnum):
    NONE = 0
    READ = 1
    WRITE = 2
    SEND_EXTERNAL = 3   # email leaving the org, external web posts
    PAYMENT = 4         # moving money
    ADMIN = 5           # credential / policy changes


class Provenance(BaseModel):
    origin: Origin
    tainted: bool = False           # derived from an untrusted origin at any hop
    injected: bool = False          # this content carries a hidden instruction
    label: str = ""                 # human-readable source tag

    @classmethod
    def trusted(cls, origin: Origin = Origin.USER, label: str = "") -> Provenance:
        return cls(origin=origin, tainted=origin not in TRUSTED_ORIGINS, label=label)


# --------------------------------------------------------------------------- #
# Environment content
# --------------------------------------------------------------------------- #
class Content(BaseModel):
    """A piece of readable content in the range: an email body, a doc, a memory record.

    ``payload`` is the visible text. ``instruction`` is a hidden adversarial directive that
    a susceptible agent may follow; it is None for benign content.
    """
    id: str
    payload: str
    provenance: Provenance
    instruction: InjectedInstruction | None = None


class InjectedInstruction(BaseModel):
    """The hidden directive an attack plants. ``trigger_after`` delays activation."""
    text: str
    attack_id: str
    trigger_after: int = 0          # activates only after this many agent steps/sessions
    asi: str = ""                   # ASI id this instruction realizes


class Email(BaseModel):
    id: str
    sender: str
    to: str
    subject: str
    body: str
    external: bool = False
    provenance: Provenance
    instruction: InjectedInstruction | None = None


class Document(BaseModel):
    id: str
    title: str
    body: str
    sensitive: bool = False
    provenance: Provenance
    instruction: InjectedInstruction | None = None


class CalendarEvent(BaseModel):
    id: str
    title: str
    attendees: list[str] = Field(default_factory=list)
    notes: str = ""
    provenance: Provenance


class MemoryRecord(BaseModel):
    id: str
    key: str
    value: str
    provenance: Provenance
    instruction: InjectedInstruction | None = None
    quarantined: bool = False
    expires_at_step: int | None = None      # None = never expires
    written_at_step: int = 0


class Ticket(BaseModel):
    id: str
    title: str
    body: str
    status: str = "open"
    provenance: Provenance


class Payment(BaseModel):
    id: str
    to_account: str
    amount: float
    memo: str = ""
    external: bool = False


# --------------------------------------------------------------------------- #
# Credentials and delegation
# --------------------------------------------------------------------------- #
class Credential(BaseModel):
    """A short-lived scoped credential the agent acts under."""
    id: str
    principal: str                       # who the authority belongs to
    scopes: set[str] = Field(default_factory=set)   # allowed "tool.action" strings
    max_payment: float = 0.0
    allow_external_send: bool = False
    issued_at_step: int = 0
    ttl_steps: int = 9999                # short-lived: expires issued_at + ttl

    def expired(self, step: int) -> bool:
        return step > self.issued_at_step + self.ttl_steps

    def permits(self, action: str) -> bool:
        return action in self.scopes


class Delegation(BaseModel):
    """An explicit, signed grant of authority from one principal to the agent."""
    id: str
    grantor: str
    grantee: str
    action: str
    signature: str = ""                  # HMAC over the grant; forged grants fail check
    valid: bool = True


# --------------------------------------------------------------------------- #
# Actions and traces
# --------------------------------------------------------------------------- #
class ActionRequest(BaseModel):
    """A single tool call the agent wants to make, with the context a guard needs."""
    step: int
    tool: str
    action: str                          # e.g. "payments.send", "email.send"
    args: dict = Field(default_factory=dict)
    privilege: Privilege = Privilege.READ
    consequential: bool = False          # irreversible / external / money
    source_provenance: Provenance | None = None   # provenance of the data that motivated it
    delegation_id: str | None = None
    adversarial: bool = False            # ground-truth label: did an injection cause this
    attack_id: str | None = None
    intent: str = ""                     # the task intent this call claims to serve


class GuardOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVE = "approve"       # routed to human approval


class GuardResult(BaseModel):
    guard: str
    outcome: GuardOutcome
    reason: str = ""


class ActionResult(BaseModel):
    request: ActionRequest
    allowed: bool
    approved: bool = False
    guard_results: list[GuardResult] = Field(default_factory=list)
    effect: str = ""                     # description of what changed in the world


class Incident(BaseModel):
    """One append-only record. The recorder never mutates or deletes these."""
    step: int
    kind: str                            # deny | approval | trip | killswitch | breach
    detail: str
    attack_id: str | None = None
    guard: str = ""


Content.model_rebuild()

__all__ = [
    "TRUSTED_ORIGINS",
    "ActionRequest",
    "ActionResult",
    "CalendarEvent",
    "Content",
    "Credential",
    "Delegation",
    "Document",
    "Email",
    "GuardOutcome",
    "GuardResult",
    "Incident",
    "InjectedInstruction",
    "MemoryRecord",
    "Origin",
    "Payment",
    "Privilege",
    "Provenance",
    "Ticket",
]
