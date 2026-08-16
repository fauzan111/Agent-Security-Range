"""Append-only incident recorder.

Every denial, approval, circuit trip, kill-switch pull, and confirmed breach lands here.
The list is append-only by construction: there is no update or delete method, only
``record`` and read accessors. This is the audit spine that lets a reviewer reconstruct
exactly why the range reached its final state.
"""

from __future__ import annotations

from agentsec.models import Incident


class IncidentRecorder:
    def __init__(self) -> None:
        self._log: list[Incident] = []

    def record(self, incident: Incident) -> None:
        self._log.append(incident)

    def deny(self, step: int, guard: str, detail: str, attack_id: str | None = None) -> None:
        self.record(Incident(step=step, kind="deny", guard=guard, detail=detail,
                             attack_id=attack_id))

    def approval(self, step: int, detail: str, attack_id: str | None = None) -> None:
        self.record(Incident(step=step, kind="approval", detail=detail, attack_id=attack_id))

    def breach(self, step: int, detail: str, attack_id: str | None = None) -> None:
        self.record(Incident(step=step, kind="breach", detail=detail, attack_id=attack_id))

    def trip(self, step: int, guard: str, detail: str) -> None:
        self.record(Incident(step=step, kind="trip", guard=guard, detail=detail))

    def all(self) -> list[Incident]:
        return list(self._log)

    def of_kind(self, kind: str) -> list[Incident]:
        return [i for i in self._log if i.kind == kind]

    def count(self, kind: str) -> int:
        return sum(1 for i in self._log if i.kind == kind)


__all__ = ["IncidentRecorder"]
