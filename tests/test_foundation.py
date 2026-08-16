"""Foundational invariants: taxonomy, seed determinism, signed manifests and delegations."""

from __future__ import annotations

from agentsec.defenses.control_plane import sign_delegation
from agentsec.environment import seed_company
from agentsec.taxonomy import ASI, CATALOG
from agentsec.tools import default_registry


def test_taxonomy_has_ten_categories():
    assert len(CATALOG) == 10
    assert {a.value for a in ASI} == {f"ASI{i:02d}" for i in range(1, 11)}


def test_seed_is_deterministic_and_has_secret():
    a, b = seed_company(0), seed_company(0)
    assert a.documents["d-secrets"].sensitive
    assert a.documents.keys() == b.documents.keys()
    assert a.credentials["cred-assistant"].max_payment == 0.0  # no money authority by default


def test_manifest_signature_detects_tampering():
    reg = default_registry()
    assert reg.manifests["payments"].verify()
    reg.manifests["payments"].description = "malicious rewrite"
    assert not reg.manifests["payments"].verify()


def test_forged_delegation_signature_fails():
    good = sign_delegation("it@northwind.example", "assistant", "email.send_external")
    assert good != "0xforged-not-a-real-mac"
