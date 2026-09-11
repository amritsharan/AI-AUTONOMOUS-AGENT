"""
Unit tests for QuantumShield AI Policy Engine.
Verifies strictly deterministic security boundaries.
"""
import pytest
from app.policy.engine import (
    PolicyEngine,
    ScopeConfig,
    NEVER_ALLOWED_ACTIONS,
    VALID_TEST_ACTIONS,
    DESTRUCTIVE_ACTIONS,
)


@pytest.fixture
def lab_scope():
    return ScopeConfig(
        target="http://vulnerable-app:8080",
        environment="lab",
        allowed_hosts=["vulnerable-app", "localhost", "127.0.0.1"],
        allowed_ports=[80, 443, 8080, 8000, 3000],
        destructive_tests=False,
        max_requests_per_minute=60,
    )


def test_valid_action_allowed(lab_scope):
    pe = PolicyEngine()
    decision = pe.validate("recon_crawl", "http://vulnerable-app:8080/api/users", lab_scope)
    assert decision.allowed is True
    assert "passed" in decision.reason.lower()


def test_never_allowed_actions_blocked(lab_scope):
    pe = PolicyEngine()
    for bad_action in NEVER_ALLOWED_ACTIONS:
        decision = pe.validate(bad_action, "http://vulnerable-app:8080", lab_scope)
        assert decision.allowed is False
        assert "prohibited" in decision.reason.lower()


def test_unknown_action_blocked(lab_scope):
    pe = PolicyEngine()
    decision = pe.validate("some_random_payload_hack", "http://vulnerable-app:8080", lab_scope)
    assert decision.allowed is False
    assert "unknown action" in decision.reason.lower()


def test_destructive_action_gated(lab_scope):
    pe = PolicyEngine()
    # When destructive_tests is False, destructive action is blocked
    lab_scope.destructive_tests = False
    decision = pe.validate("delete_test_data", "http://vulnerable-app:8080", lab_scope)
    assert decision.allowed is False
    assert "destructive" in decision.reason.lower()

    # When destructive_tests is True, it is allowed for authorized host
    lab_scope.destructive_tests = True
    decision = pe.validate("delete_test_data", "http://vulnerable-app:8080", lab_scope)
    assert decision.allowed is True


def test_production_environment_hard_blocked():
    pe = PolicyEngine()
    prod_scope = ScopeConfig(
        target="http://production-site.com",
        environment="production",
        allowed_hosts=["production-site.com"],
    )
    decision = pe.validate("recon_crawl", "http://production-site.com", prod_scope)
    assert decision.allowed is False
    assert "production" in decision.reason.lower()


def test_unauthorized_host_blocked(lab_scope):
    pe = PolicyEngine()
    decision = pe.validate("recon_crawl", "http://external-evil-site.com/exploit", lab_scope)
    assert decision.allowed is False
    assert "allowed_hosts" in decision.reason.lower() or "blocked" in decision.reason.lower()
