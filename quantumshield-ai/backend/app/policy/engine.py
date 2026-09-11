"""
QuantumShield AI — Policy Engine
================================
This is a DETERMINISTIC policy engine. The LLM NEVER controls this code path.
Every security action MUST be validated through PolicyEngine.validate() before execution.

The engine enforces:
- Target hostname/IP allow-listing
- Environment restrictions (lab/staging only)
- Action allow-listing
- Rate limiting
- Destructive test gating
- External target blocking
- Production environment blocking
"""
import re
import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class ScopeConfig:
    """Scope configuration for a security scan."""
    target: str
    environment: str = "lab"
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8080, 8000, 3000])
    destructive_tests: bool = False
    max_requests_per_minute: int = 60
    test_account_username: str = ""
    test_account_password: str = ""
    allowed_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "environment": self.environment,
            "allowed_hosts": self.allowed_hosts,
            "allowed_ports": self.allowed_ports,
            "destructive_tests": self.destructive_tests,
            "max_requests_per_minute": self.max_requests_per_minute,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeConfig":
        return cls(
            target=data.get("target", ""),
            environment=data.get("environment", "lab"),
            allowed_hosts=data.get("allowed_hosts", []),
            allowed_ports=data.get("allowed_ports", [80, 443, 8080, 8000, 3000]),
            destructive_tests=data.get("destructive_tests", False),
            max_requests_per_minute=data.get("max_requests_per_minute", 60),
            test_account_username=data.get("test_account_username", ""),
            test_account_password=data.get("test_account_password", ""),
            allowed_actions=data.get("allowed_actions", []),
        )


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""
    allowed: bool
    reason: str
    action: str
    target: str


# Environments that BLOCK scanning
BLOCKED_ENVIRONMENTS = {"production", "prod", "live"}

# Actions that are NEVER allowed regardless of scope
NEVER_ALLOWED_ACTIONS = {
    "shell_exec",
    "arbitrary_command",
    "delete_production_data",
    "exploit_live_system",
    "brute_force_unlimited",
    "ddos",
    "destroy_data",
}

# Actions that require explicit destructive_tests=True
DESTRUCTIVE_ACTIONS = {
    "delete_test_data",
    "modify_database",
    "upload_webshell_test",
}

# Valid security test action names
VALID_TEST_ACTIONS = {
    "http_request",
    "recon_crawl",
    "auth_test",
    "authz_test_idor",
    "injection_test_sql",
    "injection_test_xss",
    "injection_test_ssti",
    "api_security_test",
    "config_test",
    "header_check",
    "cookie_check",
    "cors_test",
    "tls_check",
    "file_upload_test",
    "rate_limit_test",
    "quantum_crypto_discovery",
    "shor_demo",
    "grover_demo",
    "pqc_assessment",
    "verification_test",
    "regression_test",
    "report_generate",
}


class PolicyEngine:
    """
    Deterministic policy engine for security action authorization.

    CRITICAL: This class must NEVER be subclassed or overridden by LLM-generated code.
    All validation is purely algorithmic.
    """

    def __init__(self):
        # Rate limiting: track request counts per (scan_id, minute_window)
        self._request_counts: dict[str, list[float]] = defaultdict(list)

    def validate(self, action: str, target: str, scope: ScopeConfig, scan_id: str = "") -> PolicyDecision:
        """
        Validate a security action against the scope policy.

        Args:
            action: The action type being requested (must be in VALID_TEST_ACTIONS)
            target: The URL or host being targeted
            scope: The scope configuration for this scan
            scan_id: Optional scan ID for rate limiting

        Returns:
            PolicyDecision with allowed=True/False and reason
        """
        logger.debug(f"PolicyEngine.validate: action={action} target={target}")

        # 1. Action must be a known valid test action
        if action in NEVER_ALLOWED_ACTIONS:
            return PolicyDecision(
                allowed=False,
                reason=f"Action '{action}' is explicitly prohibited by security policy.",
                action=action,
                target=target,
            )

        if action not in (VALID_TEST_ACTIONS | DESTRUCTIVE_ACTIONS):
            return PolicyDecision(
                allowed=False,
                reason=f"Unknown action '{action}'. Only predefined security test actions are permitted.",
                action=action,
                target=target,
            )

        # 2. Block destructive actions unless explicitly enabled
        if action in DESTRUCTIVE_ACTIONS and not scope.destructive_tests:
            return PolicyDecision(
                allowed=False,
                reason=f"Destructive action '{action}' is disabled. Enable destructive_tests in scope to allow.",
                action=action,
                target=target,
            )

        # 3. Environment check
        env_check = self._check_environment(scope.environment)
        if not env_check["allowed"]:
            return PolicyDecision(
                allowed=False,
                reason=env_check["reason"],
                action=action,
                target=target,
            )

        # 4. Target host/port validation
        host_check = self._check_target_host(target, scope)
        if not host_check["allowed"]:
            return PolicyDecision(
                allowed=False,
                reason=host_check["reason"],
                action=action,
                target=target,
            )

        # 5. Rate limiting
        rate_check = self._check_rate_limit(scan_id or "default", scope.max_requests_per_minute)
        if not rate_check["allowed"]:
            return PolicyDecision(
                allowed=False,
                reason=rate_check["reason"],
                action=action,
                target=target,
            )

        return PolicyDecision(
            allowed=True,
            reason="Policy check passed.",
            action=action,
            target=target,
        )

    def validate_scope(self, scope: ScopeConfig) -> tuple[bool, str]:
        """Validate a scope configuration object itself."""
        if not scope.target:
            return False, "Scope target URL is required."

        parsed = self._parse_url(scope.target)
        if not parsed:
            return False, f"Invalid target URL: {scope.target}"

        if scope.environment in BLOCKED_ENVIRONMENTS:
            return False, f"Environment '{scope.environment}' is not allowed for security testing."

        if scope.max_requests_per_minute > 300:
            return False, "max_requests_per_minute cannot exceed 300 for safety."

        if not scope.allowed_hosts:
            # Derive from target URL
            scope.allowed_hosts = [parsed["host"]]

        return True, "Scope is valid."

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _check_environment(self, environment: str) -> dict:
        env = environment.lower().strip()
        if env in BLOCKED_ENVIRONMENTS:
            return {
                "allowed": False,
                "reason": f"Environment '{env}' is blocked. Only lab/staging environments are allowed."
            }
        return {"allowed": True, "reason": "Environment OK"}

    def _check_target_host(self, target: str, scope: ScopeConfig) -> dict:
        parsed = self._parse_url(target)
        if not parsed:
            return {"allowed": False, "reason": f"Cannot parse target URL: {target}"}

        host = parsed["host"]
        port = parsed["port"]

        # Block obviously external targets unless explicitly allowed
        if self._is_public_ip_or_external(host):
            # Only allow if explicitly in allowed_hosts
            if host not in scope.allowed_hosts:
                return {
                    "allowed": False,
                    "reason": f"External target '{host}' is not in allowed_hosts scope. Only authorized lab/internal targets are permitted."
                }

        # Check against allowed hosts
        if scope.allowed_hosts:
            host_allowed = any(
                host == ah or host.endswith("." + ah)
                for ah in scope.allowed_hosts
            )
            if not host_allowed:
                return {
                    "allowed": False,
                    "reason": f"Host '{host}' is not in the approved allowed_hosts list: {scope.allowed_hosts}"
                }

        # Check port
        if port and scope.allowed_ports and port not in scope.allowed_ports:
            return {
                "allowed": False,
                "reason": f"Port {port} is not in allowed_ports: {scope.allowed_ports}"
            }

        return {"allowed": True, "reason": "Host/port OK"}

    def _check_rate_limit(self, scan_id: str, max_rpm: int) -> dict:
        now = time.time()
        window_start = now - 60.0  # 1-minute window

        # Clean old entries
        self._request_counts[scan_id] = [
            t for t in self._request_counts[scan_id] if t > window_start
        ]

        count = len(self._request_counts[scan_id])
        if count >= max_rpm:
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {count}/{max_rpm} requests in the last minute."
            }

        self._request_counts[scan_id].append(now)
        return {"allowed": True, "reason": "Rate limit OK"}

    def _parse_url(self, url: str) -> Optional[dict]:
        try:
            # If no scheme, add one for parsing
            if not url.startswith(("http://", "https://", "ws://", "wss://")):
                url = "http://" + url
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme in ("https", "wss") else 80
            return {"host": host, "port": port, "scheme": parsed.scheme, "path": parsed.path}
        except Exception:
            return None

    def _is_public_ip_or_external(self, host: str) -> bool:
        """Check if the host looks like a public/external target."""
        # Private IP ranges and localhost are OK
        private_patterns = [
            r"^localhost$",
            r"^127\.",
            r"^10\.",
            r"^172\.(1[6-9]|2\d|3[01])\.",
            r"^192\.168\.",
            r"^::1$",
            r"^0\.0\.0\.0$",
        ]
        for pattern in private_patterns:
            if re.match(pattern, host):
                return False

        # Docker service names (no dots, no IP-like) are internal
        if "." not in host:
            return False  # e.g., "vulnerable-app", "db", "redis"

        # Has dots but doesn't match private ranges → treat as potentially external
        # Check if it looks like a dotted hostname (not an IP)
        # Public domain names like "example.com" → external
        return True

    def reset_rate_limits(self, scan_id: str = ""):
        """Reset rate limit counters (for testing)."""
        if scan_id:
            self._request_counts.pop(scan_id, None)
        else:
            self._request_counts.clear()


# Global singleton
policy_engine = PolicyEngine()
