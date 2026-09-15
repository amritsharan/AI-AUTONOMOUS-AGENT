"""
AI Security Orchestrator — Main Scan Orchestration Engine
Implements an explicit state machine for security scanning.
State transitions: OBSERVE → ANALYZE → PLAN → POLICY_CHECK → EXECUTE → OBSERVE_RESULT → UPDATE_STATE → VERIFY → FINDING → REMEDIATION → REGRESSION → COMPLETE
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.policy.engine import PolicyEngine, ScopeConfig
from app.agents.llm_provider import llm_provider
from app.classical.recon import run_recon
from app.classical.auth_tests import run_auth_tests
from app.classical.authz_tests import run_authz_tests
from app.classical.injection_tests import run_injection_tests
from app.classical.config_tests import run_config_tests
from app.classical.api_security import audit_api_security
from app.classical.jwt_security import audit_jwt_security
from app.classical.websocket_security import audit_websocket_security
from app.quantum.hybrid_tls import assess_hybrid_pqc_tls
from app.quantum.crypto_discovery import run_crypto_discovery
from app.quantum.shor_demo import assess_shor_threat
from app.quantum.grover_demo import assess_grover_threat
from app.quantum.pqc_assessment import assess_pqc_readiness
from app.engines.core import (
    calculate_risk_score, calculate_quantum_risk_score,
    generate_remediation
)
from app.database.models import (
    Scan, Finding, Evidence, AgentEvent, CryptoAsset, Endpoint,
    Remediation, ScanStatus, FindingStatus, Severity, FindingType
)

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Explicit state machine orchestrator for security scans.
    All security actions pass through the PolicyEngine.
    LLM is used for analysis/planning only — never for action execution.
    """

    def __init__(self, db: AsyncSession, event_callback: Optional[Callable] = None):
        self.db = db
        self.policy = PolicyEngine()
        self.event_callback = event_callback

    async def emit(self, scan_id: str, event_type: str, message: str,
                   agent: str = "SecurityOrchestrator", reason: str = "",
                   tool: str = "", target: str = "", result: str = "",
                   decision: str = "", state: str = "", metadata: dict = None):
        """Emit a scan event to the database and WebSocket clients."""
        logger.info(f"[SCAN:{scan_id}] [{state}] {message}")
        try:
            event = AgentEvent(
                scan_id=scan_id,
                event_type=event_type,
                agent=agent,
                message=message,
                reason=reason or "",
                tool=tool or "",
                target=target or "",
                result=result or "",
                decision=decision or "",
                state=state or "",
                extra_metadata=json.dumps(metadata or {}),
                timestamp=datetime.utcnow(),
            )
            self.db.add(event)
            await self.db.commit()

            if self.event_callback:
                await self.event_callback({
                    "type": "agent_event",
                    "scan_id": scan_id,
                    "event_type": event_type,
                    "agent": agent,
                    "message": message,
                    "state": state,
                    "timestamp": datetime.utcnow().isoformat(),
                })
        except Exception as e:
            logger.error(f"Event emission error: {e}")

    async def run_scan(self, scan: Scan, scope: ScopeConfig):
        """
        Main scan entry point. Runs the complete security assessment.
        """
        scan_id = scan.id
        target_url = scope.target
        findings_created = []
        crypto_assets_created = []

        try:
            # ── STATE: OBSERVE ───────────────────────────────────────────
            await self.emit(scan_id, "state_change", "Scan started. Entering OBSERVE state.", state="OBSERVE")
            await self._update_scan_status(scan, ScanStatus.RUNNING, "OBSERVE")

            # ── Scope validation ─────────────────────────────────────────
            valid, reason = self.policy.validate_scope(scope)
            if not valid:
                await self.emit(scan_id, "error", f"Scope validation failed: {reason}", state="POLICY_CHECK")
                await self._update_scan_status(scan, ScanStatus.FAILED, error=reason)
                return
            await self.emit(scan_id, "policy", "Scope validated successfully.", state="POLICY_CHECK",
                           target=target_url, result="ALLOWED")

            # ── STATE: ANALYZE — Reconnaissance ──────────────────────────
            await self.emit(scan_id, "state_change", "Starting reconnaissance...", state="ANALYZE",
                           agent="ReconEngine", tool="recon_crawl", target=target_url)

            recon_result = await run_recon(
                target_url, scope, self.policy, scan_id,
                event_callback=lambda etype, msg: self.emit(scan_id, etype, msg, agent="ReconEngine", state="ANALYZE")
            )

            # Store application map on scan
            app_map = {
                "target_url": target_url,
                "pages": recon_result.pages,
                "apis": recon_result.apis,
                "technologies": recon_result.technologies,
                "authentication_mechanisms": recon_result.authentication_mechanisms,
                "security_headers": recon_result.security_headers,
                "cors_policy": recon_result.cors_policy,
                "metadata": recon_result.metadata,
            }
            scan.application_map = json.dumps(app_map)
            scan.endpoints_discovered = len(recon_result.pages) + len(recon_result.apis)

            # Store endpoints in DB
            for api in recon_result.apis[:50]:  # Cap at 50
                auth_req = api.get("auth_required", False)
                auth_bool = bool(auth_req) if isinstance(auth_req, bool) else (str(auth_req).lower() in ("true", "1", "yes", "post only", "required"))
                ep = Endpoint(
                    scan_id=scan_id,
                    path=api.get("path", "/"),
                    method=api.get("methods", ["GET"])[0],
                    auth_required=auth_bool,
                    notes=str(api.get("notes", "")),
                )
                self.db.add(ep)

            await self.db.commit()
            await self.emit(scan_id, "recon_complete",
                           f"Reconnaissance complete: {scan.endpoints_discovered} endpoints, {len(recon_result.technologies)} technologies detected.",
                           state="OBSERVE_RESULT", result=f"{scan.endpoints_discovered} endpoints")

            # ── STATE: PLAN ───────────────────────────────────────────────
            await self.emit(scan_id, "state_change", "Analyzing application map and planning tests...", state="PLAN",
                           agent="SecurityPlanner")

            # LLM analysis (if available) — non-blocking
            if llm_provider.available:
                llm_analysis = await llm_provider.analyze_findings([], app_map)
                if llm_analysis:
                    await self.emit(scan_id, "llm_analysis", f"AI Analysis: {llm_analysis[:300]}",
                                   agent="AISecurityPlanner", state="PLAN")

            # ── Run all test modules concurrently ─────────────────────────
            await self.emit(scan_id, "state_change", "Executing security tests (classical + quantum)...", state="EXECUTE")

            tasks = []
            if scan.scan_type in ("classical", "full"):
                tasks.extend([
                    self._run_auth_module(scan, scope, target_url),
                    self._run_authz_module(scan, scope, target_url),
                    self._run_injection_module(scan, scope, target_url),
                    self._run_config_module(scan, scope, target_url),
                    self._run_api_security_module(scan, scope, target_url),
                    self._run_jwt_module(scan, scope, target_url),
                    self._run_websocket_module(scan, scope, target_url),
                ])
            if scan.scan_type in ("quantum", "full"):
                tasks.append(self._run_quantum_module(scan, scope, target_url))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            all_raw_findings = []
            all_crypto_assets = []
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"Module error: {r}")
                    continue
                if isinstance(r, dict):
                    all_raw_findings.extend(r.get("findings", []))
                    all_crypto_assets.extend(r.get("crypto_assets", []))

            # ── STATE: VERIFY ─────────────────────────────────────────────
            await self.emit(scan_id, "state_change",
                           f"Verification phase: checking {len(all_raw_findings)} potential findings...",
                           state="VERIFY")

            confirmed_findings = []
            for raw in all_raw_findings:
                if raw.get("status") == "SUSPICIOUS" and raw.get("confidence", 0) >= 0.7:
                    # Create and confirm finding
                    finding = await self._create_finding(scan_id, raw)
                    if finding:
                        confirmed_findings.append(finding)
                        findings_created.append(finding)

            # ── Store crypto assets ───────────────────────────────────────
            for asset in all_crypto_assets:
                ca = CryptoAsset(
                    scan_id=scan_id,
                    algorithm=asset.algorithm,
                    key_size=asset.key_size,
                    protocol=asset.protocol,
                    endpoint=asset.endpoint,
                    usage=asset.usage,
                    classical_security=asset.classical_security,
                    quantum_security=asset.quantum_security,
                    quantum_attack=asset.quantum_attack,
                    pqc_status=asset.pqc_status,
                    risk_score=asset.risk_score,
                    details=json.dumps(asset.details),
                )
                self.db.add(ca)
                crypto_assets_created.append(asset)

            scan.quantum_assets_found = len(crypto_assets_created)
            await self.db.commit()

            # ── STATE: FINDING ────────────────────────────────────────────
            await self.emit(scan_id, "state_change",
                           f"Findings identified: {len(confirmed_findings)} confirmed.",
                           state="FINDING")

            # ── STATE: REMEDIATION ────────────────────────────────────────
            await self.emit(scan_id, "state_change", "Generating remediation recommendations...",
                           state="REMEDIATION")

            for finding in confirmed_findings:
                await self._generate_remediation(finding)

            # ── Calculate scores ──────────────────────────────────────────
            findings_data = [
                {"severity": f.severity, "confidence": f.confidence}
                for f in confirmed_findings
            ]
            scan.security_score = self._calculate_security_score(findings_data)

            crypto_data = [
                {"algorithm": a.algorithm, "key_size": a.key_size,
                 "quantum_security": a.quantum_security, "usage": a.usage}
                for a in all_crypto_assets
            ]
            quantum_result = calculate_quantum_risk_score(crypto_data)
            scan.quantum_score = quantum_result["quantum_score"]
            scan.pqc_readiness = quantum_result.get("pqc_readiness_pct")

            # ── PQC Assessment ────────────────────────────────────────────
            pqc_result = assess_pqc_readiness(crypto_data)
            scan.pqc_readiness = pqc_result.get("pqc_readiness_score")

            # ── Finalize ──────────────────────────────────────────────────
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.current_state = "COMPLETE"
            scan.completed_tests = scan.total_tests
            await self.db.commit()

            await self.emit(
                scan_id, "scan_complete",
                f"Scan complete! Security Score: {scan.security_score:.0f}/100 | "
                f"Quantum Score: {scan.quantum_score:.0f}/100 | "
                f"Findings: {len(confirmed_findings)} confirmed | "
                f"Crypto Assets: {len(crypto_assets_created)}",
                state="COMPLETE",
                agent="SecurityOrchestrator",
                result="COMPLETED",
            )

        except asyncio.CancelledError:
            await self._update_scan_status(scan, ScanStatus.CANCELLED)
            raise
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            await self._update_scan_status(scan, ScanStatus.FAILED, error=str(e))
            await self.emit(scan_id, "error", f"Scan failed: {str(e)[:200]}", state="ERROR")

    async def _run_auth_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run authentication tests."""
        await self.emit(scan.id, "module_start", "Starting authentication security tests.",
                       agent="AuthTestEngine", tool="auth_test", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 6
        try:
            results = await run_auth_tests(
                target_url, scope, self.policy, scan.id,
                event_callback=lambda etype, msg: self.emit(scan.id, etype, msg, agent="AuthTestEngine", state="EXECUTE")
            )
            await self.emit(scan.id, "module_complete",
                           f"Authentication tests: {len([r for r in results if r.status == 'SUSPICIOUS'])} suspicious findings.",
                           agent="AuthTestEngine", state="OBSERVE_RESULT")
            return {"findings": [
                {
                    "status": r.status, "confidence": r.confidence,
                    "title": f"Auth: {r.test_name}", "category": "AUTHENTICATION",
                    "severity": r.severity, "endpoint": r.endpoint,
                    "description": r.observation, "evidence": r.evidence,
                    "finding_type": "CLASSICAL",
                }
                for r in results if r.status == "SUSPICIOUS"
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"Auth tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_authz_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run authorization tests."""
        await self.emit(scan.id, "module_start", "Starting authorization/IDOR tests.",
                       agent="AuthzTestEngine", tool="authz_test_idor", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 5
        try:
            results = await run_authz_tests(
                target_url, scope, self.policy, scan.id,
                event_callback=lambda etype, msg: self.emit(scan.id, etype, msg, agent="AuthzTestEngine", state="EXECUTE")
            )
            return {"findings": [
                {
                    "status": r.status, "confidence": r.confidence,
                    "title": f"AuthZ: {r.test_name}", "category": r.finding_type,
                    "severity": r.severity, "endpoint": r.endpoint,
                    "description": r.observation, "evidence": r.evidence,
                    "finding_type": "CLASSICAL",
                }
                for r in results if r.status == "SUSPICIOUS"
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"AuthZ tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_injection_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run injection tests."""
        await self.emit(scan.id, "module_start", "Starting injection security tests.",
                       agent="InjectionTestEngine", tool="injection_test_sql", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 4
        try:
            results = await run_injection_tests(
                target_url, scope, self.policy, scan.id,
                event_callback=lambda etype, msg: self.emit(scan.id, etype, msg, agent="InjectionTestEngine", state="EXECUTE")
            )
            return {"findings": [
                {
                    "status": r.status, "confidence": r.confidence,
                    "title": f"Injection: {r.test_name}", "category": r.injection_type or "INJECTION",
                    "severity": r.severity, "endpoint": r.endpoint,
                    "description": r.observation, "evidence": r.evidence,
                    "finding_type": "CLASSICAL",
                }
                for r in results if r.status == "SUSPICIOUS"
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"Injection tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_config_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run configuration security tests."""
        await self.emit(scan.id, "module_start", "Starting configuration security tests.",
                       agent="ConfigTestEngine", tool="config_test", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 6
        try:
            results = await run_config_tests(
                target_url, scope, self.policy, scan.id,
                event_callback=lambda etype, msg: self.emit(scan.id, etype, msg, agent="ConfigTestEngine", state="EXECUTE")
            )
            return {"findings": [
                {
                    "status": r.status, "confidence": r.confidence,
                    "title": f"Config: {r.test_name}", "category": "CONFIGURATION",
                    "severity": r.severity, "endpoint": r.endpoint,
                    "description": r.observation, "evidence": r.evidence,
                    "finding_type": "CLASSICAL",
                }
                for r in results if r.status == "SUSPICIOUS"
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"Config tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_api_security_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run OpenAPI and GraphQL security audits."""
        await self.emit(scan.id, "module_start", "Starting OpenAPI & GraphQL security audit.",
                       agent="APISecurityEngine", tool="api_security_audit", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 4
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                raw_findings = await audit_api_security(client, target_url)
            return {"findings": [
                {
                    "status": "SUSPICIOUS", "confidence": 0.85,
                    "title": f.get("title"), "category": f.get("type", "API_SECURITY"),
                    "severity": f.get("severity", "MEDIUM"), "endpoint": f.get("endpoint", "/api"),
                    "description": f.get("description"), "evidence": f.get("evidence"),
                    "finding_type": "CLASSICAL",
                }
                for f in raw_findings
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"API security tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_jwt_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run JSON Web Token (JWT) security testing."""
        await self.emit(scan.id, "module_start", "Starting JWT authentication and signature audit.",
                       agent="JWTSecurityEngine", tool="jwt_signature_audit", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 3
        try:
            endpoints = ["/api/users/1/profile", "/api/admin/system-status", "/api/orders"]
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                raw_findings = await audit_jwt_security(client, target_url, endpoints)
            return {"findings": [
                {
                    "status": "SUSPICIOUS", "confidence": 0.90,
                    "title": f.get("title"), "category": f.get("type", "JWT_SECURITY"),
                    "severity": f.get("severity", "HIGH"), "endpoint": f.get("endpoint", "/api/auth"),
                    "description": f.get("description"), "evidence": f.get("evidence"),
                    "finding_type": "CLASSICAL",
                }
                for f in raw_findings
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"JWT security tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_websocket_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run Target WebSocket & CSWSH security tests."""
        await self.emit(scan.id, "module_start", "Auditing target WebSocket endpoints and CSWSH defenses.",
                       agent="WebSocketEngine", tool="websocket_audit", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 2
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
                raw_findings = await audit_websocket_security(target_url, client)
            return {"findings": [
                {
                    "status": "SUSPICIOUS", "confidence": 0.85,
                    "title": f.get("title"), "category": f.get("type", "WEBSOCKET_SECURITY"),
                    "severity": f.get("severity", "HIGH"), "endpoint": f.get("endpoint", "/ws"),
                    "description": f.get("description"), "evidence": f.get("evidence"),
                    "finding_type": "CLASSICAL",
                }
                for f in raw_findings
            ]}
        except Exception as e:
            await self.emit(scan.id, "module_error", f"WebSocket tests failed: {e}", state="EXECUTE")
            return {"findings": []}

    async def _run_quantum_module(self, scan: Scan, scope: ScopeConfig, target_url: str) -> dict:
        """Run quantum security analysis."""
        await self.emit(scan.id, "module_start", "Starting quantum cryptographic analysis.",
                       agent="QuantumEngine", tool="quantum_crypto_discovery", target=target_url, state="EXECUTE")
        scan.total_tests = (scan.total_tests or 0) + 4
        findings = []
        crypto_assets = []

        try:
            # Crypto discovery
            assets = await run_crypto_discovery(
                target_url, scope, self.policy, scan.id,
                event_callback=lambda etype, msg: self.emit(scan.id, etype, msg, agent="QuantumEngine", state="EXECUTE")
            )
            crypto_assets = assets

            # Shor assessment for each vulnerable asset
            for asset in assets:
                if asset.quantum_attack == "shor":
                    assessment = assess_shor_threat(asset.algorithm, asset.key_size)
                    await self.emit(
                        scan.id, "quantum_assessment",
                        f"Shor analysis: {asset.algorithm} — Shor applicable: {assessment.shor_applicable}, Currently breakable: {assessment.current_practical_break}",
                        agent="QuantumEngine", state="EXECUTE"
                    )
                    if assessment.shor_applicable and not assessment.quantum_resistant:
                        findings.append({
                            "status": "SUSPICIOUS",
                            "confidence": 0.95,
                            "title": f"Quantum: {asset.algorithm} vulnerable to Shor's algorithm",
                            "category": "QUANTUM_VULNERABILITY",
                            "severity": "MEDIUM",  # Medium — not exploitable today
                            "endpoint": asset.endpoint,
                            "description": (
                                f"{asset.algorithm} uses {assessment.mathematical_problem}. "
                                f"Shor's algorithm can solve this in polynomial time on a CRQC. "
                                f"Current practical risk: LOW (no CRQC exists today). "
                                f"Future risk: HIGH when CRQC becomes available. "
                                f"Estimated qubits needed: {assessment.estimated_qubits_required}."
                            ),
                            "evidence": {
                                "quantum_attack": "shor",
                                "mathematical_problem": assessment.mathematical_problem,
                                "classical_complexity": assessment.classical_complexity,
                                "quantum_complexity": assessment.quantum_complexity,
                                "current_practical_break": assessment.current_practical_break,
                                "recommendation": assessment.recommendation,
                            },
                            "finding_type": "QUANTUM",
                        })

                elif asset.quantum_attack == "grover":
                    grover_assess = assess_grover_threat(asset.algorithm, asset.key_size)
                    await self.emit(
                        scan.id, "quantum_assessment",
                        f"Grover analysis: {asset.algorithm} — Effective quantum security: {grover_assess.effective_quantum_security_bits} bits",
                        agent="QuantumEngine", state="EXECUTE"
                    )
                    if not grover_assess.is_sufficient:
                        findings.append({
                            "status": "SUSPICIOUS",
                            "confidence": 0.9,
                            "title": f"Quantum: {asset.algorithm} has reduced security under Grover",
                            "category": "QUANTUM_GROVER",
                            "severity": "LOW",
                            "endpoint": asset.endpoint,
                            "description": grover_assess.recommendation,
                            "evidence": {
                                "quantum_attack": "grover",
                                "classical_security_bits": asset.key_size,
                                "quantum_security_bits": grover_assess.effective_quantum_security_bits,
                                "is_sufficient": grover_assess.is_sufficient,
                            },
                            "finding_type": "QUANTUM",
                        })

            await self.emit(scan.id, "quantum_complete",
                           f"Quantum analysis complete: {len(assets)} crypto assets, {len(findings)} quantum findings.",
                           agent="QuantumEngine", state="OBSERVE_RESULT")

        except Exception as e:
            await self.emit(scan.id, "module_error", f"Quantum module failed: {e}", state="EXECUTE")

        return {"findings": findings, "crypto_assets": crypto_assets}

    async def _create_finding(self, scan_id: str, raw: dict) -> Optional[Finding]:
        """Create a confirmed finding in the database."""
        try:
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFORMATIONAL": Severity.INFORMATIONAL,
            }
            severity = severity_map.get(raw.get("severity", "MEDIUM").upper(), Severity.MEDIUM)
            finding_type_map = {
                "CLASSICAL": FindingType.CLASSICAL,
                "QUANTUM": FindingType.QUANTUM,
            }
            finding_type = finding_type_map.get(raw.get("finding_type", "CLASSICAL").upper(), FindingType.CLASSICAL)

            risk_score = calculate_risk_score(
                raw.get("severity", "MEDIUM"),
                raw.get("confidence", 0.7),
            )

            finding = Finding(
                scan_id=scan_id,
                title=raw.get("title", "Security Finding"),
                category=raw.get("category", "UNKNOWN"),
                finding_type=finding_type,
                severity=severity,
                confidence=raw.get("confidence", 0.7),
                endpoint=raw.get("endpoint", ""),
                description=raw.get("description", ""),
                risk_score=risk_score,
                status=FindingStatus.CONFIRMED,
                last_verified=datetime.utcnow(),
            )
            self.db.add(finding)
            await self.db.flush()  # Get the ID

            # Store evidence
            ev_data = raw.get("evidence", {})
            if ev_data:
                evidence = Evidence(
                    finding_id=finding.id,
                    test_name=raw.get("title", ""),
                    endpoint=raw.get("endpoint", ""),
                    observation=raw.get("description", ""),
                    confidence=raw.get("confidence", 0.7),
                    is_confirmed=True,
                    raw_data=json.dumps(ev_data),
                )
                self.db.add(evidence)

            await self.db.commit()
            await self.emit(scan_id, "finding_confirmed",
                           f"CONFIRMED: [{severity.value}] {raw.get('title', '')} at {raw.get('endpoint', '')}",
                           agent="VerificationEngine", state="FINDING",
                           result=f"risk_score={risk_score}")
            return finding

        except Exception as e:
            logger.error(f"Finding creation error: {e}")
            return None

    async def _generate_remediation(self, finding: Finding):
        """Generate and store remediation for a finding."""
        try:
            rem_data = generate_remediation(
                finding.category,
                finding.endpoint or "",
                llm_available=llm_provider.available,
            )
            rem = Remediation(
                finding_id=finding.id,
                explanation=rem_data.get("explanation", ""),
                root_cause=rem_data.get("root_cause", ""),
                recommended_fix=rem_data.get("recommended_fix", ""),
                code_example=rem_data.get("code_example", ""),
                priority=rem_data.get("priority", "MEDIUM"),
                regression_test_description=rem_data.get("regression_test_description", ""),
            )
            self.db.add(rem)
            await self.db.commit()
        except Exception as e:
            logger.error(f"Remediation generation error: {e}")

    async def _update_scan_status(self, scan: Scan, status: ScanStatus,
                                  state: str = "", error: str = ""):
        try:
            scan.status = status
            if state:
                scan.current_state = state
            if error:
                scan.error_message = error[:1000]
            if status == ScanStatus.RUNNING and not scan.started_at:
                scan.started_at = datetime.utcnow()
            await self.db.commit()
        except Exception as e:
            logger.error(f"Scan status update error: {e}")

    def _calculate_security_score(self, findings: list) -> float:
        """Calculate overall security score (100 = perfect, 0 = all critical)."""
        if not findings:
            return 85.0  # No findings = good but not perfect (unknown unknowns)

        deductions = {
            "CRITICAL": 20.0,
            "HIGH": 10.0,
            "MEDIUM": 5.0,
            "LOW": 2.0,
            "INFORMATIONAL": 0.5,
        }

        total_deduction = 0.0
        for f in findings:
            severity = f.get("severity", "LOW").upper()
            conf = f.get("confidence", 0.7)
            total_deduction += deductions.get(severity, 2.0) * conf

        score = max(0.0, 100.0 - total_deduction)
        return round(score, 1)
