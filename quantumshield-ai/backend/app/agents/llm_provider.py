"""
AI Security Orchestrator — LLM Provider Abstraction
Supports: openai | anthropic | google | none (deterministic fallback)
"""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").lower().strip()
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")


class LLMProvider:
    """Abstract LLM provider interface."""

    def __init__(self):
        self.available = False
        self.provider_name = "none"
        self._init_provider()

    def _init_provider(self):
        global LLM_PROVIDER, LLM_API_KEY, LLM_MODEL

        if LLM_PROVIDER == "none" or not LLM_API_KEY:
            logger.info("LLM_PROVIDER=none or no API key. Running in deterministic-only mode.")
            self.available = False
            self.provider_name = "none"
            return

        try:
            if LLM_PROVIDER == "openai":
                from langchain_openai import ChatOpenAI
                model = LLM_MODEL or "gpt-4o-mini"
                self._llm = ChatOpenAI(api_key=LLM_API_KEY, model=model, temperature=0.1)
                self.available = True
                self.provider_name = f"openai/{model}"
                logger.info(f"LLM initialized: {self.provider_name}")

            elif LLM_PROVIDER == "anthropic":
                from langchain_anthropic import ChatAnthropic
                model = LLM_MODEL or "claude-3-5-haiku-20241022"
                self._llm = ChatAnthropic(api_key=LLM_API_KEY, model=model, temperature=0.1)
                self.available = True
                self.provider_name = f"anthropic/{model}"
                logger.info(f"LLM initialized: {self.provider_name}")

            elif LLM_PROVIDER == "google":
                from langchain_google_genai import ChatGoogleGenerativeAI
                model = LLM_MODEL or "gemini-1.5-flash"
                self._llm = ChatGoogleGenerativeAI(google_api_key=LLM_API_KEY, model=model, temperature=0.1)
                self.available = True
                self.provider_name = f"google/{model}"
                logger.info(f"LLM initialized: {self.provider_name}")

            else:
                logger.warning(f"Unknown LLM_PROVIDER='{LLM_PROVIDER}'. Using deterministic mode.")
                self.available = False
                self.provider_name = "none"

        except ImportError as e:
            logger.warning(f"LLM provider import failed: {e}. Using deterministic mode.")
            self.available = False
        except Exception as e:
            logger.error(f"LLM init error: {e}. Using deterministic mode.")
            self.available = False

    async def generate_analysis(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate LLM analysis. Returns empty string if unavailable."""
        if not self.available:
            return ""
        try:
            from langchain_core.messages import HumanMessage
            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            return response.content[:max_tokens * 4]  # Rough token estimate
        except Exception as e:
            logger.error(f"LLM generation error: {e}")
            self.available = False  # Disable on error
            return ""

    async def analyze_findings(self, findings: list, app_map: dict) -> str:
        """Have LLM analyze findings and suggest next steps."""
        if not self.available:
            return ""
        prompt = f"""You are a security analyst. Given these preliminary findings and application map:

Application: {app_map.get('target_url', '')}
Technologies: {app_map.get('technologies', [])}
APIs: {len(app_map.get('apis', []))} endpoints discovered

Preliminary findings:
{[{'type': f.get('type'), 'endpoint': f.get('endpoint'), 'severity': f.get('severity')} for f in findings[:10]]}

Identify the 3 most critical attack surfaces to investigate next and why.
Be concise (3-5 sentences total). Focus on security testing priorities, not remediation."""
        return await self.generate_analysis(prompt, max_tokens=300)

    async def generate_remediation_summary(self, finding: dict) -> str:
        """Generate a brief LLM-enhanced remediation summary."""
        if not self.available:
            return ""
        prompt = f"""Security finding:
Type: {finding.get('category', '')}
Endpoint: {finding.get('endpoint', '')}
Severity: {finding.get('severity', '')}
Description: {finding.get('description', '')}

In 2-3 sentences, explain to a developer:
1. Why this is a vulnerability
2. The one most important fix they should make today"""
        return await self.generate_analysis(prompt, max_tokens=200)


# Global LLM provider instance
llm_provider = LLMProvider()
