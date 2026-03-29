"""
report.py — Post-incident report generator.

After a pause fires, Claude generates a structured incident report
covering: attack timeline, funds protected, attack classification,
and recommended remediation steps.
"""

import json
import logging
from datetime import datetime, timezone

import anthropic

logger = logging.getLogger("guardian.report")


REPORT_SYSTEM_PROMPT = """You are Protocol Guardian's incident analyst.
Generate a professional security incident report after a DeFi protocol emergency pause.
Be specific, technical, and actionable. Write for a protocol security team.
Respond ONLY with valid JSON."""


class ReportGenerator:
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)

    async def generate(self, ctx, decision, pause_result: dict) -> dict:
        """Generate a post-incident report after a pause fires."""
        logger.info("Generating post-incident report...")

        prompt = f"""Generate a post-incident security report for this DeFi exploit attempt.

INCIDENT SUMMARY:
- Trigger tx: {ctx.tx_hash}
- Attacker address: {decision.suspected_attacker}
- Attack type: {decision.attack_type}
- AI confidence: {decision.confidence}%
- Estimated funds at risk: ${decision.estimated_loss_usd:,}
- Protocol paused: {pause_result.get('success', False)}
- Pause tx: {pause_result.get('pause_tx_hash', 'N/A')}
- Agent rationale: {decision.rationale}

TRANSACTION DATA:
- From: {ctx.from_addr}
- To: {ctx.to_addr}
- Value: {(ctx.value_wei or 0) / 1e18:.6f} ETH
- Input: {(ctx.input_data or '')[:200]}
- Flash loan detected: {ctx.is_flash_loan}

Respond with JSON:
{{
  "title": "<incident title>",
  "severity": "<Critical|High|Medium>",
  "executive_summary": "<2-3 sentence summary for non-technical stakeholders>",
  "attack_timeline": ["<step 1>", "<step 2>", ...],
  "funds_protected_usd": <integer>,
  "attack_vector": "<technical description>",
  "affected_components": ["<component>", ...],
  "remediation_steps": ["<step>", ...],
  "similar_past_exploits": ["<exploit name>", ...],
  "recommended_monitoring": ["<rule>", ...]
}}"""

        response = self.client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1500,
            system=REPORT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        try:
            report = json.loads(raw)
        except json.JSONDecodeError:
            report = {
                "title": f"Incident Report — {decision.attack_type}",
                "severity": "High",
                "executive_summary": decision.rationale,
                "attack_timeline": ["See raw AI response for details"],
                "funds_protected_usd": decision.estimated_loss_usd,
                "raw_response": raw,
            }

        report["generated_at"] = datetime.now(timezone.utc).isoformat()
        report["trigger_tx"] = ctx.tx_hash
        report["pause_tx"] = pause_result.get("pause_tx_hash")

        # Pretty print to console for demo
        print("\n" + "="*60)
        print("📋 POST-INCIDENT REPORT")
        print("="*60)
        print(f"Title:     {report.get('title')}")
        print(f"Severity:  {report.get('severity')}")
        print(f"Summary:   {report.get('executive_summary')}")
        print(f"Protected: ${report.get('funds_protected_usd', 0):,}")
        print("\nAttack Timeline:")
        for i, step in enumerate(report.get("attack_timeline", []), 1):
            print(f"  {i}. {step}")
        print("\nRemediation Steps:")
        for step in report.get("remediation_steps", []):
            print(f"  • {step}")
        print("="*60 + "\n")

        return report
