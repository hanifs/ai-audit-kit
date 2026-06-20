"""
Module 3 — Governance Scorecard
================================
NIST AI RMF · OWASP LLM Top 10 · Local heuristic analysis

Scores an AI policy document or system prompt against:
  - NIST AI RMF (GOVERN / MAP / MEASURE / MANAGE)
  - OWASP LLM Top 10 mitigations

Pure stdlib — no API calls, no LLM, no dependencies beyond rich.

Usage (via CLI):
  python llm_audit.py --module governance --file policy.txt
  python llm_audit.py --module governance --input "Our AI system..."
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Rich ──────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


# ── Scoring rubric ────────────────────────────────────────────────────────────
#
# Each check has:
#   id          — unique identifier
#   framework   — NIST AI RMF function or OWASP
#   category    — subcategory label shown in the scorecard
#   weight      — importance multiplier (1–3)
#   keywords    — list of term groups; a check passes if ANY group matches
#                 a group is a list of synonyms — ALL must appear (AND logic)
#                 groups are OR-ed together
#   description — what this check validates

CHECKS: list[dict[str, Any]] = [

    # ══ NIST AI RMF — GOVERN ══════════════════════════════════════════════════

    {
        "id": "GOV-1.1-a",
        "framework": "NIST GOVERN",
        "category": "GOVERN 1.1 — Policy & Scope",
        "weight": 3,
        "keywords": [
            ["policy", "ai"],
            ["governance", "framework"],
            ["guidelines", "artificial intelligence"],
            ["principles", "responsible"],
        ],
        "description": "Document establishes an AI policy or governance framework",
    },
    {
        "id": "GOV-1.1-b",
        "framework": "NIST GOVERN",
        "category": "GOVERN 1.1 — Intended Use",
        "weight": 2,
        "keywords": [
            ["intended use"],
            ["use case"],
            ["scope", "application"],
            ["purpose", "system"],
            ["designed to"],
        ],
        "description": "Document defines intended use or system scope",
    },
    {
        "id": "GOV-1.2-a",
        "framework": "NIST GOVERN",
        "category": "GOVERN 1.2 — Accountability",
        "weight": 3,
        "keywords": [
            ["accountab"],
            ["responsible", "owner"],
            ["approval", "authority"],
            ["designated", "role"],
            ["responsible party"],
        ],
        "description": "Document assigns accountability or ownership",
    },
    {
        "id": "GOV-1.2-b",
        "framework": "NIST GOVERN",
        "category": "GOVERN 1.2 — Review Cycle",
        "weight": 2,
        "keywords": [
            ["review", "annually"],
            ["review", "quarterly"],
            ["periodic", "review"],
            ["updated", "regularly"],
            ["revision", "schedule"],
        ],
        "description": "Document specifies a review or update cadence",
    },
    {
        "id": "GOV-1.3",
        "framework": "NIST GOVERN",
        "category": "GOVERN 1.3 — Risk Tolerance",
        "weight": 2,
        "keywords": [
            ["risk tolerance"],
            ["risk appetite"],
            ["acceptable risk"],
            ["risk threshold"],
            ["risk level"],
        ],
        "description": "Document articulates organisational risk tolerance for AI",
    },
    {
        "id": "GOV-2.1",
        "framework": "NIST GOVERN",
        "category": "GOVERN 2.1 — Roles & Responsibilities",
        "weight": 2,
        "keywords": [
            ["roles", "responsibilities"],
            ["raci"],
            ["team", "responsible"],
            ["stakeholder", "role"],
            ["assigned", "responsible"],
        ],
        "description": "Document defines AI-related roles and responsibilities",
    },
    {
        "id": "GOV-3.1",
        "framework": "NIST GOVERN",
        "category": "GOVERN 3.1 — Workforce Training",
        "weight": 1,
        "keywords": [
            ["training", "staff"],
            ["awareness", "program"],
            ["education", "ai"],
            ["workforce", "training"],
            ["employee", "training"],
        ],
        "description": "Document addresses workforce AI training or awareness",
    },
    {
        "id": "GOV-5.1",
        "framework": "NIST GOVERN",
        "category": "GOVERN 5.1 — Third-Party Risk",
        "weight": 2,
        "keywords": [
            ["third.party", "risk"],
            ["vendor", "assessment"],
            ["supplier", "ai"],
            ["third.party", "model"],
            ["external", "provider"],
        ],
        "description": "Document addresses third-party or vendor AI risk",
    },

    # ══ NIST AI RMF — MAP ═════════════════════════════════════════════════════

    {
        "id": "MAP-1.1",
        "framework": "NIST MAP",
        "category": "MAP 1.1 — Context & Use",
        "weight": 2,
        "keywords": [
            ["deployment", "context"],
            ["operational", "environment"],
            ["use", "context"],
            ["application", "domain"],
        ],
        "description": "Document describes AI deployment context",
    },
    {
        "id": "MAP-2.2",
        "framework": "NIST MAP",
        "category": "MAP 2.2 — Risk Categorisation",
        "weight": 2,
        "keywords": [
            ["risk", "categor"],
            ["high.risk", "ai"],
            ["risk", "classif"],
            ["risk", "tier"],
            ["impact", "level"],
        ],
        "description": "Document categorises AI systems by risk level",
    },
    {
        "id": "MAP-5.1",
        "framework": "NIST MAP",
        "category": "MAP 5.1 — Privacy Risk",
        "weight": 3,
        "keywords": [
            ["privacy"],
            ["personal data"],
            ["pii"],
            ["data protection"],
            ["gdpr"],
            ["hipaa"],
            ["personally identifiable"],
        ],
        "description": "Document addresses privacy or data protection risk",
    },
    {
        "id": "MAP-5.2",
        "framework": "NIST MAP",
        "category": "MAP 5.2 — Bias & Fairness",
        "weight": 2,
        "keywords": [
            ["bias"],
            ["fairness"],
            ["equit"],
            ["discriminat"],
            ["demographic"],
            ["disparate impact"],
        ],
        "description": "Document addresses AI bias or fairness",
    },

    # ══ NIST AI RMF — MEASURE ═════════════════════════════════════════════════

    {
        "id": "MEA-2.1",
        "framework": "NIST MEASURE",
        "category": "MEASURE 2.1 — Evaluation Plan",
        "weight": 2,
        "keywords": [
            ["evaluat", "plan"],
            ["testing", "framework"],
            ["benchmark"],
            ["performance", "metric"],
            ["evaluat", "criteria"],
        ],
        "description": "Document includes an AI evaluation or testing plan",
    },
    {
        "id": "MEA-2.5",
        "framework": "NIST MEASURE",
        "category": "MEASURE 2.5 — Monitoring",
        "weight": 2,
        "keywords": [
            ["monitor"],
            ["observ"],
            ["logging"],
            ["audit", "log"],
            ["track", "performance"],
        ],
        "description": "Document mandates ongoing monitoring or logging",
    },
    {
        "id": "MEA-4.1",
        "framework": "NIST MEASURE",
        "category": "MEASURE 4.1 — Human Oversight",
        "weight": 3,
        "keywords": [
            ["human", "oversight"],
            ["human.in.the.loop"],
            ["human review"],
            ["human supervision"],
            ["human control"],
        ],
        "description": "Document mandates human oversight of AI decisions",
    },

    # ══ NIST AI RMF — MANAGE ══════════════════════════════════════════════════

    {
        "id": "MAN-1.3",
        "framework": "NIST MANAGE",
        "category": "MANAGE 1.3 — Incident Response",
        "weight": 3,
        "keywords": [
            ["incident", "response"],
            ["breach", "procedure"],
            ["incident", "plan"],
            ["escalat", "process"],
            ["incident", "management"],
        ],
        "description": "Document defines an AI incident response process",
    },
    {
        "id": "MAN-2.2",
        "framework": "NIST MANAGE",
        "category": "MANAGE 2.2 — Decommission",
        "weight": 1,
        "keywords": [
            ["decommission"],
            ["sunset", "model"],
            ["retire", "system"],
            ["end.of.life"],
            ["model", "deprecat"],
        ],
        "description": "Document addresses AI system decommissioning",
    },
    {
        "id": "MAN-2.4",
        "framework": "NIST MANAGE",
        "category": "MANAGE 2.4 — Security Controls",
        "weight": 3,
        "keywords": [
            ["security", "control"],
            ["access", "control"],
            ["authentication"],
            ["authoriz"],
            ["least privilege"],
            ["encryption"],
        ],
        "description": "Document specifies AI security controls",
    },
    {
        "id": "MAN-3.1",
        "framework": "NIST MANAGE",
        "category": "MANAGE 3.1 — Remediation",
        "weight": 2,
        "keywords": [
            ["remediat"],
            ["corrective", "action"],
            ["mitigation", "plan"],
            ["risk", "response"],
            ["remediation", "process"],
        ],
        "description": "Document outlines risk remediation or corrective actions",
    },

    # ══ OWASP LLM Top 10 ══════════════════════════════════════════════════════

    {
        "id": "OWASP-LLM01",
        "framework": "OWASP",
        "category": "LLM01 — Prompt Injection",
        "weight": 3,
        "keywords": [
            ["prompt injection"],
            ["injection", "attack"],
            ["input", "sanitiz"],
            ["input", "validat"],
            ["adversarial", "input"],
        ],
        "description": "Document addresses prompt injection risk (OWASP LLM01)",
    },
    {
        "id": "OWASP-LLM02",
        "framework": "OWASP",
        "category": "LLM02 — Output Handling",
        "weight": 2,
        "keywords": [
            ["output", "validat"],
            ["output", "sanitiz"],
            ["content", "filter"],
            ["output", "review"],
            ["response", "check"],
        ],
        "description": "Document addresses insecure output handling (OWASP LLM02)",
    },
    {
        "id": "OWASP-LLM06",
        "framework": "OWASP",
        "category": "LLM06 — Sensitive Disclosure",
        "weight": 3,
        "keywords": [
            ["sensitive", "data"],
            ["data", "leakage"],
            ["confidential", "information"],
            ["pii", "protect"],
            ["data", "disclosure"],
        ],
        "description": "Document addresses sensitive data disclosure (OWASP LLM06)",
    },
    {
        "id": "OWASP-LLM08",
        "framework": "OWASP",
        "category": "LLM08 — Excessive Agency",
        "weight": 2,
        "keywords": [
            ["excessive agency"],
            ["autonomous", "action"],
            ["agent", "permission"],
            ["least privilege", "agent"],
            ["action", "approval"],
        ],
        "description": "Document restricts autonomous AI actions (OWASP LLM08)",
    },
    {
        "id": "OWASP-LLM09",
        "framework": "OWASP",
        "category": "LLM09 — Overreliance",
        "weight": 2,
        "keywords": [
            ["overreliance"],
            ["human", "verification"],
            ["fact.check"],
            ["hallucination"],
            ["verify", "output"],
            ["accuracy", "review"],
        ],
        "description": "Document mitigates overreliance on AI output (OWASP LLM09)",
    },
]


# ── Framework grouping ────────────────────────────────────────────────────────

FRAMEWORK_ORDER = ["NIST GOVERN", "NIST MAP", "NIST MEASURE", "NIST MANAGE", "OWASP"]

FRAMEWORK_LABELS = {
    "NIST GOVERN":  "NIST AI RMF — GOVERN",
    "NIST MAP":     "NIST AI RMF — MAP",
    "NIST MEASURE": "NIST AI RMF — MEASURE",
    "NIST MANAGE":  "NIST AI RMF — MANAGE",
    "OWASP":        "OWASP LLM Top 10",
}


# ── Heuristic engine ──────────────────────────────────────────────────────────

def _normalise(text: str) -> str:
    """Lowercase, collapse whitespace, replace hyphens for fuzzy matching."""
    text = text.lower()
    text = re.sub(r"[-–—/]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _check_passes(text_norm: str, keyword_groups: list[list[str]]) -> bool:
    """
    A check passes if ANY keyword group matches.
    A group matches if ALL terms in the group appear in the text
    (terms support simple regex via re.search).
    """
    for group in keyword_groups:
        if all(re.search(term, text_norm) for term in group):
            return True
    return False


def score_document(text: str) -> dict[str, Any]:
    """
    Run all checks against the document text.

    Returns structured result with per-check and per-framework scores.
    """
    text_norm = _normalise(text)
    results   = []

    for check in CHECKS:
        passed = _check_passes(text_norm, check["keywords"])
        results.append({
            "id":          check["id"],
            "framework":   check["framework"],
            "category":    check["category"],
            "weight":      check["weight"],
            "passed":      passed,
            "description": check["description"],
        })

    # ── Weighted totals ───────────────────────────────────────────────────────
    total_weight  = sum(c["weight"] for c in CHECKS)
    earned_weight = sum(r["weight"] for r in results if r["passed"])
    overall_pct   = (earned_weight / total_weight * 100) if total_weight else 0

    # ── Per-framework breakdown ───────────────────────────────────────────────
    framework_scores: dict[str, dict] = {}
    for fw in FRAMEWORK_ORDER:
        fw_checks  = [r for r in results if r["framework"] == fw]
        fw_weight  = sum(r["weight"] for r in fw_checks)
        fw_earned  = sum(r["weight"] for r in fw_checks if r["passed"])
        fw_pct     = (fw_earned / fw_weight * 100) if fw_weight else 0
        framework_scores[fw] = {
            "label":        FRAMEWORK_LABELS[fw],
            "checks":       len(fw_checks),
            "passed":       sum(1 for r in fw_checks if r["passed"]),
            "total_weight": fw_weight,
            "earned_weight":fw_earned,
            "pass_pct":     round(fw_pct, 1),
            "risk_level":   _risk_level(fw_pct),
        }

    return {
        "timestamp":        datetime.now().isoformat(),
        "audit_module":     "governance_check",
        "toolkit_version":  "0.1.0",
        "total_checks":     len(results),
        "passed_checks":    sum(1 for r in results if r["passed"]),
        "total_weight":     total_weight,
        "earned_weight":    earned_weight,
        "overall_pct":      round(overall_pct, 1),
        "overall_risk":     _risk_level(overall_pct),
        "framework_scores": framework_scores,
        "check_results":    results,
        "word_count":       len(text.split()),
        "char_count":       len(text),
    }


# ── Risk helpers ──────────────────────────────────────────────────────────────

def _risk_level(pct: float) -> str:
    if pct >= 75:
        return "LOW"
    elif pct >= 50:
        return "MEDIUM"
    else:
        return "HIGH"


def _risk_badge(level: str) -> str:
    return {"HIGH": "🔴 HIGH", "MEDIUM": "⚠  MEDIUM", "LOW": "✅ LOW"}.get(level, level)


def _risk_color(level: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(level, "white")


def _progress_bar(pct: float, width: int = 20) -> str:
    """ASCII progress bar."""
    filled = int(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


# ── Terminal output ───────────────────────────────────────────────────────────

def _print_rich(result: dict[str, Any]):
    """Rich terminal scorecard."""
    overall_risk  = result["overall_risk"]
    overall_pct   = result["overall_pct"]
    overall_color = _risk_color(overall_risk)

    # ── Summary panel ─────────────────────────────────────────────────────────
    summary = (
        f"[bold]Checks run:[/bold]      {result['total_checks']}\n"
        f"[bold]Checks passed:[/bold]   {result['passed_checks']} / {result['total_checks']}\n"
        f"[bold]Weighted score:[/bold]  {result['earned_weight']} / {result['total_weight']} "
        f"({overall_pct:.0f}%)\n"
        f"[bold]Document size:[/bold]   {result['word_count']} words\n"
        f"[bold]Overall risk:[/bold]    [{overall_color}]{_risk_badge(overall_risk)}[/{overall_color}]"
    )
    console.print(Panel(
        summary,
        title="[bold cyan]Governance Scorecard — Summary[/bold cyan]",
        border_style="cyan",
    ))

    # ── Framework breakdown table ──────────────────────────────────────────────
    table = Table(
        title="Framework Coverage",
        box=box.DOUBLE_EDGE,
        header_style="bold white on dark_blue",
        show_lines=True,
        min_width=78,
    )
    table.add_column("Framework",      style="bold cyan",  min_width=28)
    table.add_column("Checks",         justify="center",   min_width=8)
    table.add_column("Pass",           justify="center",   min_width=8)
    table.add_column("Score",          justify="center",   min_width=22)
    table.add_column("Risk",           justify="center",   min_width=13)

    for fw in FRAMEWORK_ORDER:
        fs    = result["framework_scores"][fw]
        pct   = fs["pass_pct"]
        color = _risk_color(fs["risk_level"])
        bar   = _progress_bar(pct, width=14)

        table.add_row(
            fs["label"],
            str(fs["checks"]),
            f"{fs['passed']}/{fs['checks']}",
            f"{bar} {pct:.0f}%",
            f"[{color}]{_risk_badge(fs['risk_level'])}[/{color}]",
        )

    # Overall row
    bar = _progress_bar(overall_pct, width=14)
    table.add_section()
    table.add_row(
        "[bold]OVERALL[/bold]",
        str(result["total_checks"]),
        f"{result['passed_checks']}/{result['total_checks']}",
        f"[bold]{bar} {overall_pct:.0f}%[/bold]",
        f"[bold {overall_color}]{_risk_badge(overall_risk)}[/bold {overall_color}]",
    )

    console.print()
    console.print(table)

    # ── Per-check detail ───────────────────────────────────────────────────────
    console.print()
    detail = Table(
        title="Check Detail",
        box=box.SIMPLE_HEAVY,
        header_style="bold",
        show_lines=False,
    )
    detail.add_column("Check ID",    style="dim cyan",  min_width=14)
    detail.add_column("Category",    style="white",     min_width=32)
    detail.add_column("Weight",      justify="center",  min_width=7)
    detail.add_column("Result",      justify="center",  min_width=10)
    detail.add_column("Description", style="dim",       min_width=40)

    current_fw = None
    for r in result["check_results"]:
        if r["framework"] != current_fw:
            current_fw = r["framework"]
            detail.add_section()

        result_cell = "[green]✓ PASS[/green]" if r["passed"] else "[red]✗ FAIL[/red]"
        weight_cell = "●" * r["weight"] + "○" * (3 - r["weight"])

        detail.add_row(
            r["id"],
            r["category"],
            weight_cell,
            result_cell,
            r["description"],
        )

    console.print(detail)

    # ── Recommendations ───────────────────────────────────────────────────────
    failed = [r for r in result["check_results"] if not r["passed"]]
    high_pri = sorted(
        [r for r in failed if r["weight"] == 3],
        key=lambda x: x["framework"]
    )

    if high_pri:
        console.print()
        recs = "\n".join(
            f"  [red]✗[/red] [{r['id']}] {r['description']}"
            for r in high_pri
        )
        console.print(Panel(
            recs,
            title="[bold red]High-Priority Gaps (weight 3)[/bold red]",
            border_style="red",
            padding=(0, 2),
        ))
    elif failed:
        console.print()
        console.print(Panel(
            f"[green]{result['passed_checks']}/{result['total_checks']} checks passed.[/green]\n"
            "[dim]No high-priority gaps. Address remaining medium/low items to reach full compliance.[/dim]",
            border_style="green",
            padding=(0, 2),
        ))
    else:
        console.print()
        console.print(Panel(
            "[bold green]✓ All checks passed.[/bold green]\n"
            "[dim]Document demonstrates strong AI governance coverage.[/dim]",
            border_style="green",
        ))

    console.print()


def _print_plain(result: dict[str, Any]):
    """Fallback plain-text scorecard."""
    print("\n" + "═" * 70)
    print("  ai-audit-kit — Governance Scorecard")
    print("═" * 70)
    print(f"  Checks:  {result['passed_checks']}/{result['total_checks']} passed")
    print(f"  Score:   {result['earned_weight']}/{result['total_weight']} weighted ({result['overall_pct']:.0f}%)")
    print(f"  Risk:    {_risk_badge(result['overall_risk'])}")
    print()

    for fw in FRAMEWORK_ORDER:
        fs  = result["framework_scores"][fw]
        bar = _progress_bar(fs["pass_pct"], width=15)
        print(f"  {fs['label']:<30} {bar} {fs['pass_pct']:.0f}%  {_risk_badge(fs['risk_level'])}")

    print("═" * 70)

    failed = [r for r in result["check_results"] if not r["passed"]]
    if failed:
        print("\n  Gaps:")
        for r in failed:
            print(f"    ✗ [{r['id']}] {r['description']}")


# ── Audit log ─────────────────────────────────────────────────────────────────

def _save_audit_log(result: dict[str, Any], output_dir: str) -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir) / f"governance_audit_{ts}.json"

    # Don't write the full document text to the log
    log = {k: v for k, v in result.items()}

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    return out_path


# ── Entry point ───────────────────────────────────────────────────────────────

def run_governance_check(text: str, output_dir: str = "reports"):
    """Main entrypoint called by llm_audit.py."""

    if RICH_AVAILABLE:
        console.print(f"[dim]Analysing document ({len(text.split())} words) against "
                      f"{len(CHECKS)} governance checks…[/dim]\n")

    result = score_document(text)

    if RICH_AVAILABLE:
        _print_rich(result)
    else:
        _print_plain(result)

    try:
        log_path = _save_audit_log(result, output_dir)
        if RICH_AVAILABLE:
            console.print(f"[green]✓ Audit log saved:[/green] {log_path}")
        else:
            print(f"Audit log saved: {log_path}")
    except Exception as exc:
        if RICH_AVAILABLE:
            console.print(f"[yellow]⚠ Could not save audit log: {exc}[/yellow]")
        else:
            print(f"WARNING: Could not save audit log: {exc}")


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    _SAMPLE_POLICY = """
    AI Governance Policy — Acme Corp
    Effective Date: January 2024 | Review: Annually

    1. PURPOSE AND SCOPE
    This policy establishes governance guidelines for the responsible use of
    artificial intelligence systems across Acme Corp. It applies to all AI
    use cases including customer-facing and internal applications.

    2. ACCOUNTABILITY AND ROLES
    The Chief AI Officer is accountable for AI governance. Roles and
    responsibilities are defined in the RACI matrix (Appendix A).
    Each AI system must have a designated owner.

    3. RISK TOLERANCE AND CATEGORISATION
    Acme maintains a low risk tolerance for high-risk AI applications.
    All AI systems are classified by risk tier (High / Medium / Low)
    based on data sensitivity and decision impact.

    4. PRIVACY AND DATA PROTECTION
    All AI systems must comply with GDPR and HIPAA where applicable.
    Personal data and PII must be minimised. Data protection impact
    assessments are required for high-risk AI deployments.

    5. HUMAN OVERSIGHT
    Human-in-the-loop review is mandatory for all automated decisions
    affecting individuals. Human oversight mechanisms must be documented.

    6. SECURITY CONTROLS
    Access control and authentication are required for all AI systems.
    Least privilege principles apply to AI agents and integrations.
    Prompt injection and input sanitization controls must be implemented.

    7. MONITORING AND INCIDENT RESPONSE
    All AI systems must implement logging and monitoring. An incident
    response plan must be documented and tested annually. Escalation
    processes must be defined for AI-related breaches or failures.

    8. BIAS AND FAIRNESS
    AI systems must be evaluated for bias and disparate impact prior
    to deployment. Fairness metrics must be tracked on an ongoing basis.

    9. THIRD-PARTY AI RISK
    Vendor assessments are required before adopting third-party AI models
    or external providers. Contractual controls must address AI-specific risks.

    10. REMEDIATION
    Corrective action plans must be produced for any failed governance
    checks. Risk response procedures are defined in the Risk Register.
    """

    print("Running standalone governance check...")
    run_governance_check(text=_SAMPLE_POLICY, output_dir="reports")
