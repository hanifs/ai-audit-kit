"""
Module 1 — PII Scanner
======================
Microsoft Presidio · HIPAA Safe Harbor · 15+ entity types

Detects and redacts personally identifiable / protected health information.
Produces a structured audit log and terminal scorecard.

Supported entities (HIPAA Safe Harbor §164.514(b)(2)):
  PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD,
  DATE_TIME, US_DRIVER_LICENSE, MEDICAL_LICENSE, IP_ADDRESS,
  URL, LOCATION, NRP, US_PASSPORT, IBAN_CODE, CRYPTO

Usage (via CLI):
  python llm_audit.py --module pii --input "John Smith, SSN 123-45-6789"
  python llm_audit.py --module pii --file patient_notes.txt
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Presidio ──────────────────────────────────────────────────────────────────
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

# ── Rich ──────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


# ── HIPAA Safe Harbor entity mapping ─────────────────────────────────────────
#
# 18 identifiers under HIPAA Safe Harbor (§164.514(b)(2)).
# Presidio entity types that map to HIPAA-covered identifiers.

HIPAA_ENTITIES: dict[str, dict[str, str]] = {
    "PERSON":              {"hipaa": "Names",                    "safe_harbor": "§1"},
    "LOCATION":            {"hipaa": "Geographic data",          "safe_harbor": "§2"},
    "DATE_TIME":           {"hipaa": "Dates (except year)",      "safe_harbor": "§3"},
    "PHONE_NUMBER":        {"hipaa": "Phone numbers",            "safe_harbor": "§4"},
    "EMAIL_ADDRESS":       {"hipaa": "Email addresses",          "safe_harbor": "§6"},
    "US_SSN":              {"hipaa": "Social security numbers",  "safe_harbor": "§8"},
    "MEDICAL_LICENSE":     {"hipaa": "Medical record numbers",   "safe_harbor": "§9"},
    "US_DRIVER_LICENSE":   {"hipaa": "Account numbers",         "safe_harbor": "§10"},
    "US_PASSPORT":         {"hipaa": "Certificate/license #s",  "safe_harbor": "§12"},
    "CREDIT_CARD":         {"hipaa": "Account numbers",         "safe_harbor": "§11"},
    "IP_ADDRESS":          {"hipaa": "IP addresses",            "safe_harbor": "§15"},
    "URL":                 {"hipaa": "URLs",                    "safe_harbor": "§16"},
    "NRP":                 {"hipaa": "Geographic data",         "safe_harbor": "§2"},
    "IBAN_CODE":           {"hipaa": "Account numbers",         "safe_harbor": "§11"},
    "CRYPTO":              {"hipaa": "Account numbers",         "safe_harbor": "§11"},
}

# All entities to scan for
ALL_ENTITIES = list(HIPAA_ENTITIES.keys())

# Risk level thresholds
RISK_THRESHOLDS = {
    "HIGH":   3,   # 3+ entity types found → HIGH
    "MEDIUM": 1,   # 1-2 entity types → MEDIUM
    "LOW":    0,   # clean scan → LOW
}


# ── Core scanner ──────────────────────────────────────────────────────────────

class PIIScanner:
    """
    Wraps Microsoft Presidio analyzer + anonymizer.

    Detects PII/PHI entities and applies redaction with [ENTITY_TYPE]
    placeholder tokens.
    """

    def __init__(self, score_threshold: float = 0.5):
        if not PRESIDIO_AVAILABLE:
            raise ImportError(
                "presidio-analyzer and presidio-anonymizer are required.\n"
                "Install: pip install presidio-analyzer presidio-anonymizer\n"
                "Then:    python -m spacy download en_core_web_sm"
            )
        self.score_threshold = score_threshold
        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

    def analyze(self, text: str) -> list[RecognizerResult]:
        """Run Presidio analyzer and return all hits above threshold."""
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=ALL_ENTITIES,
            score_threshold=self.score_threshold,
        )
        # Sort by position for clean output
        return sorted(results, key=lambda r: r.start)

    def redact(self, text: str, results: list[RecognizerResult]) -> str:
        """Replace detected entities with [ENTITY_TYPE] placeholder tokens."""
        if not results:
            return text

        operators = {
            entity: OperatorConfig("replace", {"new_value": f"[{entity}]"})
            for entity in ALL_ENTITIES
        }
        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text

    def scan(self, text: str) -> dict[str, Any]:
        """
        Full scan pipeline. Returns structured result dict.

        Returns:
            {
                "original_text": str,
                "redacted_text": str,
                "entities": [...],
                "entity_summary": {type: count},
                "hipaa_violations": [...],
                "risk_level": "LOW" | "MEDIUM" | "HIGH",
                "is_hipaa_compliant": bool,
                "score_threshold": float,
                "timestamp": str,
            }
        """
        results = self.analyze(text)

        # Build entity list with full metadata
        entities = []
        for r in results:
            entity_info = {
                "entity_type":   r.entity_type,
                "start":         r.start,
                "end":           r.end,
                "score":         round(r.score, 4),
                "text_span":     text[r.start:r.end],
                "hipaa_category": HIPAA_ENTITIES.get(r.entity_type, {}).get("hipaa", "Other"),
                "safe_harbor":   HIPAA_ENTITIES.get(r.entity_type, {}).get("safe_harbor", ""),
                "is_hipaa":      r.entity_type in HIPAA_ENTITIES,
            }
            entities.append(entity_info)

        # Summarise by entity type
        entity_summary: dict[str, int] = {}
        for e in entities:
            entity_summary[e["entity_type"]] = entity_summary.get(e["entity_type"], 0) + 1

        # HIPAA violations: entities that are HIPAA-covered
        hipaa_violations = [e for e in entities if e["is_hipaa"]]

        # Risk level
        unique_types = len(entity_summary)
        if unique_types >= RISK_THRESHOLDS["HIGH"]:
            risk_level = "HIGH"
        elif unique_types >= RISK_THRESHOLDS["MEDIUM"]:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        redacted_text = self.redact(text, results)

        return {
            "original_text":    text,
            "redacted_text":    redacted_text,
            "entities":         entities,
            "entity_summary":   entity_summary,
            "hipaa_violations": hipaa_violations,
            "risk_level":       risk_level,
            "is_hipaa_compliant": len(hipaa_violations) == 0,
            "score_threshold":  self.score_threshold,
            "timestamp":        datetime.now().isoformat(),
            "total_entities":   len(entities),
            "unique_entity_types": unique_types,
        }


# ── Terminal output ───────────────────────────────────────────────────────────

def _risk_badge(level: str) -> str:
    """Return a coloured terminal badge for a risk level."""
    badges = {
        "HIGH":   "🔴 HIGH",
        "MEDIUM": "⚠  MEDIUM",
        "LOW":    "✅ LOW",
    }
    return badges.get(level, level)


def _risk_color(level: str) -> str:
    """Return Rich colour string for a risk level."""
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(level, "white")


def print_pii_results(result: dict[str, Any]):
    """
    Render the PII scan result to the terminal using Rich (or plain text fallback).
    """
    if RICH_AVAILABLE:
        _print_rich(result)
    else:
        _print_plain(result)


def _print_rich(result: dict[str, Any]):
    """Rich terminal output."""
    risk       = result["risk_level"]
    color      = _risk_color(risk)
    total      = result["total_entities"]
    hipaa_ct   = len(result["hipaa_violations"])
    compliant  = result["is_hipaa_compliant"]

    # ── Summary panel ────────────────────────────────────────────────────────
    summary_lines = (
        f"[bold]Entities detected:[/bold]    {total}\n"
        f"[bold]Unique entity types:[/bold]  {result['unique_entity_types']}\n"
        f"[bold]HIPAA violations:[/bold]     {hipaa_ct}\n"
        f"[bold]HIPAA Safe Harbor:[/bold]    {'[green]COMPLIANT ✓[/green]' if compliant else '[red]NON-COMPLIANT ✗[/red]'}\n"
        f"[bold]Overall risk level:[/bold]   [{color}]{_risk_badge(risk)}[/{color}]\n"
        f"[bold]Confidence threshold:[/bold] {result['score_threshold']}"
    )
    console.print(Panel(summary_lines, title="[bold cyan]PII Scan Summary[/bold cyan]", border_style="cyan"))

    # ── Entity table ─────────────────────────────────────────────────────────
    if result["entity_summary"]:
        table = Table(
            title="Detected Entities",
            box=box.DOUBLE_EDGE,
            header_style="bold white on dark_blue",
            show_lines=True,
        )
        table.add_column("Entity Type",     style="bold cyan",   min_width=22)
        table.add_column("Count",           style="white",       justify="center", min_width=7)
        table.add_column("HIPAA Category",  style="dim white",   min_width=25)
        table.add_column("Safe Harbor §",   style="dim yellow",  min_width=12)
        table.add_column("Risk",            style="white",       min_width=12)

        for etype, count in sorted(result["entity_summary"].items()):
            hipaa_info  = HIPAA_ENTITIES.get(etype, {})
            hipaa_cat   = hipaa_info.get("hipaa", "—")
            safe_harbor = hipaa_info.get("safe_harbor", "—")
            is_hipaa    = etype in HIPAA_ENTITIES
            risk_cell   = f"[red]🔴 HIPAA[/red]" if is_hipaa else "[dim]—[/dim]"
            table.add_row(etype, str(count), hipaa_cat, safe_harbor, risk_cell)

        console.print(table)
    else:
        console.print("[green]✓ No PII entities detected above confidence threshold.[/green]")

    # ── Redacted text ─────────────────────────────────────────────────────────
    console.print()
    console.print("[bold]Redacted output:[/bold]")
    redacted = result["redacted_text"]
    # Highlight the [ENTITY] tokens
    import re
    highlighted = re.sub(r"(\[[A-Z_]+\])", r"[bold red]\1[/bold red]", redacted)
    console.print(
        Panel(highlighted, border_style="dim", title="[dim]redacted text[/dim]", padding=(1, 2))
    )

    # ── Per-hit detail ────────────────────────────────────────────────────────
    if result["entities"]:
        console.print()
        detail = Table(
            title="Entity Detail (all hits)",
            box=box.SIMPLE_HEAVY,
            header_style="bold",
            show_lines=False,
        )
        detail.add_column("Pos",         justify="right",  style="dim",        min_width=8)
        detail.add_column("Entity Type", style="cyan",     min_width=20)
        detail.add_column("Value",       style="bold red", min_width=25)
        detail.add_column("Score",       justify="right",  style="yellow",     min_width=7)
        detail.add_column("HIPAA",       justify="center", min_width=7)

        for e in result["entities"]:
            detail.add_row(
                f"{e['start']}–{e['end']}",
                e["entity_type"],
                e["text_span"],
                f"{e['score']:.3f}",
                "✓" if e["is_hipaa"] else "—",
            )
        console.print(detail)

    console.print()


def _print_plain(result: dict[str, Any]):
    """Fallback plain-text output (no Rich)."""
    print("\n" + "═" * 60)
    print("  PII SCAN RESULTS")
    print("═" * 60)
    print(f"  Entities detected  : {result['total_entities']}")
    print(f"  Unique types       : {result['unique_entity_types']}")
    print(f"  HIPAA violations   : {len(result['hipaa_violations'])}")
    compliant = "YES" if result["is_hipaa_compliant"] else "NO"
    print(f"  HIPAA compliant    : {compliant}")
    print(f"  Risk level         : {_risk_badge(result['risk_level'])}")
    print()
    if result["entity_summary"]:
        print("  Entity breakdown:")
        for etype, count in result["entity_summary"].items():
            print(f"    {etype:<25} {count}")
    print()
    print("  Redacted text:")
    print(f"  {result['redacted_text']}")
    print("═" * 60)


# ── Audit log ─────────────────────────────────────────────────────────────────

def save_audit_log(result: dict[str, Any], output_dir: str) -> Path:
    """
    Save the full scan result as a JSON audit log in output_dir.

    Filename format: pii_audit_YYYYMMDD_HHMMSS.json
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir) / f"pii_audit_{ts}.json"

    # Sanitise: don't write original text to log (privacy)
    log_data = {k: v for k, v in result.items() if k != "original_text"}
    log_data["audit_module"]  = "pii_scanner"
    log_data["toolkit_version"] = "0.1.0"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2, ensure_ascii=False)

    return out_path


# ── Entry point (called from llm_audit.py) ───────────────────────────────────

def run_pii_scan(
    text: str,
    output_dir: str = "reports",
    score_threshold: float = 0.5,
):
    """
    Main entrypoint called by llm_audit.py.

    Instantiates scanner, runs analysis, prints results, saves audit log.
    """
    if not PRESIDIO_AVAILABLE:
        msg = (
            "presidio-analyzer / presidio-anonymizer not installed.\n"
            "  pip install presidio-analyzer presidio-anonymizer\n"
            "  python -m spacy download en_core_web_sm"
        )
        if RICH_AVAILABLE:
            console.print(f"[bold red]✗ DEPENDENCY ERROR:[/bold red]\n{msg}")
        else:
            print(f"DEPENDENCY ERROR:\n{msg}")
        return

    if RICH_AVAILABLE:
        console.print("[dim]Initialising Presidio engine...[/dim]")

    try:
        scanner = PIIScanner(score_threshold=score_threshold)
    except Exception as exc:
        if RICH_AVAILABLE:
            console.print(f"[red]Failed to initialise Presidio: {exc}[/red]")
        else:
            print(f"Failed to initialise Presidio: {exc}")
        return

    if RICH_AVAILABLE:
        console.print("[dim]Running analysis...[/dim]\n")

    result = scanner.scan(text)
    print_pii_results(result)

    # Save audit log
    try:
        log_path = save_audit_log(result, output_dir)
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
    _TEST_TEXT = """
    Patient: John Michael Smith
    DOB: January 15, 1980
    SSN: 123-45-6789
    Phone: (555) 867-5309
    Email: john.smith@example.com
    Address: 742 Evergreen Terrace, Springfield, IL 62701
    Credit Card: 4111-1111-1111-1111
    Medical License: ML-9988776
    IP Address: 192.168.1.100
    Notes: Patient presented with chest pain. Referred to Dr. Jane Doe at Northwestern.
    """

    print("Running standalone PII scan test...")
    run_pii_scan(text=_TEST_TEXT, output_dir="reports", score_threshold=0.35)
