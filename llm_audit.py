#!/usr/bin/env python3
"""
airadar — AI Governance & Security Audit Toolkit
======================================================
NIST AI RMF · OWASP LLM Top 10 · HIPAA/PII · IAM Policy Validation

Usage:
  python llm_audit.py --module pii --input "text"
  python llm_audit.py --module pii --file input.txt
  python llm_audit.py --module prompt --mode offline
  python llm_audit.py --module prompt --mode live
  python llm_audit.py --module governance --file policy.txt
  python llm_audit.py --module iam --file rbac_policy.json
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# ── Rich for terminal output ──────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

# ── Version ───────────────────────────────────────────────────────────────────
__version__ = "0.1.0"

BANNER = r"""
  █████╗  ██╗ ██████╗   █████╗  ██████╗   █████╗  ██████╗ 
 ██╔══██╗ ██║ ██╔══██╗ ██╔══██╗ ██╔══██╗ ██╔══██╗ ██╔══██╗
 ███████║ ██║ ██████╔╝ ███████║ ██║  ██║ ███████║ ██████╔╝
 ██╔══██║ ██║ ██╔══██╗ ██╔══██║ ██║  ██║ ██╔══██║ ██╔══██╗
 ██║  ██║ ██║ ██║  ██║ ██║  ██║ ██████╔╝ ██║  ██║ ██║  ██║
 ╚═╝  ╚═╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═╝
                     airadar  v{version}
       NIST AI RMF · OWASP LLM Top 10 · HIPAA · IAM
"""


def print_banner():
    """Print the startup banner."""
    banner = BANNER.format(version=__version__)
    if RICH_AVAILABLE:
        console.print(banner, style="bold cyan")
        console.print(
            Panel(
                "[dim]Open-source AI governance audit toolkit · MIT License[/dim]\n"
                "[dim]Runs 100% locally — zero hosting costs, zero API exposure by default[/dim]",
                border_style="cyan",
                padding=(0, 2),
            )
        )
    else:
        print(banner)
        print("=" * 60)
        print("Open-source AI governance audit toolkit — MIT License")
        print("Runs 100% locally — zero hosting costs by default")
        print("=" * 60)
    print()


def print_module_header(module_name: str, description: str):
    """Print a consistent module header."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if RICH_AVAILABLE:
        console.print(
            Panel(
                f"[bold white]{module_name}[/bold white]\n"
                f"[dim]{description}[/dim]\n"
                f"[dim]Started: {timestamp}[/dim]",
                border_style="blue",
                padding=(0, 2),
            )
        )
    else:
        print(f"\n{'─'*60}")
        print(f"  {module_name}")
        print(f"  {description}")
        print(f"  Started: {timestamp}")
        print(f"{'─'*60}\n")


def load_file(file_path: str) -> str:
    """Load text content from a file with error handling."""
    path = Path(file_path)
    if not path.exists():
        _error(f"File not found: {file_path}")
        sys.exit(1)
    if not path.is_file():
        _error(f"Path is not a file: {file_path}")
        sys.exit(1)
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        _error(f"Could not read file as UTF-8 text: {file_path}")
        sys.exit(1)


def _error(msg: str):
    """Print a styled error message."""
    if RICH_AVAILABLE:
        console.print(f"[bold red]✗ ERROR:[/bold red] {msg}")
    else:
        print(f"ERROR: {msg}", file=sys.stderr)


def _warn(msg: str):
    """Print a styled warning message."""
    if RICH_AVAILABLE:
        console.print(f"[bold yellow]⚠ WARNING:[/bold yellow] {msg}")
    else:
        print(f"WARNING: {msg}")


def _success(msg: str):
    """Print a styled success message."""
    if RICH_AVAILABLE:
        console.print(f"[bold green]✓[/bold green] {msg}")
    else:
        print(f"OK: {msg}")


# ── Module routing ────────────────────────────────────────────────────────────

def run_pii(args):
    """Route to Module 1 — PII Scanner."""
    print_module_header(
        "Module 1 — PII Scanner",
        "Microsoft Presidio · HIPAA Safe Harbor · 15+ entity types"
    )

    # Validate: must have --input or --file
    if not args.input and not args.file:
        _error("Module 'pii' requires --input TEXT or --file PATH")
        _hint_pii()
        sys.exit(1)

    if args.input and args.file:
        _warn("Both --input and --file provided; using --input")

    text = args.input if args.input else load_file(args.file)

    if not text.strip():
        _error("Input text is empty.")
        sys.exit(1)

    # Import and run
    try:
        from modules.pii_scanner import run_pii_scan
    except ImportError as e:
        _error(f"Could not import pii_scanner: {e}")
        _error("Run: pip install presidio-analyzer presidio-anonymizer && python -m spacy download en_core_web_sm")
        sys.exit(1)

    run_pii_scan(
        text=text,
        output_dir=args.output_dir,
        score_threshold=args.score_threshold,
    )


def run_prompt(args):
    """Route to Module 2 — Prompt Guard."""
    print_module_header(
        "Module 2 — Prompt Guard",
        "Adversarial Testing · OWASP LLM01/LLM08/LLM09 · Injection Payloads"
    )

    mode = args.mode or "offline"
    if mode not in ("offline", "live"):
        _error(f"Invalid mode '{mode}'. Choose: offline | live")
        sys.exit(1)

    if mode == "live":
        api_key = (
            os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        if not api_key:
            _error("Live mode requires ANTHROPIC_API_KEY or OPENAI_API_KEY in environment.")
            _warn("Set: export ANTHROPIC_API_KEY=sk-ant-...")
            _warn("Or run offline mode: python llm_audit.py --module prompt --mode offline")
            sys.exit(1)

    try:
        from modules.prompt_guard import run_prompt_guard
    except ImportError as e:
        _error(f"Could not import prompt_guard: {e}")
        sys.exit(1)

    run_prompt_guard(mode=mode, output_dir=args.output_dir)


def run_governance(args):
    """Route to Module 3 — Governance Scorecard."""
    print_module_header(
        "Module 3 — Governance Scorecard",
        "NIST AI RMF · OWASP LLM Top 10 · Local heuristic analysis"
    )

    if not args.file and not args.input:
        _error("Module 'governance' requires --file PATH or --input TEXT")
        _hint_governance()
        sys.exit(1)

    text = args.input if args.input else load_file(args.file)

    if not text.strip():
        _error("Input text is empty.")
        sys.exit(1)

    try:
        from modules.governance_check import run_governance_check
    except ImportError as e:
        _error(f"Could not import governance_check: {e}")
        sys.exit(1)

    run_governance_check(text=text, output_dir=args.output_dir)


def run_iam(args):
    """Route to Module 4 — IAM Policy Validator."""
    print_module_header(
        "Module 4 — IAM Policy Validator",
        "Azure RBAC · Least-Privilege · Conditional Access · Zero-Trust"
    )

    if not args.file:
        _error("Module 'iam' requires --file PATH (JSON policy file)")
        _hint_iam()
        sys.exit(1)

    policy_path = Path(args.file)
    if policy_path.suffix.lower() not in (".json",):
        _warn(f"Expected a .json file, got: {policy_path.suffix}")

    try:
        from modules.iam_validator import run_iam_validation
    except ImportError as e:
        _error(f"Could not import iam_validator: {e}")
        sys.exit(1)

    run_iam_validation(file_path=args.file, output_dir=args.output_dir)


# ── Help hints ────────────────────────────────────────────────────────────────

def _hint_pii():
    print()
    print("  Usage examples:")
    print('    python llm_audit.py --module pii --input "John Smith, SSN 123-45-6789"')
    print("    python llm_audit.py --module pii --file data/patient_notes.txt")
    print()


def _hint_governance():
    print()
    print("  Usage examples:")
    print("    python llm_audit.py --module governance --file policy.txt")
    print('    python llm_audit.py --module governance --input "Our AI system prompt..."')
    print()


def _hint_iam():
    print()
    print("  Usage examples:")
    print("    python llm_audit.py --module iam --file rbac_policy.json")
    print("    python llm_audit.py --module iam --file conditional_access.json")
    print()


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm_audit.py",
        description=(
            "airadar: AI Governance & Security Audit Toolkit\n"
            "NIST AI RMF · OWASP LLM Top 10 · HIPAA/PII · IAM Validation\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODULES:
  pii          Detect & redact PII/PHI using Microsoft Presidio (HIPAA Safe Harbor)
  prompt       Run adversarial prompt injection tests (OWASP LLM01-LLM09)
  governance   Score AI policy document against NIST AI RMF + OWASP
  iam          Validate Azure RBAC / Conditional Access policy JSON

EXAMPLES:
  python llm_audit.py --module pii --input "Patient John Doe, DOB 01/15/1980"
  python llm_audit.py --module pii --file notes.txt --output-dir reports/
  python llm_audit.py --module prompt --mode offline
  python llm_audit.py --module prompt --mode live
  python llm_audit.py --module governance --file system_prompt.txt
  python llm_audit.py --module iam --file rbac.json

LIVE MODE (Module 2):
  Set ANTHROPIC_API_KEY or OPENAI_API_KEY in your environment.
  export ANTHROPIC_API_KEY=sk-ant-...
        """,
    )

    parser.add_argument(
        "--module", "-m",
        required=True,
        choices=["pii", "prompt", "governance", "iam"],
        help="Which audit module to run",
    )
    parser.add_argument(
        "--input", "-i",
        default=None,
        help="Text string to analyze (for pii and governance modules)",
    )
    parser.add_argument(
        "--file", "-f",
        default=None,
        help="Path to input file (.txt, .json, etc.)",
    )
    parser.add_argument(
        "--mode",
        default="offline",
        choices=["offline", "live"],
        help="Prompt Guard mode: offline (free) or live (BYOK). Default: offline",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="reports",
        dest="output_dir",
        help="Directory for audit report output. Default: reports/",
    )
    parser.add_argument(
        "--score-threshold",
        type=float,
        default=0.5,
        dest="score_threshold",
        help="Presidio confidence threshold (0.0–1.0). Default: 0.5",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"airadar {__version__}",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the startup banner (useful for scripting)",
    )

    return parser


# ── Dispatch table ────────────────────────────────────────────────────────────

MODULE_DISPATCH = {
    "pii":        run_pii,
    "prompt":     run_prompt,
    "governance": run_governance,
    "iam":        run_iam,
}


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Ensure output dir exists
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    # Banner (suppress if --no-banner or piped output)
    if not args.no_banner and sys.stdout.isatty():
        print_banner()

    # Dispatch to selected module
    handler = MODULE_DISPATCH.get(args.module)
    if handler is None:
        _error(f"Unknown module: {args.module}")
        parser.print_help()
        sys.exit(1)

    try:
        handler(args)
    except KeyboardInterrupt:
        print()
        if RICH_AVAILABLE:
            console.print("\n[yellow]Audit interrupted by user.[/yellow]")
        else:
            print("\nAudit interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
    