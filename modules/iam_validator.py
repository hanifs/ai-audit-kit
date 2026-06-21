"""
Module 4 — IAM Policy Validator
================================
Azure RBAC · Conditional Access · Least-Privilege · Zero-Trust

Validates Azure RBAC role definitions and Conditional Access policy JSON
against least-privilege principles and known misconfiguration patterns.

Pure stdlib — json, re, pathlib only. Zero API calls.

Supported input types (auto-detected):
  - Azure RBAC role definition JSON
  - Azure Conditional Access policy JSON
  - Generic IAM policy JSON

Usage (via CLI):
  python llm_audit.py --module iam --file rbac_policy.json
  python llm_audit.py --module iam --file conditional_access.json
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
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


# ── Dangerous permission patterns ─────────────────────────────────────────────
#
# These are wildcard or high-privilege actions that violate least-privilege.
# Matched against the "actions" / "permissions" arrays in a role definition.

DANGEROUS_ACTIONS: list[dict[str, Any]] = [
    {
        "id":          "ACT-001",
        "pattern":     r"^\*$",
        "label":       "Wildcard (*) — full resource access",
        "severity":    "HIGH",
        "owasp":       "LLM08",
        "cis":         "CIS Azure 1.1",
        "description": "Wildcard action grants unrestricted access to all resources and operations.",
        "remediation": "Replace * with the specific actions required for the role's purpose.",
    },
    {
        "id":          "ACT-002",
        "pattern":     r"\*/\*",
        "label":       "Wildcard scope (*/*)  — all resource types",
        "severity":    "HIGH",
        "owasp":       "LLM08",
        "cis":         "CIS Azure 1.1",
        "description": "*/write or */delete grants write/delete across ALL resource types.",
        "remediation": "Scope actions to specific resource providers (e.g. Microsoft.Compute/*).",
    },
    {
        "id":          "ACT-003",
        "pattern":     r"microsoft\.authorization/roleassignments/write",
        "label":       "Role Assignment Write — privilege escalation risk",
        "severity":    "HIGH",
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.22",
        "description": "Allows the principal to grant any role to any user — privilege escalation vector.",
        "remediation": "Remove unless this is a dedicated IAM admin role with strict assignment scope.",
    },
    {
        "id":          "ACT-004",
        "pattern":     r"microsoft\.authorization/roledefinitions/write",
        "label":       "Role Definition Write — custom role creation risk",
        "severity":    "HIGH",
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.22",
        "description": "Allows creation of new custom roles — attacker could create a role with * permissions.",
        "remediation": "Restrict to dedicated IAM governance roles only.",
    },
    {
        "id":          "ACT-005",
        "pattern":     r"microsoft\.keyvault/vaults/secrets/\*",
        "label":       "Key Vault Secrets Wildcard",
        "severity":    "HIGH",
        "owasp":       "LLM06",
        "cis":         "CIS Azure 8.1",
        "description": "Grants read/write/delete on ALL Key Vault secrets including credentials and keys.",
        "remediation": "Scope to specific secret names or use read-only (secrets/read) where possible.",
    },
    {
        "id":          "ACT-006",
        "pattern":     r"microsoft\.storage/storageaccounts/\*",
        "label":       "Storage Account Wildcard",
        "severity":    "HIGH",
        "owasp":       "LLM06",
        "cis":         "CIS Azure 3.1",
        "description": "Full control over storage accounts including data and configuration.",
        "remediation": "Use Storage Blob Data Reader/Contributor scoped to specific containers.",
    },
    {
        "id":          "ACT-007",
        "pattern":     r"microsoft\.compute/virtualmachines/\*",
        "label":       "Virtual Machine Wildcard",
        "severity":    "MEDIUM",
        "owasp":       "LLM08",
        "cis":         "CIS Azure 7.1",
        "description": "Full control over VMs including runCommand — code execution risk.",
        "remediation": "Restrict to required VM operations (start/stop/read) only.",
    },
    {
        "id":          "ACT-008",
        "pattern":     r"microsoft\.insights/\*",
        "label":       "Azure Monitor Wildcard",
        "severity":    "LOW",
        "owasp":       "LLM06",
        "cis":         "CIS Azure 5.1",
        "description": "Full access to monitoring data, diagnostic settings, and logs.",
        "remediation": "Use Monitoring Reader role for read-only access to metrics and logs.",
    },
    {
        "id":          "ACT-009",
        "pattern":     r"microsoft\.sql/servers/\*",
        "label":       "SQL Server Wildcard",
        "severity":    "HIGH",
        "owasp":       "LLM06",
        "cis":         "CIS Azure 4.1",
        "description": "Full control over SQL servers including data, firewall rules, and credentials.",
        "remediation": "Scope to specific databases and use SQL DB Contributor where possible.",
    },
    {
        "id":          "ACT-010",
        "pattern":     r"microsoft\.network/\*",
        "label":       "Network Wildcard",
        "severity":    "MEDIUM",
        "owasp":       "LLM08",
        "cis":         "CIS Azure 6.1",
        "description": "Full control over network resources including NSGs, peering, and VPN gateways.",
        "remediation": "Scope to specific network operations required (e.g. read-only for auditors).",
    },
]

# ── Structural checks (apply to any IAM JSON) ─────────────────────────────────

STRUCTURAL_CHECKS: list[dict[str, Any]] = [
    {
        "id":          "STR-001",
        "label":       "Scope defined (not subscription-wide)",
        "severity":    "HIGH",
        "check_type":  "scope_not_subscription",
        "description": "Role assigned at subscription scope grants access to ALL resources.",
        "remediation": "Scope role assignments to resource group or specific resource level.",
    },
    {
        "id":          "STR-002",
        "label":       "NotActions used (exclusion-based — fragile)",
        "severity":    "MEDIUM",
        "check_type":  "not_actions_present",
        "description": "NotActions rely on exclusion logic which is fragile — new actions bypass it.",
        "remediation": "Use explicit Actions allowlists rather than NotActions exclusions.",
    },
    {
        "id":          "STR-003",
        "label":       "DataActions wildcard present",
        "severity":    "HIGH",
        "check_type":  "data_actions_wildcard",
        "description": "Wildcard DataActions grants read/write/delete on all data plane operations.",
        "remediation": "Specify only required data plane operations explicitly.",
    },
    {
        "id":          "STR-004",
        "label":       "AssignableScopes includes root (/)",
        "severity":    "HIGH",
        "check_type":  "root_assignable_scope",
        "description": "AssignableScope of / means the role can be assigned anywhere in the tenant.",
        "remediation": "Restrict AssignableScopes to specific subscriptions or resource groups.",
    },
    {
        "id":          "STR-005",
        "label":       "Role description provided",
        "severity":    "LOW",
        "check_type":  "description_present",
        "description": "Missing description makes it hard to audit role purpose over time.",
        "remediation": "Add a description explaining the role's purpose and who should hold it.",
    },
]

# ── Conditional Access checks ─────────────────────────────────────────────────

CA_CHECKS: list[dict[str, Any]] = [
    {
        "id":          "CA-001",
        "label":       "MFA required",
        "severity":    "HIGH",
        "check_type":  "mfa_required",
        "description": "Policy does not enforce multi-factor authentication.",
        "remediation": "Add grantControls requiring MFA for all applicable users and apps.",
    },
    {
        "id":          "CA-002",
        "label":       "Policy state is enabled (not report-only)",
        "severity":    "MEDIUM",
        "check_type":  "policy_enabled",
        "description": "Policy is in report-only or disabled state — not enforcing controls.",
        "remediation": "Set state to 'enabled' after validating in report-only mode.",
    },
    {
        "id":          "CA-003",
        "label":       "All users included (no broad exclusions)",
        "severity":    "MEDIUM",
        "check_type":  "broad_exclusions",
        "description": "Large user exclusion groups may leave significant attack surface uncovered.",
        "remediation": "Minimise exclusion groups; document and review exclusions quarterly.",
    },
    {
        "id":          "CA-004",
        "label":       "Sign-in risk policy present",
        "severity":    "MEDIUM",
        "check_type":  "signin_risk",
        "description": "No sign-in risk condition — risky logins not blocked or challenged.",
        "remediation": "Add signInRiskLevels condition (high, medium) with block or MFA grant.",
    },
    {
        "id":          "CA-005",
        "label":       "Compliant device required",
        "severity":    "LOW",
        "check_type":  "compliant_device",
        "description": "Policy does not require compliant or Hybrid Azure AD joined device.",
        "remediation": "Add requireCompliantDevice or requireHybridAzureADJoinedDevice to grant controls.",
    },
]


# ── Policy type detection ─────────────────────────────────────────────────────

def _detect_policy_type(policy: dict) -> str:
    """
    Auto-detect whether the JSON is:
      - 'rbac'               Azure RBAC role definition
      - 'conditional_access' Azure Conditional Access policy
      - 'generic'            Unknown IAM JSON
    """
    keys = set(policy.keys())

    # RBAC signals
    if any(k in keys for k in ("permissions", "assignableScopes", "roleName", "roleType")):
        return "rbac"

    # Conditional Access signals
    if any(k in keys for k in ("conditions", "grantControls", "sessionControls")):
        return "conditional_access"

    # Nested properties (common Azure JSON wrapper)
    props = policy.get("properties", {})
    if isinstance(props, dict):
        if any(k in props for k in ("permissions", "assignableScopes")):
            return "rbac"
        if any(k in props for k in ("conditions", "grantControls")):
            return "conditional_access"

    return "generic"


# ── RBAC analysis ─────────────────────────────────────────────────────────────

def _flatten_actions(policy: dict) -> list[str]:
    """Extract all action strings from a RBAC policy (handles nested properties)."""
    actions: list[str] = []
    perms = (
        policy.get("permissions")
        or policy.get("properties", {}).get("permissions")
        or []
    )
    for perm in perms:
        if isinstance(perm, dict):
            actions.extend(perm.get("actions", []))
            actions.extend(perm.get("Actions", []))
    return [a.lower() for a in actions if isinstance(a, str)]


def _flatten_data_actions(policy: dict) -> list[str]:
    """Extract DataActions from a RBAC policy."""
    data_actions: list[str] = []
    perms = (
        policy.get("permissions")
        or policy.get("properties", {}).get("permissions")
        or []
    )
    for perm in perms:
        if isinstance(perm, dict):
            data_actions.extend(perm.get("dataActions", []))
            data_actions.extend(perm.get("DataActions", []))
    return [a.lower() for a in data_actions if isinstance(a, str)]


def _flatten_not_actions(policy: dict) -> list[str]:
    """Extract NotActions from a RBAC policy."""
    not_actions: list[str] = []
    perms = (
        policy.get("permissions")
        or policy.get("properties", {}).get("permissions")
        or []
    )
    for perm in perms:
        if isinstance(perm, dict):
            not_actions.extend(perm.get("notActions", []))
            not_actions.extend(perm.get("NotActions", []))
    return not_actions


def _get_assignable_scopes(policy: dict) -> list[str]:
    return (
        policy.get("assignableScopes")
        or policy.get("properties", {}).get("assignableScopes")
        or []
    )


def _analyse_rbac(policy: dict) -> list[dict]:
    """Run all RBAC checks and return finding list."""
    findings: list[dict] = []
    actions          = _flatten_actions(policy)
    data_actions     = _flatten_data_actions(policy)
    not_actions      = _flatten_not_actions(policy)
    assignable_scopes = _get_assignable_scopes(policy)
    description      = (
        policy.get("description")
        or policy.get("properties", {}).get("description")
        or ""
    )

    # ── Dangerous action pattern checks ───────────────────────────────────────
    for action in actions:
        for rule in DANGEROUS_ACTIONS:
            if re.search(rule["pattern"], action, re.IGNORECASE):
                findings.append({
                    "check_id":    rule["id"],
                    "label":       rule["label"],
                    "severity":    rule["severity"],
                    "owasp":       rule.get("owasp", ""),
                    "cis":         rule.get("cis", ""),
                    "matched":     action,
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                    "passed":      False,
                })

    # ── Structural checks ─────────────────────────────────────────────────────
    # STR-001: subscription-wide scope
    sub_scope = any(
        re.match(r"^/subscriptions/[^/]+$", s) for s in assignable_scopes
    ) or "/" in assignable_scopes

    findings.append({
        "check_id":    "STR-001",
        "label":       STRUCTURAL_CHECKS[0]["label"],
        "severity":    STRUCTURAL_CHECKS[0]["severity"],
        "owasp":       "LLM08",
        "cis":         "CIS Azure 1.1",
        "matched":     str(assignable_scopes),
        "description": STRUCTURAL_CHECKS[0]["description"],
        "remediation": STRUCTURAL_CHECKS[0]["remediation"],
        "passed":      not sub_scope,
    })

    # STR-002: NotActions present
    findings.append({
        "check_id":    "STR-002",
        "label":       STRUCTURAL_CHECKS[1]["label"],
        "severity":    STRUCTURAL_CHECKS[1]["severity"],
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.21",
        "matched":     str(not_actions) if not_actions else "none",
        "description": STRUCTURAL_CHECKS[1]["description"],
        "remediation": STRUCTURAL_CHECKS[1]["remediation"],
        "passed":      len(not_actions) == 0,
    })

    # STR-003: DataActions wildcard
    data_wildcard = any(re.search(r"\*", da) for da in data_actions)
    findings.append({
        "check_id":    "STR-003",
        "label":       STRUCTURAL_CHECKS[2]["label"],
        "severity":    STRUCTURAL_CHECKS[2]["severity"],
        "owasp":       "LLM06",
        "cis":         "CIS Azure 1.1",
        "matched":     str(data_actions) if data_wildcard else "none",
        "description": STRUCTURAL_CHECKS[2]["description"],
        "remediation": STRUCTURAL_CHECKS[2]["remediation"],
        "passed":      not data_wildcard,
    })

    # STR-004: Root assignable scope
    root_scope = "/" in assignable_scopes
    findings.append({
        "check_id":    "STR-004",
        "label":       STRUCTURAL_CHECKS[3]["label"],
        "severity":    STRUCTURAL_CHECKS[3]["severity"],
        "owasp":       "LLM08",
        "cis":         "CIS Azure 1.23",
        "matched":     "/" if root_scope else "not present",
        "description": STRUCTURAL_CHECKS[3]["description"],
        "remediation": STRUCTURAL_CHECKS[3]["remediation"],
        "passed":      not root_scope,
    })

    # STR-005: Description present
    findings.append({
        "check_id":    "STR-005",
        "label":       STRUCTURAL_CHECKS[4]["label"],
        "severity":    STRUCTURAL_CHECKS[4]["severity"],
        "owasp":       "",
        "cis":         "",
        "matched":     description[:60] if description else "missing",
        "description": STRUCTURAL_CHECKS[4]["description"],
        "remediation": STRUCTURAL_CHECKS[4]["remediation"],
        "passed":      bool(description.strip()),
    })

    return findings


# ── Conditional Access analysis ───────────────────────────────────────────────

def _analyse_conditional_access(policy: dict) -> list[dict]:
    """Run Conditional Access checks and return finding list."""
    findings: list[dict] = []
    props         = policy.get("properties", policy)
    conditions    = props.get("conditions", {})
    grant         = props.get("grantControls") or {}
    state         = props.get("state", "")
    users         = conditions.get("users", {})
    signin_risk   = conditions.get("signInRiskLevels", [])
    built_in      = grant.get("builtInControls", [])
    excluded_users = users.get("excludeUsers", []) + users.get("excludeGroups", [])

    # CA-001: MFA required
    mfa_required = "mfa" in [c.lower() for c in built_in]
    findings.append({
        "check_id":    "CA-001",
        "label":       CA_CHECKS[0]["label"],
        "severity":    CA_CHECKS[0]["severity"],
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.2",
        "matched":     str(built_in),
        "description": CA_CHECKS[0]["description"],
        "remediation": CA_CHECKS[0]["remediation"],
        "passed":      mfa_required,
    })

    # CA-002: Policy enabled
    is_enabled = state.lower() == "enabled"
    findings.append({
        "check_id":    "CA-002",
        "label":       CA_CHECKS[1]["label"],
        "severity":    CA_CHECKS[1]["severity"],
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.2",
        "matched":     state or "not set",
        "description": CA_CHECKS[1]["description"],
        "remediation": CA_CHECKS[1]["remediation"],
        "passed":      is_enabled,
    })

    # CA-003: Broad exclusions (more than 5 excluded objects = flag)
    broad = len(excluded_users) > 5
    findings.append({
        "check_id":    "CA-003",
        "label":       CA_CHECKS[2]["label"],
        "severity":    CA_CHECKS[2]["severity"],
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.3",
        "matched":     f"{len(excluded_users)} exclusions",
        "description": CA_CHECKS[2]["description"],
        "remediation": CA_CHECKS[2]["remediation"],
        "passed":      not broad,
    })

    # CA-004: Sign-in risk condition
    has_risk = bool(signin_risk)
    findings.append({
        "check_id":    "CA-004",
        "label":       CA_CHECKS[3]["label"],
        "severity":    CA_CHECKS[3]["severity"],
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.4",
        "matched":     str(signin_risk) if has_risk else "not configured",
        "description": CA_CHECKS[3]["description"],
        "remediation": CA_CHECKS[3]["remediation"],
        "passed":      has_risk,
    })

    # CA-005: Compliant device
    compliant = any(
        c.lower() in ("requirecompliantdevice", "requirehybridazureadjoineddevice")
        for c in built_in
    )
    findings.append({
        "check_id":    "CA-005",
        "label":       CA_CHECKS[4]["label"],
        "severity":    CA_CHECKS[4]["severity"],
        "owasp":       "LLM07",
        "cis":         "CIS Azure 1.5",
        "matched":     str(built_in),
        "description": CA_CHECKS[4]["description"],
        "remediation": CA_CHECKS[4]["remediation"],
        "passed":      compliant,
    })

    return findings


# ── Scoring ───────────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _score_findings(findings: list[dict]) -> dict[str, Any]:
    """Compute pass/fail counts and weighted risk score."""
    failures    = [f for f in findings if not f["passed"]]
    high_fails  = [f for f in failures if f["severity"] == "HIGH"]
    med_fails   = [f for f in failures if f["severity"] == "MEDIUM"]
    low_fails   = [f for f in failures if f["severity"] == "LOW"]

    weighted_fail = sum(SEVERITY_WEIGHT[f["severity"]] for f in failures)
    weighted_total = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    pass_pct = ((weighted_total - weighted_fail) / weighted_total * 100) if weighted_total else 0

    if high_fails:
        risk = "HIGH"
    elif med_fails:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "total_checks":   len(findings),
        "passed":         len(findings) - len(failures),
        "failed":         len(failures),
        "high_failures":  len(high_fails),
        "medium_failures":len(med_fails),
        "low_failures":   len(low_fails),
        "weighted_score": round(pass_pct, 1),
        "risk_level":     risk,
    }


def _risk_badge(level: str) -> str:
    return {"HIGH": "🔴 HIGH", "MEDIUM": "⚠  MEDIUM", "LOW": "✅ LOW"}.get(level, level)


def _risk_color(level: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(level, "white")


def _sev_color(sev: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")


# ── Terminal output ───────────────────────────────────────────────────────────

def _print_rich(policy_type: str, findings: list[dict], score: dict, policy: dict):
    risk    = score["risk_level"]
    color   = _risk_color(risk)
    role_name = (
        policy.get("roleName")
        or policy.get("properties", {}).get("roleName")
        or policy.get("displayName")
        or policy.get("properties", {}).get("displayName")
        or "Unknown"
    )

    # ── Summary panel ─────────────────────────────────────────────────────────
    summary = (
        f"[bold]Policy type:[/bold]     {policy_type.upper().replace('_', ' ')}\n"
        f"[bold]Name:[/bold]            {role_name}\n"
        f"[bold]Checks run:[/bold]      {score['total_checks']}\n"
        f"[bold]Passed:[/bold]          {score['passed']} / {score['total_checks']}\n"
        f"[bold]High severity:[/bold]   {score['high_failures']} failure(s)\n"
        f"[bold]Medium severity:[/bold] {score['medium_failures']} failure(s)\n"
        f"[bold]Weighted score:[/bold]  {score['weighted_score']:.0f}%\n"
        f"[bold]Overall risk:[/bold]    [{color}]{_risk_badge(risk)}[/{color}]"
    )
    console.print(Panel(
        summary,
        title="[bold cyan]IAM Policy Validator — Summary[/bold cyan]",
        border_style="cyan",
    ))

    # ── Findings table ─────────────────────────────────────────────────────────
    console.print()
    table = Table(
        title="IAM Policy Findings",
        box=box.DOUBLE_EDGE,
        header_style="bold white on dark_blue",
        show_lines=True,
        min_width=80,
    )
    table.add_column("Check",       style="dim cyan",  min_width=10)
    table.add_column("Finding",     style="white",     min_width=32)
    table.add_column("Severity",    justify="center",  min_width=10)
    table.add_column("OWASP",       justify="center",  min_width=8)
    table.add_column("CIS",         style="dim",       min_width=14)
    table.add_column("Result",      justify="center",  min_width=10)

    for f in findings:
        sc    = _sev_color(f["severity"])
        res   = "[green]✓ PASS[/green]" if f["passed"] else "[red]✗ FAIL[/red]"
        table.add_row(
            f["check_id"],
            f["label"],
            f"[{sc}]{f['severity']}[/{sc}]",
            f["owasp"] or "—",
            f["cis"] or "—",
            res,
        )

    console.print(table)

    # ── Remediation panel (failures only) ─────────────────────────────────────
    failures = [f for f in findings if not f["passed"]]
    if failures:
        console.print()
        rem_lines = []
        for f in sorted(failures, key=lambda x: SEVERITY_WEIGHT[x["severity"]], reverse=True):
            sc = _sev_color(f["severity"])
            rem_lines.append(
                f"  [{sc}][{f['severity']}][/{sc}] [{f['check_id']}] {f['label']}\n"
                f"  [dim]→ {f['remediation']}[/dim]"
            )
        console.print(Panel(
            "\n\n".join(rem_lines),
            title="[bold yellow]Remediation Recommendations[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        ))
    else:
        console.print()
        console.print(Panel(
            "[bold green]✓ No findings — policy meets least-privilege requirements.[/bold green]",
            border_style="green",
        ))

    console.print()


def _print_plain(policy_type: str, findings: list[dict], score: dict, policy: dict):
    print("\n" + "═" * 70)
    print("  ai-audit-kit — IAM Policy Validator")
    print("═" * 70)
    print(f"  Type  : {policy_type}")
    print(f"  Passed: {score['passed']}/{score['total_checks']}")
    print(f"  Risk  : {_risk_badge(score['risk_level'])}")
    print()
    for f in findings:
        status = "PASS" if f["passed"] else "FAIL"
        print(f"  [{status}] [{f['severity']}] {f['label']}")
        if not f["passed"]:
            print(f"         → {f['remediation']}")
    print("═" * 70)


# ── Audit log ─────────────────────────────────────────────────────────────────

def _save_audit_log(
    policy_type: str,
    findings: list[dict],
    score: dict,
    output_dir: str,
) -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir) / f"iam_audit_{ts}.json"

    log = {
        "audit_module":    "iam_validator",
        "toolkit_version": "0.1.0",
        "timestamp":       datetime.now().isoformat(),
        "policy_type":     policy_type,
        "score":           score,
        "findings":        findings,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    return out_path


# ── Entry point ───────────────────────────────────────────────────────────────

def run_iam_validation(file_path: str, output_dir: str = "reports"):
    """Main entrypoint called by llm_audit.py."""

    # Load and parse JSON
    try:
        raw = Path(file_path).read_text(encoding="utf-8")
        policy = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"Invalid JSON in {file_path}: {exc}"
        if RICH_AVAILABLE:
            console.print(f"[bold red]✗ JSON ERROR:[/bold red] {msg}")
        else:
            print(f"JSON ERROR: {msg}")
        return
    except Exception as exc:
        if RICH_AVAILABLE:
            console.print(f"[bold red]✗ ERROR:[/bold red] {exc}")
        else:
            print(f"ERROR: {exc}")
        return

    # Detect and analyse
    policy_type = _detect_policy_type(policy)

    if RICH_AVAILABLE:
        console.print(f"[dim]Detected policy type: [bold]{policy_type}[/bold] · running checks…[/dim]\n")

    if policy_type == "rbac":
        findings = _analyse_rbac(policy)
    elif policy_type == "conditional_access":
        findings = _analyse_conditional_access(policy)
    else:
        # Generic: run structural RBAC checks as best-effort
        if RICH_AVAILABLE:
            console.print("[yellow]⚠ Unknown policy type — running generic structural checks.[/yellow]\n")
        findings = _analyse_rbac(policy)

    score = _score_findings(findings)

    if RICH_AVAILABLE:
        _print_rich(policy_type, findings, score, policy)
    else:
        _print_plain(policy_type, findings, score, policy)

    try:
        log_path = _save_audit_log(policy_type, findings, score, output_dir)
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
    import tempfile, os

    _SAMPLE_RBAC = {
        "roleName": "AI Platform Engineer (Misconfigured)",
        "description": "",
        "assignableScopes": ["/subscriptions/00000000-0000-0000-0000-000000000000"],
        "permissions": [
            {
                "actions": [
                    "*",
                    "Microsoft.Authorization/roleAssignments/write",
                    "Microsoft.KeyVault/vaults/secrets/*",
                    "Microsoft.Storage/storageAccounts/*",
                ],
                "notActions": ["Microsoft.Authorization/*/Delete"],
                "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/*"],
                "notDataActions": [],
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(_SAMPLE_RBAC, f)
        tmp = f.name

    print("Running standalone IAM validation test...")
    run_iam_validation(file_path=tmp, output_dir="reports")
    os.unlink(tmp)
    