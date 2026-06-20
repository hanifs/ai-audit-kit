# ai-audit-kit 🛡️

> Open-source AI governance and security audit toolkit — runs 100% locally, zero hosting costs.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![NIST AI RMF](https://img.shields.io/badge/framework-NIST%20AI%20RMF-green.svg)](https://airc.nist.gov)
[![OWASP LLM Top 10](https://img.shields.io/badge/framework-OWASP%20LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

The first open-source tool combining **NIST AI RMF + OWASP LLM Top 10 + PII/HIPAA** in a single auditor workflow. Built for AI governance consultants, red-team engineers, and compliance auditors.

---

## Modules

| Module | Purpose | Standard | Cost |
|--------|---------|----------|------|
| **PII Scanner** | Detect & redact 15+ entity types | HIPAA Safe Harbor | Free |
| **Prompt Guard** | Adversarial injection testing | OWASP LLM01–LLM09 | Free (offline) / BYOK (live) |
| **Governance Scorecard** | Score AI policy documents | NIST AI RMF + OWASP | Free |
| **IAM Validator** | Azure RBAC least-privilege audit | CIS / Zero-Trust | Free |

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/your-org/ai-audit-kit.git
cd ai-audit-kit
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Run each module
python llm_audit.py --module pii --input "Call John Smith at 555-867-5309, SSN 123-45-6789"
python llm_audit.py --module pii --file data/sample.txt

python llm_audit.py --module prompt --mode offline
python llm_audit.py --module prompt --mode live   # requires ANTHROPIC_API_KEY or OPENAI_API_KEY

python llm_audit.py --module governance --file policy.txt

python llm_audit.py --module iam --file rbac_policy.json
```

---

## Framework Mapping

### NIST AI RMF Coverage

| RMF Function | Subcategory | Module | Check |
|---|---|---|---|
| GOVERN | 1.1 — Policies & procedures | Governance Scorecard | Heuristic keyword analysis |
| GOVERN | 1.2 — Accountability | Governance Scorecard | Ownership/approval clause detection |
| GOVERN | 1.3 — Organizational risk tolerance | Governance Scorecard | Risk language scoring |
| GOVERN | 2.1 — Roles & responsibilities | IAM Validator | RBAC role scope audit |
| MAP | 1.1 — AI use context | Governance Scorecard | Use-case limitation clause |
| MAP | 2.2 — Risk categorization | Governance Scorecard | Risk tier language |
| MAP | 5.1 — Privacy risk | PII Scanner | HIPAA Safe Harbor entity detection |
| MEASURE | 2.1 — Evaluation plans | Governance Scorecard | Testing/evaluation clause |
| MEASURE | 2.5 — Bias/fairness | Governance Scorecard | Fairness language detection |
| MANAGE | 1.3 — Incident response | Governance Scorecard | Incident/breach clause |
| MANAGE | 2.4 — Security controls | Prompt Guard + IAM | Injection + RBAC tests |

### OWASP LLM Top 10 Coverage

| OWASP ID | Vulnerability | Module | Test Type |
|---|---|---|---|
| LLM01 | Prompt Injection | Prompt Guard | Direct + indirect injection payloads |
| LLM02 | Insecure Output Handling | Prompt Guard | Output boundary tests |
| LLM04 | Model DoS | Prompt Guard | Repetition/overload probes |
| LLM06 | Sensitive Info Disclosure | PII Scanner + Prompt Guard | PII leak + extraction tests |
| LLM07 | Insecure Plugin Design | IAM Validator | Excessive permission checks |
| LLM08 | Excessive Agency | Prompt Guard | Autonomous action boundary tests |
| LLM09 | Overreliance | Prompt Guard | Hallucination boundary tests |
| LLM10 | Model Theft | Prompt Guard | System prompt extraction tests |

---

## Output Format

```
╔══════════════════════════════════════════════════════╗
║         ai-audit-kit — Compliance Report             ║
╠══════════════════╦══════════╦═══════════╦════════════╣
║ Test Category    ║ Tests Run║ Pass      ║ Risk Level ║
╠══════════════════╬══════════╬═══════════╬════════════╣
║ OWASP LLM01      ║ 8        ║ 6/8 (75%) ║ ⚠ MEDIUM  ║
║ OWASP LLM06      ║ 5        ║ 5/5 (100%)║ ✅ LOW     ║
║ NIST GOVERN 1.1  ║ 4        ║ 3/4 (75%) ║ ⚠ MEDIUM  ║
║ PII/HIPAA        ║ 6        ║ 6/6 (100%)║ ✅ LOW     ║
║ RAG Injection    ║ 4        ║ 2/4 (50%) ║ 🔴 HIGH   ║
╠══════════════════╬══════════╬═══════════╬════════════╣
║ OVERALL SCORE    ║ 27       ║ 22/27(81%)║ ⚠ MEDIUM  ║
╚══════════════════╩══════════╩═══════════╩════════════╝
```

---

## Cost Model

| Mode | Cost | Requires |
|------|------|---------|
| All modules (default) | **$0** | Python 3.11+ |
| Module 2 — live mode | Pay-per-use | `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` |

No hosting, no server, no ongoing expenses.

---

## Module 1 — PII Scanner

Detects and redacts 15+ entity types using Microsoft Presidio:

| Entity | HIPAA Safe Harbor | Example |
|--------|-----------------|---------|
| PERSON | ✅ | John Smith |
| EMAIL_ADDRESS | ✅ | john@example.com |
| PHONE_NUMBER | ✅ | 555-867-5309 |
| US_SSN | ✅ | 123-45-6789 |
| CREDIT_CARD | ✅ | 4111-1111-1111-1111 |
| DATE_TIME | ✅ | 01/15/1985 |
| US_DRIVER_LICENSE | ✅ | D1234567 |
| MEDICAL_LICENSE | ✅ | ML-9988776 |
| IP_ADDRESS | ✅ | 192.168.1.1 |
| URL | ✅ | https://patient-portal.com |
| LOCATION | ✅ | 123 Main St, Chicago |
| NRP (nationality) | ✅ | American |

---

## Contributing

PRs welcome. Please open an issue first for major changes.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/module-improvement`)
3. Commit changes (`git commit -m 'Add hallucination boundary tests'`)
4. Push and open a PR

---

## License

MIT — fork freely, retain attribution.

---

*Built for AI governance professionals. Not a substitute for formal legal or compliance review.*
