# Contributing to ai-audit-kit

Thanks for your interest in contributing! This project welcomes PRs,
bug reports, and suggestions from the community.

---

## Ways to Contribute

- **Bug reports** — open an issue with steps to reproduce
- **New payload tests** — add adversarial prompts to `modules/prompt_guard.py`
- **Governance checks** — extend the NIST/OWASP rubric in `modules/governance_check.py`
- **New entity types** — add Presidio recognisers to `modules/pii_scanner.py`
- **IAM rules** — add Azure or AWS policy patterns to `modules/iam_validator.py`
- **Documentation** — improve README, add examples, fix typos

---

## Getting Started

```bash
# Fork and clone
git clone https://github.com/hanifs/ai-audit-kit.git
cd ai-audit-kit

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Verify your setup
python llm_audit.py --module pii --input "Test: John Smith, SSN 123-45-6789"
python llm_audit.py --module prompt --mode offline
python llm_audit.py --module governance --file samples/policy.txt
python llm_audit.py --module iam --file samples/rbac_policy.json
```

---

## Contribution Guidelines

1. **Open an issue first** for significant changes
2. **One feature per PR** — keeps reviews manageable
3. **Follow existing code style** — docstrings, type hints, Rich output patterns
4. **Test all 4 modules** before submitting
5. **No real PII in samples** — all sample data must be fictional

---

## Adding Prompt Guard Payloads

```python
{
    "id":       "LLM01-009",
    "owasp":    "LLM01",
    "category": "Direct Injection",
    "severity": "HIGH",
    "payload":  "Your adversarial prompt here",
    "detect":   ["keyword1", "keyword2"],
}
```

---

## Adding Governance Checks

```python
{
    "id":          "GOV-1.1-c",
    "framework":   "NIST GOVERN",
    "category":    "GOVERN 1.1 — Label",
    "weight":      2,
    "keywords":    [
        ["term1", "term2"],
        ["alternative"],
    ],
    "description": "What this check validates",
}
```

---

## Commit Message Format

```
feat: add LLM03 training data poisoning payloads
fix: correct HIPAA Safe Harbor mapping for DATE_TIME
docs: add AWS IAM policy example to samples/
chore: update requirements.txt
```

---

## License

By contributing, you agree your contributions will be licensed under
the project's [MIT License](LICENSE).
