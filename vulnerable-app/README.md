# Deliberately vulnerable target

> ⚠️ **Do not deploy this.** Every file here contains intentional security
> defects whose only purpose is to make each scanner in the pipeline fire on
> real, reachable code.

Each vulnerability is tagged in a comment with the tool(s) expected to flag it:

| # | Vulnerability | File | Expected tool(s) |
|---|---|---|---|
| 1 | SQL injection | `app/db.py` | Semgrep, CodeQL |
| 2 | OS command injection | `app/views.py` | Semgrep, CodeQL |
| 3 | Insecure deserialization (pickle) | `app/views.py` | Semgrep (custom rule), CodeQL |
| 4 | Hardcoded secret | `app/config.py` | Gitleaks, Semgrep (custom + p/secrets) |
| 5 | Debug flag left enabled | `app/__main__.py` | Semgrep (custom rule) |

The custom Semgrep rules that back rows 3–5 live in [`../semgrep-rules`](../semgrep-rules).
