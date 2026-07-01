# SAST playground

A self-contained Static Application Security Testing (SAST) pipeline that runs
in GitHub Actions and surfaces findings in the repository's **Security → Code
scanning** tab.

Three open-source, SARIF-capable scanners run as independent jobs, and a small
Go binary merges their output, deduplicates it, and acts as a CI gate that fails
the build when a finding reaches a configurable severity.

```
push / pull_request
        │
        ├── Semgrep CE  ──► SARIF ─► Security tab (category: semgrep)  ─┐
        ├── CodeQL      ──► SARIF ─► Security tab (category: codeql)   ─┤
        ├── Gitleaks    ──► SARIF ─► Security tab (category: gitleaks) ─┤
        │                                                              ▼
        └── gate ◄── downloads all SARIF ◄────────────── sarifgate (Go binary)
                     merge → dedup → threshold → exit code
```

## What's in here

| Path | What it is |
|---|---|
| `.github/workflows/sast.yml` | The single workflow: one job per scanner plus the gate. |
| `cmd/sarifgate/` | `main` package for the Go gate binary (CLI). |
| `internal/sarif/` | SARIF model, merge/dedup, severity resolution, and tests. |
| `semgrep-rules/` | Custom Semgrep rules (insecure deserialization, hardcoded secret, Flask debug). |
| `vulnerable-app/` | A deliberately vulnerable Flask app so every scanner fires. |
| `Makefile` | Local build/test/gate helpers. |

## The scanners

| Tool | What it does here | Configuration |
|---|---|---|
| **Semgrep CE** | Primary pattern scanner. | `p/owasp-top-ten`, `p/security-audit`, `p/secrets`, plus the local `semgrep-rules/` directory. |
| **CodeQL** | Deep dataflow / taint tracking. | `security-extended` query suite, Python. |
| **Gitleaks** | Hardcoded secrets across **full git history**. | Default ruleset, `fetch-depth: 0`. |

Each scanner uploads its SARIF with a **distinct category** via
`github/codeql-action/upload-sarif`, so results stay separable in the Security
tab and re-runs replace (rather than duplicate) prior results.

## The gate binary (`sarifgate`)

A single static Go binary with no third-party dependencies. It:

1. **Merges** every input SARIF document into one report.
2. **Deduplicates** findings by a stable fingerprint — `sha256(ruleID + file +
   line)` — so the same defect reported by two scanners collapses to one
   finding. On a collision the higher severity wins and the finding stays active
   if it is active in any input.
3. **Resolves severity** for each finding, preferring the rule's numeric
   `security-severity` (the same value GitHub uses), and falling back to the
   SARIF `level`. Scores map to buckets exactly as GitHub does: `≥9.0`
   CRITICAL, `≥7.0` HIGH, `≥4.0` MEDIUM, `>0` LOW.
4. **Gates** the build: exits non-zero when any **active** finding (suppressed
   findings are ignored) is at or above the threshold (default **HIGH**).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No active finding at or above the threshold. |
| `1` | Threshold breached — the gate fails the build. |
| `2` | Usage or I/O error (bad flag, unreadable/invalid SARIF). |

### Usage

```
sarifgate [flags] <input.sarif> [<input.sarif> ...]

  -threshold  CRITICAL|HIGH|MEDIUM|LOW|NONE   severity that fails the build (default HIGH)
  -output     <path>                          write the merged SARIF document
  -summary    <path>                          append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)
  -glob                                       treat positional args as globs and expand them
  -no-fail                                    report only; always exit 0 (dry run)
```

### Build

Requires Go 1.23+.

```sh
# Single static binary (CGO disabled, stripped):
make build            # -> bin/sarifgate

# or directly:
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/sarifgate ./cmd/sarifgate

# Run the unit tests:
make test
```

### Try it locally

```sh
# Generate a SARIF file from the custom rules against the vulnerable app:
pip install semgrep
semgrep scan --config semgrep-rules/ --sarif --output semgrep.sarif vulnerable-app/

# Gate on it (HIGH by default) — this exits 1 because the app is vulnerable:
./bin/sarifgate -threshold HIGH -output merged.sarif semgrep.sarif

# Lower-severity dry run that never fails:
./bin/sarifgate -threshold CRITICAL -no-fail semgrep.sarif
```

## The vulnerable target

`vulnerable-app/` is a tiny Flask app whose only job is to make every scanner
fire on real, reachable code. Each defect is tagged in a comment with the tool
expected to catch it. See [`vulnerable-app/README.md`](vulnerable-app/README.md)
for the full table; at a minimum it covers SQL injection, OS command injection,
insecure deserialization, a hardcoded secret, and a debug flag left enabled.

> ⚠️ The vulnerable app is for scanning only. Never deploy or run it against
> untrusted input.

## Using it on your own repository

1. **Fork** this repository (or copy the `.github/`, `cmd/`, `internal/`,
   `semgrep-rules/` directories and `go.mod` into your own).
2. **Enable code scanning.** On GitHub: **Settings → Code security and analysis
   → Code scanning**. The workflow uploads SARIF itself, so you do **not** need
   to enable CodeQL's "default setup" — if you do, disable it to avoid a clash
   with this "advanced" workflow. For private repositories, code scanning
   requires GitHub Advanced Security.
3. **Push** to any branch, or open a pull request. The `SAST` workflow runs on
   both `push` and `pull_request`.
4. **Read the results.** Open the **Security → Code scanning** tab. Filter by
   **Tool** to see Semgrep, CodeQL, and Gitleaks results separately (they each
   uploaded under their own category). Each alert links to the exact line, the
   rule, and a description. Pull requests also get inline annotations.
5. **The gate.** The `SAST gate` job posts a Markdown summary (severity
   breakdown + every deduplicated finding) to the run's summary page and fails
   the build when something reaches the threshold. Change the threshold by
   editing `SAST_THRESHOLD` at the top of `.github/workflows/sast.yml`
   (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `NONE`).

### Adapting it to your stack

- **Languages:** change `languages:` in the CodeQL job and point Semgrep at the
  relevant rulesets. Semgrep auto-detects languages from the files it scans.
- **Custom rules:** drop more `.yml` files into `semgrep-rules/`. Give each rule
  a `metadata.security-severity` score so the gate (and GitHub) can bucket it.
- **More scanners:** any SARIF-producing tool can be added as another job that
  uploads with its own category and shares its SARIF as an artifact named
  `sarif-<tool>`; the gate picks up every `*.sarif` artifact automatically.
