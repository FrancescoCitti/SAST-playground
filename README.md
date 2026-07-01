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
| `third-party/pygoat` | OWASP PyGoat, a well-known vulnerable Django app, pinned as a submodule. |
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

## Sample targets

The repository ships two deliberately vulnerable applications so the scanners
fire on real, reachable code. Both are for scanning only and must never be
deployed or exposed to untrusted input.

- **`vulnerable-app/`** — a tiny in-repo Flask app. Each defect is tagged in a
  comment with the tool expected to catch it. It covers, at a minimum, SQL
  injection, OS command injection, insecure deserialization, a hardcoded secret,
  and a debug flag left enabled. See
  [`vulnerable-app/README.md`](vulnerable-app/README.md) for the full table.
- **`third-party/pygoat`** — [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat),
  a well-known intentionally vulnerable Django application, included as a git
  submodule pinned to a fixed commit. It provides a larger, realistic Python
  codebase for the Python-based scanners (CodeQL, Semgrep) to exercise.

Because PyGoat is a submodule, a plain clone leaves its directory empty. It is
fetched with:

```sh
git clone --recurse-submodules <repo-url>
# or, in an existing clone:
git submodule update --init --recursive
```

The workflow checks out submodules automatically, so CI always scans PyGoat.

## Using the pipeline in another repository

1. **Fork or copy.** Forking this repository is the quickest start; alternatively
   the `.github/`, `cmd/`, `internal/`, and `semgrep-rules/` directories plus
   `go.mod` can be copied into another project.
2. **Enable code scanning.** Under **Settings → Code security and analysis →
   Code scanning**, code scanning must be enabled. The workflow uploads SARIF
   itself, so CodeQL's "default setup" is not required — and if it is enabled it
   should be disabled, to avoid clashing with this "advanced" workflow. Private
   repositories require GitHub Advanced Security for code scanning.
3. **Push or open a pull request.** The `SAST` workflow runs on both `push` and
   `pull_request`.
4. **Read the results.** The **Security → Code scanning** tab lists every alert,
   filterable by **Tool** so Semgrep, CodeQL, and Gitleaks stay separate (each
   uploaded under its own category). Every alert links to the exact line, the
   rule, and a description. Pull requests also receive inline annotations.
5. **The gate.** The `SAST gate` job posts a Markdown summary (severity
   breakdown plus every deduplicated finding) to the run's summary page and
   fails the build when a finding reaches the threshold. The threshold is set by
   the `SAST_THRESHOLD` value at the top of `.github/workflows/sast.yml`
   (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `NONE`).

### Adapting it to another stack

- **Languages:** adjust `languages:` in the CodeQL job and point Semgrep at the
  relevant rulesets. Semgrep auto-detects languages from the files it scans.
- **Custom rules:** more `.yml` files can be added to `semgrep-rules/`. Each rule
  should carry a `metadata.security-severity` score so the gate (and GitHub) can
  bucket it.
- **More scanners:** any SARIF-producing tool can be added as another job that
  uploads with its own category and shares its SARIF as an artifact named
  `sarif-<tool>`; the gate picks up every `*.sarif` artifact automatically.
