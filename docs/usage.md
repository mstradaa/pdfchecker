# Usage Reference

Complete command-line reference for PDF Security Checker. For installation and the
quick start, see the [README](../README.md).

- [Options](#options)
- [Policies](#policies)
- [Bulk Scans and Related Samples](#bulk-scans-and-related-samples)
- [Password-Protected PDFs](#password-protected-pdfs)
- [URL Discovery](#url-discovery)
- [Local YARA Rules](#local-yara-rules)
- [JSON Output](#json-output)
- [Indicator Export](#indicator-export)
- [Threat-Intelligence Keys](#threat-intelligence-keys)
- [Limits](#limits)

## Options

Pass one action followed by a PDF file or a folder:

```bash
pdfchecker -m suspicious.pdf        # extract metadata
pdfchecker -rs suspicious.pdf       # compute a risk score
pdfchecker -r ./samples/            # generate a report for every PDF in a folder
```

### Actions

| Option | Description |
| --- | --- |
| `-a, --analyze` | Full terminal scan with coverage, optional policies, YARA, and grouping |
| `-l, --links` | Extract, defang, and optionally check links |
| `-rs, --risk-score` | Compute a 0–100 risk score across all modules |
| `-m, --metadata` | Extract document and file-system metadata |
| `-js, --javascript` | Detect and analyze JavaScript |
| `-ef, --embedded-files` | Detect and optionally extract embedded files |
| `-sa, --structure` | Detect structural anomalies |
| `-qr, --qr-codes` | Detect and decode QR codes (requires the `qr` extra) |
| `-hc, --hash-checker` | Compute MD5, SHA-1, and SHA-256 hashes |
| `-r, --report` | Generate a comprehensive PDF report |
| `-i, --export-indicators` | Export URL, domain, and JavaScript indicators |

### Full scan options (with `-a`)

| Option | Description |
| --- | --- |
| `--policy FILE` | Apply a JSON policy file (see [Policies](#policies)) |
| `--fail-on-risk N` | Reject a file at or above this score (0–100) |
| `--yara RULES` | Match local YARA rules; repeat for more files (requires the `yara` extra) |
| `--campaigns` | Group a folder by shared URLs, scripts, and attachment hashes |
| `--recursive` | Include subfolders in a folder scan |

### Encrypted PDFs (all actions)

| Option | Description |
| --- | --- |
| `--ask-password` | Prompt once without echo and use the password for the whole batch |
| `--password-env NAME` | Read the PDF password from this environment variable |

### Input limits (all actions)

| Option | Description |
| --- | --- |
| `--max-size MB` | Analyze PDFs up to this size (default: 100, max: 2048); see [Limits](#limits) |

### Output

| Option | Description |
| --- | --- |
| `--json` | Emit machine-readable JSON instead of interactive text |
| `--format {json,stix}` | Select the indicator export format for `-i` (default: JSON) |
| `-o, --output FILE` | Write an indicator export to a file instead of stdout |

### Reputation service configuration

| Option | Description |
| --- | --- |
| `--set-api-key` | Store a VirusTotal key securely |
| `--show-api-key` | Display the stored VirusTotal key, masked |
| `--remove-api-key` | Delete the stored VirusTotal key |
| `--set-urlhaus-api-key` | Store a URLhaus Auth-Key securely |
| `--show-urlhaus-api-key` | Display the stored URLhaus Auth-Key, masked |
| `--remove-urlhaus-api-key` | Delete the stored URLhaus Auth-Key |
| `--edit-api-limit` | View or change the per-provider call limit (default 10) |

## Policies

Use `--fail-on-risk N` for a simple inclusive threshold, or `--policy FILE` for a
reusable JSON policy:

```json
{
  "risk_threshold": 55,
  "reject_javascript": true,
  "reject_attachments": true,
  "reject_link_mismatch": true,
  "reject_yara": true,
  "require_complete": true
}
```

All keys are optional; omitted boolean rules are disabled. `--fail-on-risk`
overrides the policy's threshold. `reject_yara` requires
[`--yara RULES`](#local-yara-rules), and `require_complete` blocks files whose
coverage is incomplete. An unevaluable required check is reported as unknown,
never as a policy pass.

```bash
pdfchecker -a samples/ --policy policy.json --yara rules.yar
```

## Bulk Scans and Related Samples

Every action accepts either a single PDF or a folder. `-a FOLDER` runs without
prompts, ranks results by risk, and summarizes failures and policy decisions; add
`--recursive` to include subfolders. For the other actions, a folder input is
scanned non-recursively, asks for confirmation, and asks interactive questions once
for the whole batch. A malformed PDF cannot bring down the run. Embedded-file
extraction is offered in single-file mode only.

Add `--campaigns` to group related files. Grouping uses exact shared URLs, complete
script SHA-256 hashes, and attachment SHA-256 hashes. URL scheme/host casing and
default ports are normalized; paths and query strings remain significant.

Each group lists its files and the indicators connecting them. Connections can be
transitive: A shares a script with B, while B shares a URL with C. Shared domains
alone do not create groups. These groups are investigation leads, not attribution;
common benign links and scripts can connect unrelated documents.

## Password-Protected PDFs

All PDF analysis actions accept either a hidden prompt or a named environment
variable. A batch uses the same password for each file; wrong passwords produce
per-file failures while other PDFs continue:

```bash
pdfchecker -a encrypted.pdf --ask-password
pdfchecker -a samples/ --password-env PDF_PASSWORD --json
pdfchecker -i encrypted.pdf --password-env PDF_PASSWORD -o indicators.json
```

Passwords are not accepted as plaintext command-line arguments, saved in
configuration, or included in results. File hashes refer to the original
encrypted bytes.

## URL Discovery

Link analysis, full scans, risk scoring, reports, and indicator exports inspect
annotation destinations, visible page text, URI/submission/import actions, and
recovered JavaScript, keeping the source page, object, or script of each URL.

A visible URL that names a different site than its annotation destination is
flagged as a mismatch, adds 10 points to the links risk category, and can be
rejected with the `reject_link_mismatch` [policy](#policies) rule.
`www.` prefixes and links between a site and its own subdomains are not
mismatches; redirects and benign tracking links can still cause them.

Discovery never visits URLs or executes JavaScript. Dynamically assembled URLs,
image-only text without a QR code, and arbitrary obfuscation may not be recovered.

## Local YARA Rules

With the `yara` extra installed, pass one or more source rule files:

```bash
pdfchecker -a suspicious.pdf --yara rules.yar
pdfchecker -a samples/ --yara rules.yar --yara organization.yar --policy policy.json
```

Rules match original PDF bytes, recovered JavaScript, attachments, and hidden
embedded streams, including content decrypted with the supplied password.
Findings identify the rule, namespace, tags, and content location. Rule syntax
follows the [YARA Python documentation](https://yara.readthedocs.io/en/stable/yarapython.html).

## JSON Output

Adding `--json` to any action prints one structured JSON document to stdout.

```bash
# Risk score of a single PDF as JSON
pdfchecker -rs suspicious.pdf --json

# Score every PDF in a folder and extract path/score pairs
pdfchecker -rs ./samples/ --json 2>/dev/null | jq '[.files[] | {path, score: .result.score, level: .result.level}]'
```

JSON mode is non-interactive (except an explicitly requested `--ask-password`
prompt): no prompts, no threat-intelligence enrichment, and no file extraction, so
it is safe to run unattended. Progress and warnings go to stderr. The schema is
versioned via `schema_version`, and per-file failures are listed in
`summary.failed` rather than reported as a clean risk score.

## Indicator Export

Indicator export collects every URL found by
[URL discovery](#url-discovery), URL-bearing QR codes (when QR support
is installed), and embedded JavaScript. It derives normalized IDNA domains from the
URLs, deduplicates values across the input, and keeps every PDF/source location as
provenance. STIX output is a STIX 2.1 bundle using `url`, `domain-name`, and base64
`artifact` observable patterns.

```bash
# Stream a versioned native JSON export
pdfchecker --export-indicators suspicious.pdf --format json

# Export every PDF in a folder as one STIX 2.1 bundle
pdfchecker -i ./samples/ --format stix --output indicators.stix.json
```

The command is non-interactive and performs no threat-intelligence lookups. Files
written with `--output` get owner-only permissions because recovered JavaScript may
be sensitive.

## Threat-Intelligence Keys

VirusTotal and URLhaus (abuse.ch) enrichment are independent; configure either or
both. When enabled, positive VirusTotal detections or a known URLhaus malware record
raise the risk score to at least 80 (Critical), shown separately from the local
analysis score.

```bash
pdfchecker --set-api-key               # store a VirusTotal key securely
pdfchecker --set-urlhaus-api-key       # store a URLhaus Auth-Key securely
pdfchecker --edit-api-limit            # per-provider call limit (default 10)
```

A free URLhaus Auth-Key is available from the [abuse.ch Authentication Portal](https://auth.abuse.ch/).
Keys can also be supplied through environment variables, which take precedence over
stored keys and are useful on CI or headless machines:

| Provider | Environment variable |
| --- | --- |
| VirusTotal | `PDFCHECKER_VT_API_KEY` (or `VT_API_KEY`) |
| URLhaus | `PDFCHECKER_URLHAUS_AUTH_KEY` (or `URLHAUS_AUTH_KEY`) |

Each URL or hash is sent to each provider at most once per run, within that
provider's call limit for the whole run.

## Limits

Limits keep the cost of any single file bounded. When one is reached, the affected
check is marked as limited in coverage.

| Scope | Limit |
| --- | --- |
| Input file size | 100 MB by default; raise it up to 2048 MB with `--max-size MB` (larger files are skipped) |
| Text and link discovery | 1,000 pages, 2 million characters per page, 10,000 distinct URLs per PDF |
| QR decoding | 200 pages |
| YARA matching | 30 seconds, 1,000 targets, 100 MiB per target, 200 MiB total per PDF |
