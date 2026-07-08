# PDF Security Checker

PDF Security Checker is a command-line tool that inspects PDF files for security threats and extracts forensic information. It combines cryptographic hashing, embedded-script analysis, structural inspection, and threat-intelligence enrichment into a single risk score, and can produce tamper-evident PDF reports suitable for professional use.

A sample of the generated report is available [here](https://github.com/Strateo/pdfchecker/blob/main/docs/report_sample.pdf).

## Available Features

- **Link extraction** — Finds all URIs in a document, optionally displays them defanged, and checks them against VirusTotal.
- **Metadata analysis** — Extracts document properties, PDF/A and PDF/X compliance, and file-system attributes (size, timestamps, permissions).
- **JavaScript detection** — Extracts document-, page-, and form-level JavaScript and flags patterns that suggest malicious intent, distinguishing auto-run scripts from inert ones.
- **Embedded file detection** — Enumerates attachments and hidden `/EmbeddedFile` streams, classifies them by extension, magic bytes, and content mismatches, hashes each payload, and can safely extract them.
- **Structural anomaly detection** — Flags dangerous constructs such as `/Launch`, `/OpenAction`, `/AA`, XFA forms, RichMedia, remote GoTo, and name-obfuscated keywords, and reports integrity signals like incremental updates and repaired cross-reference tables.
- **QR code detection** — Renders pages and decodes QR codes so URLs hidden in images can be reviewed, defanged, and checked like ordinary links (optional dependency).
- **Risk scoring** — Combines all modules into a single weighted 0–100 score with a per-category breakdown and a Minimal-to-Critical rating; decisive indicators raise a severity floor so they cannot be averaged away.
- **Hashing** — Computes MD5, SHA-1, and SHA-256 hashes for integrity and authenticity, with optional VirusTotal lookup of the SHA-256 hash.
- **Report generation** — Produces a comprehensive PDF report covering every module, including both the original file's hash and the report's own hash for integrity verification.
- **Bulk processing** — Any analysis accepts a folder and processes every PDF in it, running work in parallel and ranking files by risk.
- **Machine-readable output** — `--json` emits a single structured document to stdout for use in scripts, CI pipelines, or mail-gateway automation.

## Installation

PDF Security Checker requires Python 3.8 or higher.

```bash
# Clone the repository
git clone https://github.com/mstradaa/pdfchecker.git
cd pdfchecker

# Install (provides the `pdfchecker` command)
pip install -e .

# Optional: enable QR code detection
pip install -e '.[qr]'
```

The tool can also be run without installing: `python pdfchecker/main.py <options>`.

## How to Use It

Pass one analysis option followed by a PDF file (or a folder for bulk mode):

```bash
pdfchecker -m suspicious.pdf        # extract metadata
pdfchecker -rs suspicious.pdf       # compute a risk score
pdfchecker -r ./samples/            # generate a report for every PDF in a folder
```

### Analysis Options

| Option | Description |
| --- | --- |
| `-hc, --hash-checker` | Compute MD5, SHA-1, and SHA-256 hashes |
| `-l, --links` | Extract, defang, and optionally check links |
| `-m, --metadata` | Extract document and file-system metadata |
| `-js, --javascript` | Detect and analyze JavaScript |
| `-ef, --embedded-files` | Detect and optionally extract embedded files |
| `-sa, --structure` | Detect structural anomalies |
| `-qr, --qr-codes` | Detect and decode QR codes |
| `-rs, --risk-score` | Compute a 0–100 risk score across all modules |
| `-r, --report` | Generate a comprehensive PDF report |
| `--json` | Emit machine-readable JSON instead of interactive text |

Each option accepts either a single PDF or a folder path.

### Bulk Mode

When a folder is given, the tool lists the PDFs found (non-recursive) and asks for confirmation before scanning. Interactive questions are asked once and applied to the whole batch. Files are processed in parallel — hashing in a thread pool and PyMuPDF analyses in isolated worker processes, so a malformed PDF cannot bring down the run. VirusTotal checks share one call budget across the batch, files above the 100MB limit are skipped, and risk-scoring mode ranks results highest-first. Embedded-file extraction is offered in single-file mode only.

### JSON Output

Adding `--json` to any analysis option makes the tool print one structured JSON document to stdout, like an API response, so results can be consumed by other programs.

```bash
# Risk score of a single PDF as JSON
pdfchecker -rs suspicious.pdf --json

# Score every PDF in a folder and extract path/score pairs
pdfchecker -rs ./samples/ --json 2>/dev/null | jq '[.files[] | {path, score: .result.score, level: .result.level}]'
```

JSON mode is fully non-interactive: no prompts, no VirusTotal enrichment, and no file extraction, so it is safe to run unattended. Only the JSON document goes to stdout; progress and warnings go to stderr. Exit codes are `0` on completion (bulk runs return `0` even when individual files fail, check `summary.failed`), `1` on a hard failure, and `2` on a usage error. The schema is versioned via `schema_version`.

### VirusTotal API Key

```bash
pdfchecker --set-api-key       # store your key securely
pdfchecker --show-api-key      # display it, masked
pdfchecker --remove-api-key    # delete the stored key
pdfchecker --edit-api-limit    # view or change the per-operation call limit (default 10)
```

The key can also be supplied through the `PDFCHECKER_VT_API_KEY` (or `VT_API_KEY`) environment variable, which takes precedence over the stored key and is useful on CI or headless machines.

## Security Considerations

- **Input validation** — File type, path, and size are validated (100MB limit), and JavaScript/metadata extraction is length-capped to prevent resource exhaustion. A memory guard aborts on decompression bombs.
- **Secure API handling** — VirusTotal traffic is HTTPS-only with strict timeouts, duplicate URLs are checked once, and API keys are cleaned from memory after use.
- **Key storage** — Keys are stored in the OS-native keychain (Keychain, Credential Manager, GNOME Keyring, KWallet); insecure plaintext backends are rejected. An environment variable can be used on headless systems instead.
- **Forensic integrity** — Reports include both the original file's hash and the report's own hash, UTC timestamps, and tool-version tagging to support reproducible, evidentiary-grade analysis.
- **Data protection** — No sensitive data is cached to disk, in-memory cleanup avoids residual traces, and logs are sanitized of identifying information.

## Roadmap

- [ ] Abuse.ch enrichment support.
- [ ] Export extracted indicators (URLs, domains, JS strings) in STIX / JSON.
- [ ] YARA rule scanning against raw PDF streams.
