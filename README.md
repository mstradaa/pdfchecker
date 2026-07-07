# PDF Security Checker

![pdfc_logo](./docs/logo.png)

## Overview

**PDF Security Checker** is a cross-platform tool designed to evaluate PDF files for security threats and extract forensic-value information. It detects malicious indicators through hash validation, embedded script analysis, and metadata inspection. Reports are generated with forensic integrity in mind, incorporating cryptographic proof and principles of reproducibility.

You can find a sample of the generated report [here](https://github.com/Strateo/pdfchecker/blob/main/docs/Report_sample.pdf).

## Features

### 1. Link Extraction and Analysis
- **URI Extraction**: Identifies and extracts all URI links embedded within a PDF file.
- **VirusTotal URL Check**: Optionally checks extracted URLs against VirusTotal to assess potential threats.
- **Defanged URL Display**: Provides an option to display URLs in a defanged format to prevent accidental clicks.

### 2. Metadata and JavaScript Analysis
- **Metadata Extraction**: Retrieves and displays metadata information, including document properties, system properties and PDF/A or PDF/X compliance.
- **File System Attributes**: Provides detailed file system attributes such as size, creation date, last access date and permissions.

- **JavaScript Extraction**: Identifies and extracts JavaScript code from various sections of a PDF, including document-level, page-level, and form fields.
- **Suspicious Pattern Analysis**: Analyzes extracted JavaScript for patterns that may indicate malicious intent.

### 3. Hash Calculation and Verification

- **MD5, SHA-1, and SHA-256 Hashes**: Calculates cryptographic hashes for PDF files to ensure data integrity and verify authenticity.
- **VirusTotal Integration**: Optionally checks the SHA-256 hash against VirusTotal's database to identify known malicious files.

### 4. Embedded File Detection & Extraction
- **Attachment Enumeration**: Detects files embedded via the EmbeddedFiles name tree and FileAttachment annotations.
- **Hidden Payload Detection**: Flags orphaned `/EmbeddedFile` streams that are not referenced by any file specification.
- **Risk Classification**: Rates each attachment by extension, magic-byte content type (PE/ELF/Mach-O/archives), double extensions, and extension/content mismatches; hashes every payload.
- **Safe Extraction**: Optionally extracts attachments to a sibling folder with owner-only, non-executable permissions.

### 5. Structural Anomaly Detection
- **Dangerous Constructs**: Flags `/Launch`, `/OpenAction`, `/AA` (automatic actions), XFA forms, RichMedia, remote/embedded GoTo, SubmitForm/ImportData actions and JBIG2 streams.
- **Auto-Run JavaScript**: Distinguishes JavaScript that runs automatically on document open from inert scripts.
- **Obfuscation Detection**: Raw-byte scan for hex-escaped PDF name tokens (e.g. `/J#61vaScript`) that hide risky keywords from naive parsers.
- **Integrity Signals**: Reports repaired cross-reference tables, incremental updates (post-signing changes) and zero-page documents.

### 6. QR Code Detection
- **Quishing Analysis**: Renders each page and decodes QR codes so URLs hidden in images can be reviewed, defanged and VirusTotal-checked like ordinary links.
- **Optional Dependency**: Requires `opencv-python-headless` (install with `pip install 'pdfchecker[qr]'`); all other features work without it.

### 7. Risk Scoring
- **Unified 0–100 Score**: Combines JavaScript, structure, embedded-file, link and QR findings into a single weighted score with a per-category breakdown and a Minimal→Critical rating.
- **Severity Floors**: A single decisive indicator (e.g. a Launch action or a high-risk executable attachment) raises the minimum score so it cannot be averaged away.
- **Bulk Triage**: In bulk mode, files are ranked by score so the riskiest surface first.

### 8. Report Generation
- **Detailed PDF Reports**: Generates comprehensive reports covering every module above — risk score, hashes, links, metadata, JavaScript, embedded files, structural anomalies and QR codes.
- **Dual-Hash System**: Provides both the original PDF's hash and the final report's hash to ensure report integrity and support evidentiary standards.



## Installation & Usage

### Installation

Ensure you have Python 3.8 or higher installed along with the required dependencies listed in `pyproject.toml`.

```bash
# Clone the repository
git clone https://github.com/strateo/pdfchecker.git
cd pdfchecker

# Install 
pip install -e .
```

### Command-Line Interface

The tool provides a command-line interface with the following options:

- `-hc, --hash-checker <PDF_FILE_OR_DIR>`: Generate hash values for a PDF file.
- `-l, --links <PDF_FILE_OR_DIR>`: Extract, defang, and optionally enrich links from a PDF file.
- `-m, --metadata <PDF_FILE_OR_DIR>`: Extract and display PDF metadata information.
- `-js, --javascript <PDF_FILE_OR_DIR>`: Analyze and detect JavaScript in the PDF file.
- `-ef, --embedded-files <PDF_FILE_OR_DIR>`: Detect and optionally extract embedded files and hidden payload streams.
- `-sa, --structure <PDF_FILE_OR_DIR>`: Detect structural anomalies (auto-run/launch actions, XFA, name obfuscation, etc.).
- `-qr, --qr-codes <PDF_FILE_OR_DIR>`: Detect and decode QR codes, then optionally check decoded URLs with VirusTotal.
- `-rs, --risk-score <PDF_FILE_OR_DIR>`: Compute a 0–100 risk score combining all analysis modules.
- `-r, --report <PDF_FILE_OR_DIR>`: Generate a PDF report with risk score, hash, links, metadata, JavaScript, embedded files, structure and QR findings, and optional VT enrichment.

### Bulk Mode

Every analysis option also accepts a folder path. When a folder is provided, PDFChecker switches to bulk mode: it lists the PDF files found in the folder (non-recursive) and asks for a Y/N confirmation before scanning them.

```bash
# Analyze a single PDF
python source/main.py -m suspicious.pdf

# Analyze every PDF in a folder (asks for confirmation first)
python source/main.py -m ./samples/
```

Bulk mode behavior:
- Interactive questions (VirusTotal enrichment, defanged output, operator name) are asked once and applied to all files.
- Per-file work runs in parallel: hashing uses a thread pool, while PyMuPDF-based analyses (links, metadata, JavaScript, embedded files, structure, QR codes, risk scoring, reports) run in isolated worker processes, so a malformed PDF cannot take down the whole batch.
- Embedded-file extraction is offered in single-file mode only; bulk mode reports detections without writing payloads to disk. Risk-scoring bulk mode ranks files by score, highest first.
- VirusTotal checks share a single API call budget across the entire batch, and a URL appearing in multiple PDFs is only checked once.
- Files larger than the 100MB limit are skipped with a notice; in report mode, previously generated `*_report.pdf` files are excluded automatically.

### VirusTotal API Key Management

- `--set-api-key`: Set your VirusTotal API key.
- `--remove-api-key`: Remove your VirusTotal API key.
- `--show-api-key`: Show your current VirusTotal API key (double confirmation).
- `--edit-api-limit`: View and edit the API call limit for VirusTotal (default value is set to 10 calls per single operation).



## Security Considerations

### Input & Content Validation
- File type, path, and size validation (100MB limit).
- JavaScript preview and metadata extraction length limits to prevent overloads.
- Controlled API input with retry safeguards.

### Secure API Handling
- API communication is HTTPS-only with strict timeout enforcement.
- Duplicate Call Prevention: Identical links within the same document are scanned only once to minimize redundant VirusTotal API usage (URLs with different paths or subdomains are treated as distinct and checked separately).
- API key memory cleaning to avoid memory dumps or swap files. 
- API keys are encrypted and stored using OS-native keychain utilities (Keychain, Credential manager, Gnome Keyring, KWallet).

### Forensic Features
- Dual-hash integrity: report includes original PDF hash and generated report hash.
- UTC timestamps, tool version tagging, and reproducible analysis metadata.
- Designed to meet evidentiary standards for professional and legal use.

### Data Protection
- No local caching of sensitive data.
- In-memory cleanup routines to avoid residual traces.
- Sanitized logs to exclude sensitive or identifying information.

## Future Enhancements & Roadmap
- [ ] Abuse.ch enrichment support.
- [ ] Export extracted indicators (URLs, domains, JS strings) in STIX / JSON.
- [ ] YARA rule scanning against raw PDF streams.
