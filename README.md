# PDF Checker

![pdfc_logo](https://github.com/user-attachments/assets/9b3d7f17-e3b1-4238-92dc-7231323eede6)

## Overview

**PDF Checker** is a cross-platform tool designed to evaluate PDF files for security threats and extract forensic-value information. It detects malicious indicators through hash validation, embedded script analysis, and metadata inspection. Reports are generated with forensic integrity in mind, incorporating cryptographic proof and principles of reproducibility.

You can find the tool chart [here](https://github.com/Strateo/pdfchecker/blob/main/docs/Mermaid_architecture.png) and a sample of the generated report [here](https://github.com/Strateo/pdfchecker/blob/main/docs/Report_sample.pdf).

## 🧾 Features

### 1. Hash Calculation and Verification
- **MD5, SHA-1, and SHA-256 Hashes**: Calculates cryptographic hashes for PDF files to ensure data integrity and verify authenticity.
- **VirusTotal Integration**: Optionally checks the SHA-256 hash against VirusTotal's database to identify known malicious files.

### 2. Link Extraction and Analysis
- **URI Extraction**: Identifies and extracts all URI links embedded within a PDF file.
- **VirusTotal URL Check**: Optionally checks extracted URLs against VirusTotal to assess potential threats.
- **Defanged URL Display**: Provides an option to display URLs in a defanged format to prevent accidental clicks.

### 3. Metadata and JavaScript Analysis
- **Metadata Extraction**: Retrieves and displays metadata information, including document properties, system properties and PDF/A or PDF/X compliance.
- **File System Attributes**: Provides detailed file system attributes such as size, creation date, last access date and permissions.

- **JavaScript Extraction**: Identifies and extracts JavaScript code from various sections of a PDF, including document-level, page-level, and form fields.
- **Suspicious Pattern Analysis**: Analyzes extracted JavaScript for patterns that may indicate malicious intent.

### 4. Report Generation
- **Detailed PDF Reports**: Generates comprehensive reports that include all the modules above, such as hash values, link analysis, metadata, and JavaScript findings.
- **Dual-Hash System**: Provides both the original PDF's hash and the final report's hash to ensure report integrity and support evidentiary standards.



## 🛠️ Installation & Usage

## Installation

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

- `-hc, --hash-checker <PDF_FILE>`: Generate hash values for a PDF file.
- `-l, --links <PDF_FILE>`: Extract, defang, and optionally enrich links from a PDF file.
- `-m, --metadata <PDF_FILE>`: Extract and display PDF metadata information.
- `-js, --javascript <PDF_FILE>`: Analyze and detect JavaScript in the PDF file.
- `-r, --report <PDF_FILE>`: Generate a PDF report with hash, links, metadata, JavaScript information and optional VT enrichment.

### VirusTotal API Key Management

- `--set-api-key`: Set your VirusTotal API key.
- `--remove-api-key`: Remove your VirusTotal API key.
- `--show-api-key`: Show your current VirusTotal API key (double confirmation).
- `--edit-api-limit`: View and edit the API call limit for VirusTotal (default value is set to 10 calls per single operation).



## 🔐 Security Considerations

### Input & Content Validation
- File type, path, and size validation (100MB limit).
- JavaScript preview and metadata extraction length limits to prevent overloads.
- Controlled API input with retry safeguards.
- Compatible with Windows, macOS, and Linux.

### Secure API Handling
- API communication is HTTPS-only with strict timeout enforcement.
- Duplicate Call Prevention: Identical links within the same document are scanned only once to minimize redundant VirusTotal API usage (URLs with different paths or subdomains are treated as distinct and checked separately).
- API key memory cleaning to avoid memory dumps or swap files. 
- API keys are encrypted and stored using OS-native keychain utilities (Keychain, Credential manager, Gnome Keyring, KWallet, FSS).

### Forensic Features
- Dual-hash integrity: report includes original PDF hash and generated report hash.
- UTC timestamps, tool version tagging, and reproducible analysis metadata.
- Designed to meet evidentiary standards for professional and legal use.

### Data Protection
- No local caching of sensitive data.
- In-memory cleanup routines to avoid residual traces.
- Sanitized logs to exclude sensitive or identifying information.

## Future Enhancements & Roadmap
- [ ] Bulk operation support.
- [ ] Abuse.ch enrichment support.
- [ ] Risk scoring based on links, JS, metadata, and structural anomalies.
- [ ] Export extracted indicators (URLs, domains, JS strings) in STIX / JSON.
