# SecureHeader

A beginner-friendly, open-source command-line tool that checks common HTTP security response headers and produces JSON or HTML reports.

## Features

- Checks six common HTTP security headers.
- Reports missing headers and remediation guidance.
- Supports JSON and HTML report exports.
- Includes automated tests and GitHub Actions CI.
- Uses a configurable request timeout.

## Requirements

- Python 3.9+
- Internet access to scan a website you are authorized to assess.

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/secureheader.git
cd secureheader
python -m venv .venv
```

Activate the environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
secureheader scan https://example.com
```

Save reports:

```bash
secureheader scan https://example.com --json report.json --html report.html
```

Run tests:

```bash
pytest -q
```

## Checks performed

Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy.

## Understanding the score

The score represents the percentage of checked headers that are present. It is **not** a complete security rating. SecureHeader checks presence, not whether a header's value is correctly configured for a particular application.

## Responsible use

Only scan websites you own or have explicit permission to assess. This tool makes an HTTP request to the target and follows redirects. Do not use it to disrupt services or perform unauthorized testing.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md), open an issue before large changes, add tests, and submit a pull request.

## Security issues

Please do not publish sensitive vulnerability details in public issues. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
