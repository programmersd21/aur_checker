<div align="center">

# aur_checker

A CLI tool to inspect Arch Linux AUR PKGBUILD files for security risks using static analysis and AI.

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/programmersd21/aur_checker/ci.yml?style=for-the-badge" alt="Build Status">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License Badge">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" alt="Python Version">
</p>

> **Support this project** - [Sponsor](https://github.com/sponsors/programmersd21) or star the repo.

---

## Pipeline

```
PKGBUILD → FETCH → STATIC_ANALYSIS → METADATA → SCORING → AI (70% weight) → VERDICT
```

1. **Fetch** - Downloads PKGBUILD from AUR CGit.
2. **Static analysis** - Regex scan for remote execution, obfuscation, system modification, package manager calls.
3. **Metadata** - AUR RPC v5 info (maintainer, orphan status, age).
4. **Scoring** - Aggregates signals into a 0-100 risk score.
5. **AI** - `gemini-3.1-flash-lite` via `google-genai`. Blended 30/70 (static/AI) for the final verdict.
6. **Output** - Rich terminal output or JSON.

---

## Installation

```bash
git clone https://github.com/programmersd21/aur_checker.git
cd aur_checker
pip install -e .
```

---

## AI Configuration

AI runs automatically. Set your API key:

| Platform | Command |
|----------|---------|
| Linux/macOS | `export AURCHECKER_AI_API_KEY="your-key"` |
| Windows PowerShell | `$env:AURCHECKER_AI_API_KEY="your-key"` |

Optional overrides:
- `AURCHECKER_AI_MODEL` - model name (default: `gemini-3.1-flash-lite`)
- `AURCHECKER_AI_TIMEOUT` - timeout in ms (default: `120000`)

---

## Usage

```bash
# Check a single package
aur_checker check keepassx2

# JSON output
aur_checker --json check keepassx2

# Check multiple packages
aur_checker batch keepassx2 visual-studio-code-bin
aur_checker batch --file packages.txt

# AI analysis from saved JSON
aur_checker explain --input analysis.json

# Check + install (makepkg required)
aur_checker install keepassx2

# Clear cached results
aur_checker clear-cache
```

---

## Scoring

| Score | Level | Verdict |
|-------|-------|---------|
| 0-20 | LOW | ALLOW |
| 21-50 | MEDIUM | REVIEW |
| 51-100 | HIGH | DENY |

Signals detected by static analysis:

| Signal | Trigger | Max weight |
|--------|---------|-----------|
| remote_exec | curl/wget piped to shell | 50 |
| external_calls | Non-source HTTPS URLs | 15 |
| pkg_manager | npm/pip/cargo/go/gem/pacman/yay | 10 |
| orphan_adopted | Package without maintainer | 10 |
| obfuscation | base64, hex, printf+xxd, openssl, eval | 30 |
| system_mod | Writing to /etc, /usr/lib, /opt, /boot | 30 |
| maintainer_changed | Maintainer turnover (always UNKNOWN) | 0 |

---

## Quality Assurance

```bash
pytest
mypy .
ruff check .
```

---

## License

MIT. See [LICENSE.md](LICENSE.md).

Contact: [geniussantu1983@gmail.com](mailto:geniussantu1983@gmail.com)

</div>
