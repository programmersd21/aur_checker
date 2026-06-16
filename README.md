# aur_checker

![demo](screenshots/image.png)

A command-line tool for analyzing Arch Linux AUR PKGBUILD files to identify security risks. Uses static analysis with optional AI-powered inspection.

[![Build Status](https://img.shields.io/github/actions/workflow/status/programmersd21/aur_checker/ci.yml?style=for-the-badge)](https://github.com/programmersd21/aur_checker/actions)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/programmersd21/aur_checker/codeql.yml?style=for-the-badge&label=CodeQL)](https://github.com/programmersd21/aur_checker/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE.md)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://www.python.org/)

## Overview

aur_checker inspects PKGBUILD files for security vulnerabilities and suspicious patterns before you build packages. It combines context-aware static analysis with optional AI review to produce explainable risk assessments.

**Analysis pipeline:**
```
PKGBUILD → Fetch → Static Analysis → Metadata → Trust Signals → Scoring → [AI Review] → Risk Verdict
```

**Key features:**
- ✓ Context-aware detection to reduce false positives
- ✓ Explainable risk scoring with detailed breakdowns
- ✓ AUR trust signals (maintainer history, popularity, age)
- ✓ Optional AI analysis (works without API key)
- ✓ User-friendly output with plain language summaries
- ✓ JSON output with stable schema for CI integration
- ✓ Clear exit codes for automation

## Installation

```bash
git clone https://github.com/programmersd21/aur_checker.git
cd aur_checker
pip install -e .
```

Requires Python 3.10 or later.

## Quick Start

```bash
# Check a single package
aur_checker check keepassx2

# Output as JSON
aur_checker check --json keepassx2

# Verbose mode with detailed signals
aur_checker check --verbose keepassx2

# Check multiple packages
aur_checker batch keepassx2 visual-studio-code-bin

# Check from a file
aur_checker batch --file packages.txt

# AI analysis from previous results
aur_checker explain --input analysis.json

# Build with makepkg
aur_checker install keepassx2

# Clear cached analysis
aur_checker clear-cache
```

## Configuration

### API Key (Optional)

AI analysis is **optional**. aur_checker works without an API key using static analysis only.

To enable AI analysis, set your Google Generative AI API key:

```bash
# Linux/macOS
export AURCHECKER_AI_API_KEY="your-api-key"

# Windows PowerShell
$env:AURCHECKER_AI_API_KEY="your-api-key"
```

### Optional Settings

| Variable | Purpose | Default |
|----------|---------|---------|
| `AURCHECKER_AI_MODEL` | AI model to use | `gemini-3.1-flash-lite` |
| `AURCHECKER_AI_TIMEOUT` | Request timeout (milliseconds) | `120000` |

## How It Works

### Analysis Process

1. **Fetch** - Downloads PKGBUILD from AUR CGit
2. **Static Analysis** - Context-aware pattern detection (skips comments, distinguishes legitimate operations)
3. **Metadata** - Retrieves AUR RPC v5 package information (maintainer, votes, age)
4. **Trust Signals** - Evaluates maintainer history, popularity, update patterns, out-of-date status
5. **Scoring** - Computes 0-100 risk score with explainable breakdown of contributing factors
6. **AI Review** (optional) - Heuristic analysis for additional context if API key is set
7. **Verdict** - Final assessment: Safe to review / Needs attention / High risk

### Risk Assessment

| Score | Risk Level | Recommendation | Exit Code |
|-------|-----------|-----------------|-----------|
| 0-20 | Low | Safe to review | 0 |
| 21-50 | Medium | Manual review recommended | 2 |
| 51-100 | High | Do not use | 1 |

**Note**: Without AI, static score is used directly (more conservative). With AI enabled, final score is 70% static + 30% AI.

### Output Modes

**Human output** (default):
- User Summary: Simple verdict, key findings in plain language
- Technical Details: Score breakdown, trust signals, metadata
- AI Analysis: Heuristic insights (clearly labeled, if enabled)
- Verbose mode: All detected signals with `--verbose`

**JSON output** (`--json`):
- Stable schema (v1.0.1) for automation
- Includes score_breakdown, trust_signals, analysis_mode
- Use with CI tools and security pipelines

### Exit Codes (for CI integration)

```
0 - Analysis completed, package appears safe (ALLOW)
1 - Analysis completed, high risk detected (DENY)
2 - Analysis completed, manual review needed (REVIEW)
3 - Package not found on AUR
4 - Unrecoverable error during analysis
```

### Security Signals

The static analyzer detects:

| Signal | Pattern | Risk Weight | Rationale |
|--------|---------|-------------|-----------|
| `remote_exec` | Downloads piped to shell (curl/wget → bash) | 50-70 | Direct code execution from internet |
| `obfuscation` | Base64, hex, eval, encoding layers | 15-35 | Attempts to hide behavior |
| `system_mod` | Writes to /etc, /boot, /usr/lib/systemd | 30 | Modifies sensitive system locations |
| `maintainer_changed` | Maintainer change detected | 15 | Increased risk during transitions |
| `orphan_adopted` | Package without active maintainer | 10 | No owner to respond to issues |
| `pkg_manager` | npm, pip, cargo, go, gem (outside deps) | 8-12 | Risk if used in build scripts |
| `external_calls` | Non-source HTTP/HTTPS URLs in execution | 5-15 | Network activity in build context |

### Trust Signals

| Signal | Description |
|--------|-------------|
| Package age | Days since first submission |
| Maintainer history | stable / changed / orphan_adopted / new |
| Update frequency | Days since last update |
| Popularity | Vote count, >100 votes = popular |
| Out of date | Flagged by users as outdated |

## What aur_checker Can and Cannot Detect

✅ **CAN detect:**
- Direct remote code execution patterns (`curl | bash`)
- System modification to sensitive directories
- Encoding/obfuscation indicators
- Suspicious trust signals (orphaned, new maintainer, out-of-date)
- Risky patterns in build scripts

❌ **CANNOT detect:**
- Sophisticated multi-stage obfuscation
- Logic bombs or conditional malware
- Compromised upstream sources (even with checksums)
- Post-install behavior of compiled binaries
- Typosquatting or social engineering

**See [SECURITY.md](SECURITY.md) for the complete threat model, limitations, and recommendations.**

## Development

### Running Tests

```bash
# Unit tests
pytest

# Type checking
mypy .

# Code style
ruff check .
```

### Project Structure

```
aur_checker/
  ai/              # AI integration (optional)
  cache/           # Result caching
  cli/             # Command-line interface
  core/            # Pipeline and context
  features/        # Static analysis (context-aware)
  output/          # Human and JSON formatters
  scanner/         # PKGBUILD and metadata fetching
  scoring/         # Risk scoring with breakdown
  compat_platform/ # Cross-platform compatibility
```

## Limitations

- AI analysis requires valid API key and internet connection
- Static analysis uses context-aware patterns but may miss sophisticated obfuscation
- Risk scores are heuristic-based and should inform, not replace, manual review
- AI responses are non-deterministic and clearly labeled as heuristic
- Cannot analyze post-build behavior or compiled binary contents

**Always read PKGBUILDs manually before building AUR packages.**

## Contributing

Contributions welcome. Please open an issue or pull request on GitHub.

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what aur_checker can and cannot detect, and how to report security issues.

---

**Maintainer:** [geniussantu1983@gmail.com](mailto:geniussantu1983@gmail.com)

**Repository:** [github.com/programmersd21/aur_checker](https://github.com/programmersd21/aur_checker)
