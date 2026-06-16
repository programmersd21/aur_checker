# Security Threat Model

## Purpose

aur_checker analyzes Arch Linux AUR PKGBUILD files to help identify security risks **before** building packages. It is a defense-in-depth tool, not a complete security solution.

## What aur_checker CAN Detect

### High Confidence

✓ **Remote code execution patterns**
- Direct piping of downloads to shell (`curl | bash`)
- `eval` with remote content
- Shell commands downloading and executing without verification

✓ **System modification**
- Writes to sensitive directories (`/etc`, `/boot`, `/usr/lib/systemd`)
- Use of `sudo` with dangerous commands (`rm`, `dd`, `chmod`, `systemctl`)

✓ **Obfuscation indicators**
- Base64/hex encoding with decoding
- Multiple layers of encoding (xxd + printf)
- Dynamic evaluation of obfuscated variables

### Medium Confidence

⚠ **Trust signals**
- Orphaned packages (no active maintainer)
- Recently changed maintainers
- Packages marked as out-of-date
- Very new packages (<30 days)
- Unusual update patterns

⚠ **Risky patterns**
- External package manager calls (npm, pip, cargo, gem) outside dependency declarations
- Non-source URL calls in build scripts
- Download commands in execution context

## What aur_checker CANNOT Detect

### Fundamental Limitations

✗ **Sophisticated obfuscation**
- Multi-stage payloads that reconstruct malicious code at runtime
- Encryption with keys embedded in legitimate-looking data
- Steganography or timing-based attacks

✗ **Logic-based attacks**
- Legitimate-looking code that behaves differently based on environment variables
- Time bombs (code that activates after a certain date)
- Conditional malware (only activates for specific usernames, hostnames, etc.)

✗ **Dependency attacks**
- Malicious upstream sources (even if checksums are present)
- Compromised build dependencies
- Supply chain attacks through legitimate packages

✗ **Post-install behavior**
- Services or systemd units installed by the package
- Behavior of compiled binaries (aur_checker analyzes build scripts, not executables)
- Network behavior of installed software

✗ **Social engineering**
- Packages with misleading names (typosquatting)
- Packages that claim to be official but aren't
- Legitimate packages with malicious optional dependencies

### Known False Negative Scenarios

1. **Legitimate-looking wrappers**: A script that downloads and verifies a binary but then executes it without further inspection
2. **Deferred execution**: Build scripts that write malicious code to files executed later (e.g., .bashrc, .profile)
3. **Data exfiltration**: Quiet data collection that doesn't match obvious attack patterns
4. **Binary exploits**: Vulnerabilities in pre-compiled binaries fetched by the PKGBUILD

## What You Should Still Do

### Before Installing ANY AUR Package

1. **Read the PKGBUILD** - aur_checker is a first-pass filter, not a substitute for code review
2. **Check the comments** on the AUR page - other users may have reported issues
3. **Verify the maintainer** - look at their other packages and history
4. **Search for the project** - confirm it's a legitimate upstream project
5. **Check upstream sources** - verify URLs point to expected repositories
6. **Review checksums** - ensure integrity verification is present and correct

### Red Flags That Require Manual Investigation

- Package name doesn't match upstream project name
- Maintainer is unknown or recently changed
- Package downloads pre-compiled binaries without source
- Multiple layers of downloads (downloads a script that downloads another script)
- Unusual or suspicious URLs
- Missing or disabled integrity checks
- Comments on AUR page mention security concerns

## How aur_checker Works

### Analysis Pipeline

1. **Fetch** - Download PKGBUILD from AUR CGit
2. **Static Analysis** - Regex-based pattern detection (context-aware to reduce false positives)
3. **Metadata** - Retrieve package info from AUR RPC API
4. **Scoring** - Compute 0-100 risk score from weighted signals with explainable breakdown
5. **Trust Signals** - Evaluate maintainer history, age, popularity, update patterns
6. **AI Review** (optional) - Heuristic analysis using LLM for additional context

### Scoring Model (Static Analysis)

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Remote execution | 50-70 | Extremely dangerous - direct code execution from internet |
| Obfuscation | 15-35 | Attempts to hide behavior from analysis |
| System modification | 30 | Writes to sensitive system locations |
| Maintainer changed | 15 | Increased risk during transition periods |
| Orphan/adopted | 10 | No active maintainer to respond to issues |
| Package managers | 8-12 | Risk if used outside normal dependency context |
| External calls | 5-15 | Network activity in build scripts |
| Trust penalty | 5-10 | Out-of-date, new, or suspicious patterns |

**Final Score**: Static score (70%) + AI adjustment (30%, if enabled)

### AI Analysis Limitations

When AI is enabled:
- Uses Google Gemini API for heuristic analysis
- **Not deterministic** - results may vary between runs
- **Cannot detect** what static analysis misses if the pattern is sophisticated
- **May produce false positives** - treat AI insights as suggestions, not facts
- Clearly labeled as "heuristic" in all outputs

## Recommendations

### For Individual Users

- Use aur_checker as a **pre-screening tool**
- Always review PKGBUILDs manually for packages with risk scores > 20
- Consider running builds in isolated containers or VMs
- Keep your system updated and use official repos when possible

### For Automation/CI

- Exit codes: 0=safe, 1=high risk, 2=review needed, 3=not found, 4=error
- Use `--json` flag for structured output
- Treat REVIEW (exit 2) as "needs human inspection"
- Do not auto-install packages with scores > 50

### For Package Maintainers

To minimize false positives in your PKGBUILDs:
- Add comments explaining unusual patterns
- Use checksums for all downloads
- Avoid piping downloads directly to shell
- Use source=() arrays for downloads, not curl in build()
- Clearly document why package managers are invoked
- Avoid encoding/obfuscation even for legitimate purposes

## Reporting Security Issues

If you find a vulnerability in aur_checker or discover a PKGBUILD that aur_checker should flag but doesn't, please report it to:

**Email**: geniussantu1983@gmail.com

Please include:
- Package name or aur_checker version
- Description of the issue
- Steps to reproduce
- Expected vs. actual behavior

## License & Disclaimer

aur_checker is provided "as is" without warranty. It is a tool to assist security review, not a guarantee of safety. Users are responsible for their own security decisions.

See [LICENSE.md](LICENSE.md) for full terms.
