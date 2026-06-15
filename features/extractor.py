import re
from core.context import PipelineContext, FeatureSet, ErrorDetail


def extract_features(ctx: PipelineContext) -> PipelineContext:
    if not ctx.pkgbuild_raw:
        ctx.errors.append(
            ErrorDetail(
                code="ANALYSIS_FAILED",
                stage="Static Analysis",
                message="No PKGBUILD raw text found to analyze.",
                recoverable=False,
            )
        )
        return ctx

    try:
        raw = ctx.pkgbuild_raw
        lines = raw.splitlines()

        # ── remote execution (curl/wget/fetch piped to shell) ──
        remote_exec_patterns = [
            re.compile(r"(curl|wget|fetch|httpie)\s.*[|;]\s*(ba)?sh"),
            re.compile(r"(ba)?sh\s*[<(<]*\s*(curl|wget|fetch)"),
            re.compile(r"eval\s+\$?\(?\s*(curl|wget|fetch)"),
            re.compile(r"sh\s+-c\s+[\"']?\$"),
            re.compile(r"system\([\"'](curl|wget|fetch)"),
            re.compile(r"(curl|wget|fetch)\s+.*https?://[^\s]+\s*[|>]"),
            re.compile(r"(python|perl|ruby)\s+-[ec]\s+[\"']"),
        ]
        remote_exec_count = sum(1 for line in lines if any(p.search(line) for p in remote_exec_patterns))

        # ── source block detection (skip these for external URL counting) ──
        source_lines = []
        in_source = False
        source_start = re.compile(r"^source\s*=\s*\(")
        for line in lines:
            stripped = line.strip()
            if source_start.search(stripped) or stripped.startswith("source=("):
                in_source = True
                source_lines.append(line)
                if stripped.endswith(")"):
                    in_source = False
                continue
            if in_source:
                source_lines.append(line)
                if stripped.endswith(")"):
                    in_source = False

        # ── external (non-source) URL calls ──
        external_url_pattern = re.compile(
            r"https?://(?!downloads\.sourceforge|github\.com/[^/]+/[^/]+/releases|raw\.githubusercontent)[^\s\"']+"
        )
        external_calls = 0
        for line in lines:
            if line in source_lines:
                continue
            external_calls += len(external_url_pattern.findall(line))

        # ── package managers ──
        package_manager_map = {
            "npm": re.compile(r"\bnpm\s+(install|add|run)\b", re.IGNORECASE),
            "pip": re.compile(r"\bpip\s+(install|download)\b", re.IGNORECASE),
            "cargo": re.compile(r"\bcargo\s+install\b", re.IGNORECASE),
            "go": re.compile(r"\bgo\s+(install|run|build)\b", re.IGNORECASE),
            "gem": re.compile(r"\bgem\s+install\b", re.IGNORECASE),
            "yay": re.compile(r"\byay\s+-S\b", re.IGNORECASE),
            "pacman": re.compile(r"\bpacman\s+-S\b", re.IGNORECASE),
        }
        package_manager_usage = [
            name for name, pat in package_manager_map.items() if any(pat.search(line) for line in lines)
        ]

        # ── obfuscation ──
        obfuscation_score = 0
        if any(re.search(r"(base64|base32|base16)(\s+-d|\s+--decode)", line) for line in lines):
            obfuscation_score += 1
        if any(re.search(r"\\x[0-9a-fA-F]{2}", line) for line in lines):
            obfuscation_score += 1
        if any(re.search(r"(printf|echo)\s+.*xxd|xxd\s+.*(printf|echo)", line) for line in lines):
            obfuscation_score += 1
        if any(re.search(r"openssl\s+enc", line) for line in lines):
            obfuscation_score += 1
        if any(re.search(r"(eval|exec)\s+\$[A-Za-z_][A-Za-z0-9_]*", line) for line in lines):
            obfuscation_score += 1
        if any(re.search(r"gpg\s+--decrypt", line) for line in lines):
            obfuscation_score += 1
        obfuscation_score = min(obfuscation_score, 3)

        # ── system modification ──
        sys_mod_pattern = re.compile(
            r"(install|cp|mv|tee|dd|write|echo\s+.*>>?)\s+.*"
            r"/(etc|usr/lib/systemd|usr/share/polkit-1|var/lib|usr/local/bin|opt|boot)/"
        )
        system_modification = any(sys_mod_pattern.search(line) for line in lines)

        # ── additional dangerous signals ──
        has_sudo = any(re.search(r"\bsudo\s+", line) for line in lines)
        chmod_dangerous = any(re.search(r"chmod\s+[0-7]77", line) for line in lines)

        if has_sudo:
            system_modification = True
        if chmod_dangerous:
            obfuscation_score = min(obfuscation_score + 1, 3)

        ctx.features = FeatureSet(
            remote_exec_count=remote_exec_count,
            external_calls=external_calls,
            package_manager_usage=package_manager_usage,
            obfuscation_score=obfuscation_score,
            system_modification=system_modification,
        )
    except re.error as e:
        ctx.errors.append(
            ErrorDetail(code="ANALYSIS_REGEX_ERR", stage="Static Analysis", message=str(e), recoverable=False)
        )
    except Exception as e:
        ctx.errors.append(
            ErrorDetail(code="ANALYSIS_FAILED", stage="Static Analysis", message=str(e), recoverable=False)
        )

    return ctx
