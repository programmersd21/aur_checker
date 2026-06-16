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
        # Only flag truly dangerous patterns, not download-and-verify sequences
        remote_exec_patterns = [
            re.compile(r"(curl|wget|fetch)\s+[^|]*\|\s*(ba)?sh"),  # Direct pipe to shell
            re.compile(r"eval\s+\$?\(?\s*(curl|wget|fetch)"),  # Eval with download
            re.compile(r"(ba)?sh\s+-c\s+[\"']?\$?\(?(curl|wget|fetch)"),  # Shell -c with download
        ]
        remote_exec_count = 0
        for line in lines:
            # Skip comments
            if line.strip().startswith("#"):
                continue
            # Skip if line contains checksums or verification
            if any(keyword in line.lower() for keyword in ["sha256", "sha512", "md5", "checksum", "verify"]):
                continue
            remote_exec_count += sum(1 for p in remote_exec_patterns if p.search(line))

        # ── source block detection (skip these for external URL counting) ──
        source_lines = set()
        in_source = False
        source_start = re.compile(r"^\s*source\s*=\s*\(")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if source_start.search(stripped) or stripped.startswith("source=("):
                in_source = True
                source_lines.add(i)
                if stripped.endswith(")"):
                    in_source = False
                continue
            if in_source:
                source_lines.add(i)
                if stripped.endswith(")"):
                    in_source = False

        # ── external (non-source) URL calls ──
        # Only flag URLs in code execution context, not download declarations
        external_url_pattern = re.compile(r"https?://[^\s\"']+")
        external_calls = 0
        for i, line in enumerate(lines):
            if i in source_lines or line.strip().startswith("#"):
                continue
            # Only count if in execution context (curl, wget, etc.)
            if any(keyword in line for keyword in ["curl", "wget", "fetch", "git clone"]):
                external_calls += len(external_url_pattern.findall(line))

        # ── package managers ──
        # Only flag if used outside of makedepends/depends context
        package_manager_map = {
            "npm": re.compile(r"\bnpm\s+(install|add|run)\b", re.IGNORECASE),
            "pip": re.compile(r"\bpip\s+(install|download)\b", re.IGNORECASE),
            "cargo": re.compile(r"\bcargo\s+install\b", re.IGNORECASE),
            "go": re.compile(r"\bgo\s+(install|get)\b", re.IGNORECASE),
            "gem": re.compile(r"\bgem\s+install\b", re.IGNORECASE),
        }
        package_manager_usage = []
        for name, pat in package_manager_map.items():
            for line in lines:
                if line.strip().startswith("#"):
                    continue
                # Skip if it's just declaring dependencies
                if any(keyword in line for keyword in ["makedepends", "depends", "optdepends"]):
                    continue
                if pat.search(line):
                    package_manager_usage.append(name)
                    break

        # ── obfuscation ──
        obfuscation_score = 0
        if any(
            re.search(r"(base64|base32)\s+(-d|--decode)", line) for line in lines if not line.strip().startswith("#")
        ):
            obfuscation_score += 1
        if any(
            re.search(r"\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}", line)
            for line in lines
            if not line.strip().startswith("#")
        ):
            # Multiple hex escapes suggest encoding
            obfuscation_score += 1
        if any(
            re.search(r"(printf|echo).*xxd|xxd.*(printf|echo)", line)
            for line in lines
            if not line.strip().startswith("#")
        ):
            obfuscation_score += 1
        if any(re.search(r"openssl\s+enc", line) for line in lines if not line.strip().startswith("#")):
            obfuscation_score += 1
        if any(
            re.search(r"(eval|exec)\s+\$[A-Za-z_][A-Za-z0-9_]*", line)
            for line in lines
            if not line.strip().startswith("#")
        ):
            obfuscation_score += 1
        obfuscation_score = min(obfuscation_score, 3)

        # ── system modification ──
        # Only flag writes to truly sensitive locations
        sys_mod_pattern = re.compile(
            r"(install|cp|mv|tee|dd)\s+[^#]*"
            r"/(etc/|usr/lib/systemd|var/lib|boot/)"
        )
        system_modification = any(sys_mod_pattern.search(line) for line in lines if not line.strip().startswith("#"))

        # Check for sudo only in dangerous contexts
        has_sudo_dangerous = any(
            re.search(r"\bsudo\s+(rm|dd|chmod|chown|systemctl)", line)
            for line in lines
            if not line.strip().startswith("#")
        )
        if has_sudo_dangerous:
            system_modification = True

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
