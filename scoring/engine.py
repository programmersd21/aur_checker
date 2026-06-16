from core.context import PipelineContext, ScoreBreakdown, ErrorDetail


def _tier(value: int, breakpoints: list[tuple[int, int]]) -> int:
    for max_val, score in breakpoints:
        if value <= max_val:
            return score
    return breakpoints[-1][1]


def score_package(ctx: PipelineContext) -> PipelineContext:
    if not ctx.features or not ctx.metadata:
        ctx.errors.append(
            ErrorDetail(
                code="SCORING_FAILED",
                stage="Scoring",
                message="Missing features or metadata to compute risk score.",
                recoverable=False,
            )
        )
        ctx.verdict = "REVIEW"
        return ctx

    f = ctx.features
    m = ctx.metadata

    # Each signal contributes independently to a 0-100 scale.
    # Truly dangerous signals (remote exec, system mod) dominate;
    # common benign signals (external URLs, package managers) stay low.

    remote_exec = _tier(f.remote_exec_count, [(0, 0), (1, 50), (2, 70)])
    external_calls = _tier(f.external_calls, [(0, 0), (1, 5), (3, 10), (5, 15)])
    pkg_manager = _tier(len(f.package_manager_usage), [(0, 0), (1, 8), (2, 12)])
    orphan_adopted = 10 if m.orphan_status else 0
    obfuscation = _tier(f.obfuscation_score, [(0, 0), (1, 15), (2, 25), (3, 35)])
    system_modification = 30 if f.system_modification else 0
    maintainer_changed = 15 if m.maintainer_changed == "true" else 0

    # Trust signals penalty
    trust_penalty = 0
    if ctx.trust_signals:
        if ctx.trust_signals.out_of_date:
            trust_penalty += 5
        if ctx.trust_signals.maintainer_history == "changed":
            trust_penalty += 10
        elif ctx.trust_signals.maintainer_history == "new":
            trust_penalty += 5

    raw = (
        remote_exec
        + external_calls
        + pkg_manager
        + orphan_adopted
        + obfuscation
        + system_modification
        + maintainer_changed
        + trust_penalty
    )

    risk_score = min(raw, 100)
    ctx.risk_score = risk_score

    # Store breakdown for explainability
    ctx.score_breakdown = ScoreBreakdown(
        remote_exec=remote_exec,
        external_calls=external_calls,
        pkg_manager=pkg_manager,
        orphan_adopted=orphan_adopted,
        obfuscation=obfuscation,
        system_modification=system_modification,
        maintainer_changed=maintainer_changed,
        trust_penalty=trust_penalty,
        total_static=risk_score,
    )

    if risk_score <= 20:
        ctx.risk_level = "LOW"
    elif risk_score <= 50:
        ctx.risk_level = "MEDIUM"
    else:
        ctx.risk_level = "HIGH"

    if ctx.risk_level == "LOW":
        ctx.verdict = "ALLOW"
    elif ctx.risk_level == "MEDIUM":
        ctx.verdict = "REVIEW"
    else:
        ctx.verdict = "DENY"

    # Escalate to REVIEW if analysis itself failed
    has_analysis_err = any(err.stage == "Static Analysis" for err in ctx.errors)
    metadata_fetch_failed = all(
        getattr(m, field) == "UNKNOWN" for field in ["maintainer", "package_age_days", "last_update_delta_days"]
    )
    if has_analysis_err or metadata_fetch_failed:
        ctx.verdict = "REVIEW"

    return ctx
