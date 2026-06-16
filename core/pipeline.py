import os
from core.context import PipelineContext
from scanner.fetch import fetch_pkgbuild
from features.extractor import extract_features
from scanner.metadata import fetch_metadata
from scoring.engine import score_package
from ai.client import analyze_with_gemini
from cache.store import CacheStore
from compat_platform.paths import get_cache_dir


def _combine_scores(ctx: PipelineContext) -> PipelineContext:
    """Blend static analysis score with AI assessment (30% AI weight)."""
    if not ctx.ai_analysis or not ctx.ai_enabled:
        # Without AI, use static score only
        return ctx

    ai_score = ctx.ai_analysis.ai_risk_score
    static_score = ctx.risk_score if ctx.risk_score is not None else 0

    # Store component scores for display
    ctx.static_score = static_score
    ctx.ai_score = ai_score

    # Reduced AI weight: 70% static, 30% AI
    combined = int(static_score * 0.7 + ai_score * 0.3)
    combined = max(0, min(combined, 100))
    ctx.risk_score = combined

    if combined <= 20:
        ctx.risk_level = "LOW"
    elif combined <= 50:
        ctx.risk_level = "MEDIUM"
    else:
        ctx.risk_level = "HIGH"

    if ctx.risk_level == "LOW":
        ctx.verdict = "ALLOW"
    elif ctx.risk_level == "MEDIUM":
        ctx.verdict = "REVIEW"
    else:
        ctx.verdict = "DENY"

    return ctx


def run_pipeline(package: str, skip_cache: bool = False, enable_ai: bool = True) -> PipelineContext:
    cache_dir = get_cache_dir()
    ttl = int(os.getenv("AURCHECKER_CACHE_TTL", 3600))
    store = CacheStore(cache_dir, ttl)

    if not skip_cache:
        cached_ctx = store.get(package)
        if cached_ctx:
            return cached_ctx

    ctx = PipelineContext(package=package, ai_enabled=enable_ai)

    ctx = fetch_pkgbuild(ctx, timeout=int(os.getenv("AURCHECKER_TIMEOUT", 10)))
    if any(not err.recoverable for err in ctx.errors):
        return ctx

    ctx = extract_features(ctx)
    if any(not err.recoverable for err in ctx.errors):
        return ctx

    ctx = fetch_metadata(ctx)
    if any(not err.recoverable for err in ctx.errors):
        return ctx

    ctx = score_package(ctx)
    if any(not err.recoverable for err in ctx.errors):
        return ctx

    # AI is optional - only run if enabled and API key is available
    if enable_ai and os.getenv("AURCHECKER_AI_API_KEY"):
        ctx = analyze_with_gemini(ctx)
        ctx = _combine_scores(ctx)
    # If AI is disabled or unavailable, static score remains the final score

    if not skip_cache:
        store.set(package, ctx)

    return ctx
