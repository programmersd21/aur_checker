import json
from core.context import PipelineContext
from typing import Any, Dict


def format_json(ctx: PipelineContext) -> str:
    """
    Export analysis result as stable JSON schema for automation and CI integration.

    Schema version: 1.0.1
    """
    output: Dict[str, Any] = {
        "schema_version": ctx.schema_version,
        "package": ctx.package,
        "verdict": ctx.verdict,
        "risk_score": ctx.risk_score,
        "risk_level": ctx.risk_level,
        "analysis_mode": "ai_enabled" if ctx.ai_enabled and ctx.ai_analysis else "static_only",
    }

    # Score breakdown for explainability
    if ctx.score_breakdown:
        output["score_breakdown"] = ctx.score_breakdown.dict()

    # Features
    if ctx.features:
        output["features"] = ctx.features.dict()

    # Trust signals
    if ctx.trust_signals:
        output["trust_signals"] = ctx.trust_signals.dict()

    # Metadata
    if ctx.metadata:
        output["metadata"] = ctx.metadata.dict()

    # AI analysis (if available)
    if ctx.ai_analysis:
        output["ai_analysis"] = ctx.ai_analysis.dict()
        output["ai_analysis"]["note"] = "AI analysis is heuristic and may not detect sophisticated attacks"

    # Errors and warnings
    if ctx.errors:
        output["errors"] = [err.dict() for err in ctx.errors]

    return json.dumps(output, indent=2)
