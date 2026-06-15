import json
from core.context import PipelineContext


def format_json(ctx: PipelineContext) -> str:
    data = {
        "package": ctx.package,
        "risk_score": ctx.risk_score,
        "risk_level": ctx.risk_level,
        "verdict": ctx.verdict,
        "features": ctx.features.dict() if ctx.features else None,
        "metadata": ctx.metadata.dict() if ctx.metadata else None,
        "ai_analysis": ctx.ai_analysis.dict() if ctx.ai_analysis else None,
        "errors": [err.dict() for err in ctx.errors],
    }
    return json.dumps(data, indent=2)
