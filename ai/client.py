import json
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any
from google import genai
from google.genai import types
from core.context import PipelineContext, AIOutput, ErrorDetail
from ai.contract import AIOutputContract


def _call_gemini(
    api_key: str,
    model_name: str,
    prompt: str,
    timeout_ms: int,
) -> dict[str, Any]:
    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(timeout=timeout_ms),
    )

    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(text=prompt),
            ],
        ),
    ]

    gen_config = types.GenerateContentConfig()

    response = client.models.generate_content(
        model=model_name,
        contents=contents,  # type: ignore[arg-type]
        config=gen_config,
    )

    text = ""
    if response.text:
        text = response.text.strip()

    if not text:
        raise ValueError("AI returned an empty response.")

    result: dict[str, Any] = json.loads(text)
    return result


def analyze_with_gemini(ctx: PipelineContext) -> PipelineContext:
    """Run AI analysis. Returns context unchanged if AI is unavailable or fails."""
    api_key = os.getenv("AURCHECKER_AI_API_KEY")
    if not api_key:
        ctx.errors.append(
            ErrorDetail(
                code="AI_DISABLED", stage="AI", message="AI analysis skipped (no API key set).", recoverable=True
            )
        )
        return ctx

    if not ctx.features or not ctx.metadata:
        ctx.errors.append(
            ErrorDetail(
                code="AI_SCHEMA_INVALID",
                stage="AI",
                message="Cannot run AI analysis without features and metadata.",
                recoverable=True,
            )
        )
        return ctx

    payload = {
        "package": ctx.package,
        "features": ctx.features.dict(),
        "metadata": ctx.metadata.dict(),
        "risk_score": ctx.risk_score,
        "risk_level": ctx.risk_level,
    }
    payload_str = json.dumps(payload)

    model_name = os.getenv("AURCHECKER_AI_MODEL", "gemini-3.1-flash-lite")
    timeout_ms = int(os.getenv("AURCHECKER_AI_TIMEOUT", "120000"))
    deadline_s = timeout_ms / 1000 + 5

    prompt = f"""You are a security expert analyzing an Arch AUR PKGBUILD. Output ONLY valid JSON matching this schema exactly:
{{
  "summary": "string (max 200 chars) - brief risk overview",
  "suspicious_patterns": ["string"] - list of specific dangerous patterns found (max 5)",
  "attack_surface": "string (max 300 chars) - what an attacker could exploit",
  "rationale": ["string"] - reasons for the risk score (max 3)",
  "ai_risk_score": integer 0-100 - your independent risk score based on PKGBUILD content",
  "ai_risk_level": "LOW" or "MEDIUM" or "HIGH",
  "ai_risk_details": "string (max 500 chars) - what specifically contributed to the risk score"
}}

Input: {payload_str}

Output valid JSON only. No markdown. No prose."""

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_call_gemini, api_key, model_name, prompt, timeout_ms)
            result = fut.result(timeout=deadline_s)

        validated = AIOutputContract(**result)

        ctx.ai_analysis = AIOutput(
            summary=validated.summary,
            suspicious_patterns=validated.suspicious_patterns,
            attack_surface=validated.attack_surface,
            rationale=validated.rationale,
            ai_risk_score=validated.ai_risk_score,
            ai_risk_level=validated.ai_risk_level,
            ai_risk_details=validated.ai_risk_details,
        )
    except FuturesTimeout:
        ctx.errors.append(
            ErrorDetail(
                code="AI_TIMEOUT",
                stage="AI",
                message=f"AI analysis timed out after {int(deadline_s)}s. Using static analysis only.",
                recoverable=True,
            )
        )
    except json.JSONDecodeError:
        ctx.errors.append(
            ErrorDetail(
                code="AI_SCHEMA_INVALID",
                stage="AI",
                message="AI returned invalid JSON. Using static analysis only.",
                recoverable=True,
            )
        )
    except Exception as e:
        ctx.errors.append(
            ErrorDetail(
                code="AI_FAILED",
                stage="AI",
                message=f"AI analysis failed: {str(e)[:100]}. Using static analysis only.",
                recoverable=True,
            )
        )

    return ctx
