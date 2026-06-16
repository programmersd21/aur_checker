from typing import Optional, List
from pydantic import BaseModel, Field


class FeatureSet(BaseModel):
    remote_exec_count: int
    external_calls: int
    package_manager_usage: List[str]
    obfuscation_score: int
    system_modification: bool


class TrustSignals(BaseModel):
    """AUR-specific trust indicators."""

    package_age_days: int | str
    maintainer_history: str  # stable, changed, orphan_adopted, new
    update_frequency_days: int | str
    is_popular: bool  # votes > 100
    out_of_date: bool


class ScoreBreakdown(BaseModel):
    """Detailed breakdown of risk score contributions."""

    remote_exec: int
    external_calls: int
    pkg_manager: int
    orphan_adopted: int
    obfuscation: int
    system_modification: int
    maintainer_changed: int
    trust_penalty: int
    total_static: int


class Metadata(BaseModel):
    maintainer: str
    orphan_status: bool
    package_age_days: str | int
    last_update_delta_days: str | int
    maintainer_changed: str
    votes: int = 0
    popularity: float = 0.0
    out_of_date: bool = False


class AIOutput(BaseModel):
    summary: str = Field(..., max_length=200)
    suspicious_patterns: List[str]
    attack_surface: str = Field(..., max_length=300)
    rationale: List[str]
    ai_risk_score: int = Field(default=0, ge=0, le=100)
    ai_risk_level: str = Field(default="LOW", pattern=r"^(LOW|MEDIUM|HIGH)$")
    ai_risk_details: str = Field(default="", max_length=500)


class ErrorDetail(BaseModel):
    code: str
    stage: str
    message: str
    recoverable: bool


class PipelineContext(BaseModel):
    schema_version: str = "1.0.1"
    package: str
    pkgbuild_raw: Optional[str] = None
    features: Optional[FeatureSet] = None
    metadata: Optional[Metadata] = None
    trust_signals: Optional[TrustSignals] = None
    score_breakdown: Optional[ScoreBreakdown] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    verdict: Optional[str] = None
    ai_analysis: Optional[AIOutput] = None
    ai_enabled: bool = False
    errors: List[ErrorDetail] = []
    static_score: Optional[int] = None
    ai_score: Optional[int] = None
