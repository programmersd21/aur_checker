from typing import Optional, List
from pydantic import BaseModel, Field


class FeatureSet(BaseModel):
    remote_exec_count: int
    external_calls: int
    package_manager_usage: List[str]
    obfuscation_score: int
    system_modification: bool


class Metadata(BaseModel):
    maintainer: str
    orphan_status: bool
    package_age_days: str | int
    last_update_delta_days: str | int
    maintainer_changed: str


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
    package: str
    pkgbuild_raw: Optional[str] = None
    features: Optional[FeatureSet] = None
    metadata: Optional[Metadata] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    verdict: Optional[str] = None
    ai_analysis: Optional[AIOutput] = None
    errors: List[ErrorDetail] = []
    static_score: Optional[int] = None
    ai_score: Optional[int] = None
