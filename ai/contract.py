from pydantic import BaseModel, field_validator, Field
from typing import List


class AIOutputContract(BaseModel):
    summary: str
    suspicious_patterns: List[str]
    attack_surface: str
    rationale: List[str]
    ai_risk_score: int = Field(default=0, ge=0, le=100)
    ai_risk_level: str = Field(default="LOW")
    ai_risk_details: str = ""

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, v):
        return str(v)[:200]

    @field_validator("suspicious_patterns")
    @classmethod
    def validate_patterns(cls, v):
        return [str(p) for p in v][:5]

    @field_validator("attack_surface")
    @classmethod
    def validate_attack_surface(cls, v):
        return str(v)[:300]

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, v):
        return [str(r) for r in v][:3]

    @field_validator("ai_risk_level")
    @classmethod
    def validate_risk_level(cls, v):
        v = str(v).upper()
        if v not in ("LOW", "MEDIUM", "HIGH"):
            return "LOW"
        return v

    @field_validator("ai_risk_details")
    @classmethod
    def validate_risk_details(cls, v):
        return str(v)[:500]
