import os
import hashlib
import json
import time
from core.context import PipelineContext, FeatureSet, Metadata, AIOutput, ErrorDetail


class CacheStore:
    def __init__(self, cache_dir: str, ttl: int = 3600):
        self.cache_dir = cache_dir
        self.ttl = ttl
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception:
            pass

    def _get_path(self, package: str) -> str:
        key = hashlib.sha256(package.encode("utf-8")).hexdigest()
        return os.path.join(self.cache_dir, f"{key}.json")

    def get(self, package: str) -> PipelineContext | None:
        path = self._get_path(package)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            cached_at = data.get("cached_at", 0)
            if (time.time() - cached_at) > self.ttl:
                return None

            ctx_data = data.get("context", {})
            errors = [ErrorDetail(**err) for err in ctx_data.get("errors", [])]
            features = None
            if ctx_data.get("features"):
                features = FeatureSet(**ctx_data["features"])
            metadata = None
            if ctx_data.get("metadata"):
                metadata = Metadata(**ctx_data["metadata"])
            ai_analysis = None
            if ctx_data.get("ai_analysis"):
                ai_analysis = AIOutput(**ctx_data["ai_analysis"])

            return PipelineContext(
                package=ctx_data.get("package"),
                pkgbuild_raw=None,
                features=features,
                metadata=metadata,
                risk_score=ctx_data.get("risk_score"),
                risk_level=ctx_data.get("risk_level"),
                verdict=ctx_data.get("verdict"),
                ai_analysis=ai_analysis,
                static_score=ctx_data.get("static_score"),
                ai_score=ctx_data.get("ai_score"),
                errors=errors,
            )
        except Exception:
            return None

    def set(self, package: str, ctx: PipelineContext) -> bool:
        path = self._get_path(package)
        try:
            data = {
                "cached_at": time.time(),
                "context": {
                    "package": ctx.package,
                    "features": ctx.features.dict() if ctx.features else None,
                    "metadata": ctx.metadata.dict() if ctx.metadata else None,
                    "risk_score": ctx.risk_score,
                    "risk_level": ctx.risk_level,
                    "verdict": ctx.verdict,
                    "ai_analysis": ctx.ai_analysis.dict() if ctx.ai_analysis else None,
                    "static_score": ctx.static_score,
                    "ai_score": ctx.ai_score,
                    "errors": [err.dict() for err in ctx.errors],
                },
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            return True
        except Exception as e:
            ctx.errors.append(ErrorDetail(code="CACHE_WRITE_ERR", stage="Cache", message=str(e), recoverable=True))
            return False
