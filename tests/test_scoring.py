from core.context import PipelineContext, FeatureSet, Metadata
from scoring.engine import score_package


def test_scoring_engine_low():
    ctx = PipelineContext(
        package="testpkg",
        features=FeatureSet(
            remote_exec_count=0,
            external_calls=0,
            package_manager_usage=[],
            obfuscation_score=0,
            system_modification=False,
        ),
        metadata=Metadata(
            maintainer="test",
            orphan_status=False,
            package_age_days=100,
            last_update_delta_days=10,
            maintainer_changed="UNKNOWN",
        ),
    )
    res = score_package(ctx)
    assert res.risk_score == 0
    assert res.risk_level == "LOW"
    assert res.verdict == "ALLOW"


def test_scoring_engine_high():
    ctx = PipelineContext(
        package="testpkg",
        features=FeatureSet(
            remote_exec_count=2,
            external_calls=2,
            package_manager_usage=["pip", "npm"],
            obfuscation_score=3,
            system_modification=True,
        ),
        metadata=Metadata(
            maintainer="UNKNOWN",
            orphan_status=True,
            package_age_days=10,
            last_update_delta_days=5,
            maintainer_changed="UNKNOWN",
        ),
    )
    res = score_package(ctx)
    assert res.risk_score > 70
    assert res.risk_level == "HIGH"
    assert res.verdict == "DENY"
