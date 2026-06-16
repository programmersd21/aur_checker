import time
import requests
from core.context import PipelineContext, Metadata, TrustSignals, ErrorDetail


def fetch_metadata(ctx: PipelineContext, timeout: int = 8) -> PipelineContext:
    url = f"https://aur.archlinux.org/rpc/v5/info?arg[]={ctx.package}"
    headers = {"User-Agent": "aur_checker/1.0.0"}
    retries = 1

    for attempt in range(retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                if not results:
                    ctx.errors.append(
                        ErrorDetail(
                            code="METADATA_NOT_FOUND",
                            stage="Metadata",
                            message="Package metadata not found in results.",
                            recoverable=True,
                        )
                    )
                    ctx.metadata = Metadata(
                        maintainer="UNKNOWN",
                        orphan_status=False,
                        package_age_days="UNKNOWN",
                        last_update_delta_days="UNKNOWN",
                        maintainer_changed="UNKNOWN",
                    )
                    return ctx

                pkg_data = results[0]
                maintainer = pkg_data.get("Maintainer")
                orphan_status = maintainer is None
                maintainer_str = maintainer if maintainer else "UNKNOWN"

                now = int(time.time())

                first_submitted = pkg_data.get("FirstSubmitted")
                package_age_days: int | str
                if first_submitted is not None:
                    package_age_days = int((now - first_submitted) / 86400)
                else:
                    package_age_days = "UNKNOWN"

                last_modified = pkg_data.get("LastModified")
                last_update_delta_days: int | str
                if last_modified is not None:
                    last_update_delta_days = int((now - last_modified) / 86400)
                else:
                    last_update_delta_days = "UNKNOWN"

                votes = pkg_data.get("NumVotes", 0)
                popularity = pkg_data.get("Popularity", 0.0)
                out_of_date = pkg_data.get("OutOfDate") is not None

                # Determine maintainer history
                maintainer_history = "stable"
                if orphan_status:
                    if isinstance(package_age_days, int) and package_age_days > 90:
                        maintainer_history = "orphan_adopted"
                    else:
                        maintainer_history = "new"
                elif isinstance(package_age_days, int) and package_age_days < 30:
                    maintainer_history = "new"

                # Build trust signals
                is_popular = votes > 100
                ctx.trust_signals = TrustSignals(
                    package_age_days=package_age_days,
                    maintainer_history=maintainer_history,
                    update_frequency_days=last_update_delta_days,
                    is_popular=is_popular,
                    out_of_date=out_of_date,
                )

                ctx.metadata = Metadata(
                    maintainer=maintainer_str,
                    orphan_status=orphan_status,
                    package_age_days=package_age_days,
                    last_update_delta_days=last_update_delta_days,
                    maintainer_changed="UNKNOWN",
                    votes=votes,
                    popularity=popularity,
                    out_of_date=out_of_date,
                )
                return ctx
            else:
                if attempt == retries:
                    ctx.errors.append(
                        ErrorDetail(
                            code="METADATA_FETCH_FAILED",
                            stage="Metadata",
                            message=f"HTTP Error {response.status_code}",
                            recoverable=True,
                        )
                    )
        except requests.exceptions.Timeout as e:
            if attempt == retries:
                ctx.errors.append(
                    ErrorDetail(code="METADATA_TIMEOUT", stage="Metadata", message=str(e), recoverable=True)
                )
        except Exception as e:
            if attempt == retries:
                ctx.errors.append(
                    ErrorDetail(code="METADATA_FETCH_FAILED", stage="Metadata", message=str(e), recoverable=True)
                )

    ctx.metadata = Metadata(
        maintainer="UNKNOWN",
        orphan_status=False,
        package_age_days="UNKNOWN",
        last_update_delta_days="UNKNOWN",
        maintainer_changed="UNKNOWN",
    )
    return ctx
