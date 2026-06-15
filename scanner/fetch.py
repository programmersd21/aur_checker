import time
import requests
from core.context import PipelineContext, ErrorDetail


def fetch_pkgbuild(ctx: PipelineContext, timeout: int = 10) -> PipelineContext:
    url = f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={ctx.package}"
    headers = {"User-Agent": "aur_checker/1.0.0"}
    retries = 2
    backoffs = [1.0, 2.0]

    for attempt in range(retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                body = response.text
                if not body:
                    ctx.errors.append(
                        ErrorDetail(
                            code="FETCH_EMPTY", stage="Fetch", message="Fetched PKGBUILD is empty.", recoverable=False
                        )
                    )
                    return ctx
                ctx.pkgbuild_raw = body
                return ctx
            elif response.status_code == 404:
                ctx.errors.append(
                    ErrorDetail(
                        code="FETCH_NOT_FOUND",
                        stage="Fetch",
                        message=f"Package {ctx.package} not found on AUR.",
                        recoverable=False,
                    )
                )
                return ctx
            else:
                if attempt == retries:
                    ctx.errors.append(
                        ErrorDetail(
                            code="FETCH_NOT_FOUND",
                            stage="Fetch",
                            message=f"HTTP Error {response.status_code}",
                            recoverable=False,
                        )
                    )
                    return ctx
        except requests.exceptions.Timeout as e:
            if attempt == retries:
                ctx.errors.append(ErrorDetail(code="FETCH_TIMEOUT", stage="Fetch", message=str(e), recoverable=False))
                return ctx
        except requests.exceptions.RequestException as e:
            if attempt == retries:
                ctx.errors.append(
                    ErrorDetail(code="FETCH_NETWORK_ERR", stage="Fetch", message=str(e), recoverable=False)
                )
                return ctx

        if attempt < retries:
            time.sleep(backoffs[attempt])

    return ctx
