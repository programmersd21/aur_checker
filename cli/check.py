import sys
import typer
from cli.root import app, state
from core.pipeline import run_pipeline
from output.human import format_human
from output.json import format_json
from rich.console import Console

console = Console()


@app.command("check", help="Run safety checks on a single AUR package.")
def check_command(package: str = typer.Argument(..., help="AUR package name to check")):
    """
    Exit codes:
    0 - Analysis completed, package appears safe (ALLOW)
    1 - Analysis completed, high risk detected (DENY)
    2 - Analysis completed, manual review needed (REVIEW)
    3 - Package not found on AUR
    4 - Unrecoverable error during analysis
    """
    res = run_pipeline(package, skip_cache=state.no_cache)
    unrecoverable = any(not err.recoverable for err in res.errors)

    if state.json:
        console.print_json(format_json(res))
    else:
        console.print(format_human(res, verbose=state.verbose))

    # Exit code logic
    if not res.pkgbuild_raw and any(err.code == "FETCH_NOT_FOUND" for err in res.errors):
        sys.exit(3)  # Package not found

    if unrecoverable:
        sys.exit(4)  # Unrecoverable error

    if res.verdict == "ALLOW":
        sys.exit(0)  # Safe
    elif res.verdict == "DENY":
        sys.exit(1)  # High risk
    else:  # REVIEW
        sys.exit(2)  # Manual review needed
