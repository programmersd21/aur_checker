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
    res = run_pipeline(package, skip_cache=state.no_cache)
    unrecoverable = any(not err.recoverable for err in res.errors)

    if state.json:
        console.print_json(format_json(res))
    else:
        console.print(format_human(res, verbose=state.verbose))

    if unrecoverable:
        sys.exit(1)

    if not res.pkgbuild_raw and any(err.code == "FETCH_NOT_FOUND" for err in res.errors):
        sys.exit(2)

    sys.exit(0)
