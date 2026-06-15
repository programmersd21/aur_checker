import sys
import subprocess
import shutil
import typer
from cli.root import app, state
from core.pipeline import run_pipeline
from output.human import format_human
from output.json import format_json
from rich.console import Console
from rich.panel import Panel

console = Console()


@app.command("install", help="Perform safety checks and install an AUR package.")
def install_command(package: str = typer.Argument(..., help="AUR package name to check and install")):
    if not shutil.which("makepkg"):
        if not state.json:
            console.print(
                Panel(
                    "[red]install requires makepkg; not available on this platform[/red]",
                    title="Error",
                    border_style="red",
                    expand=True,
                )
            )
        sys.exit(6)

    res = run_pipeline(package, skip_cache=state.no_cache)

    unrecoverable = any(not err.recoverable for err in res.errors)
    if unrecoverable:
        if state.json:
            console.print_json(format_json(res))
        else:
            console.print(format_human(res, verbose=state.verbose))
        sys.exit(1)

    if not res.pkgbuild_raw and any(err.code == "FETCH_NOT_FOUND" for err in res.errors):
        if state.json:
            console.print_json(format_json(res))
        else:
            console.print(format_human(res, verbose=state.verbose))
        sys.exit(2)

    if res.verdict == "DENY":
        if state.json:
            console.print_json(format_json(res))
        else:
            console.print(format_human(res, verbose=state.verbose))
            console.print(
                Panel(
                    "[red]package installation denied by scoring policy[/red]",
                    title="Error",
                    border_style="red",
                    expand=True,
                )
            )
        sys.exit(3)

    if state.json:
        console.print_json(format_json(res))
    else:
        console.print(format_human(res, verbose=state.verbose))

    confirm = input("Do you want to proceed with installation? (y/N): ").strip().lower()
    if confirm != "y":
        sys.exit(4)

    subprocess.run(["makepkg", "-si"])
    sys.exit(0)
