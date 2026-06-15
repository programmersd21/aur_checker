import sys
from typing import List, Optional
import typer
from cli.root import app, state
from core.pipeline import run_pipeline
from output.human import format_human
from output.json import format_json
from rich.console import Console

console = Console()


@app.command("batch", help="Run safety checks on a list of AUR packages.")
def batch_command(
    packages: List[str] = typer.Argument(None, help="Optional packages to check"),
    file_path: Optional[str] = typer.Option(None, "--file", help="Read package list from file"),
):
    pkg_list = list(packages) if packages else []

    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_list.append(line)

    if not pkg_list:
        sys.exit(0)

    any_unrecoverable = False

    for pkg in pkg_list:
        res = run_pipeline(pkg, skip_cache=state.no_cache)
        if any(not err.recoverable for err in res.errors):
            any_unrecoverable = True

        if state.json:
            console.print_json(format_json(res))
        else:
            console.print(format_human(res, verbose=state.verbose))
            console.print()

    if any_unrecoverable:
        sys.exit(1)

    sys.exit(0)
