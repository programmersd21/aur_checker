import typer
from compat_platform.detect import detect_color

app = typer.Typer(
    name="aur_checker",
    help="A CLI tool to analyze Arch Linux AUR PKGBUILDs for security risks.",
    add_completion=False,
    no_args_is_help=True,
)


class GlobalOptions:
    json: bool = False
    no_cache: bool = False
    verbose: bool = False
    use_color: bool = True


state = GlobalOptions()


@app.callback()
def main(
    json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON only; suppress all prose"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache read and write for this invocation"),
    verbose: bool = typer.Option(False, "--verbose", help="Include raw FeatureSet and Metadata in output"),
    color: str = typer.Option("auto", "--color", help="ANSI color support: auto, true, false"),
):
    state.json = json
    state.no_cache = no_cache
    state.verbose = verbose
    state.use_color = detect_color(color)


# Import subcommands so @app.command() decorators register them
import cli.check  # noqa: E402, F401
import cli.batch  # noqa: E402, F401
import cli.install  # noqa: E402, F401
import cli.explain  # noqa: E402, F401
import cli.report  # noqa: E402, F401
import cli.clear_cache  # noqa: E402, F401
