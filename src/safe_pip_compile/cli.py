from __future__ import annotations

import sys

import click

from safe_pip_compile.allowlist import load_allowlist
from safe_pip_compile.cache import VulnCache, get_cache_db_path
from safe_pip_compile.config import load_config
from safe_pip_compile.core import run_safe_compile
from safe_pip_compile.exceptions import (
    AllowlistError,
    OSVAPIError,
    OSVNetworkError,
    PipCompileError,
    SafePipCompileError,
    UnsolvableConstraintsError,
)
from safe_pip_compile.models import CompileStatus
from safe_pip_compile.reporter import Reporter

EXIT_CLEAN = 0
EXIT_UNRESOLVED = 1
EXIT_COMPILE_FAILED = 2
EXIT_ERROR = 3


@click.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
    ),
)
@click.argument("src_files", nargs=-1, type=click.Path(exists=True))
@click.option("-o", "--output-file", type=click.Path(), default=None,
              help="Output file path (passed to pip-compile)")
@click.option("--min-severity",
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              default=None,
              help="Minimum severity to block (default: all)")
@click.option("--allow-list", type=click.Path(exists=True), default=None,
              help="YAML allowlist of accepted CVEs")
@click.option("--max-iterations", type=int, default=None,
              help="Maximum resolution iterations (default: 10)")
@click.option("--strict/--no-strict", default=None,
              help="Fail on unresolved CVEs (default: strict)")
@click.option("--dry-run", is_flag=True,
              help="Show what would happen without writing files")
@click.option("--json-report", type=click.Path(), default=None,
              help="Write JSON vulnerability report to file")
@click.option("--no-cache", is_flag=True,
              help="Disable local CVE cache, always query OSV.dev")
@click.option("--refresh-cache", is_flag=True,
              help="Ignore cached data and re-fetch, then update cache")
@click.option("--cert", type=click.Path(exists=True), default=None,
              help="Path to CA bundle for SSL verification (corporate proxies). "
                   "Also reads SSL_CERT_FILE / REQUESTS_CA_BUNDLE env vars.")
@click.option("-v", "--verbose", count=True,
              help="Increase verbosity (-v, -vv)")
@click.pass_context
def main(ctx, src_files, output_file, min_severity, allow_list,
         max_iterations, strict, dry_run, json_report, no_cache,
         refresh_cache, cert, verbose):
    """CVE-aware pip-compile wrapper.

    Wraps pip-compile and iteratively resolves dependencies while avoiding
    packages with known vulnerabilities (via OSV.dev).

    All unrecognized options are passed through to pip-compile.

    \b
    Examples:
        safe-pip-compile requirements.in -o requirements.txt
        safe-pip-compile requirements.in --min-severity high
        safe-pip-compile requirements.in --allow-list cve-allowlist.yaml
        safe-pip-compile requirements.in -- --generate-hashes
    """
    passthrough_args = list(ctx.args)
    reporter = Reporter(verbosity=verbose)

    file_config = load_config()
    config = file_config.merge_cli(
        max_iterations=max_iterations,
        min_severity=min_severity,
        allowlist_path=allow_list,
        strict=strict,
    )

    if not src_files:
        src_files = ("requirements.in",)

    if not output_file:
        import os
        base = os.path.splitext(src_files[0])[0]
        output_file = base + ".txt"

    allowlist = []
    if config.allowlist_path:
        try:
            allowlist = load_allowlist(config.allowlist_path)
            if verbose:
                reporter.console.print(
                    f"Loaded {len(allowlist)} allowlist entries from {config.allowlist_path}"
                )
        except AllowlistError as e:
            reporter.console.print(f"[red]Allowlist error:[/] {e}")
            sys.exit(EXIT_ERROR)

    cache = None
    if not no_cache:
        try:
            cache = VulnCache()
            cache.open()
            if refresh_cache:
                cache.clear()
                if verbose:
                    reporter.console.print("Cache cleared (--refresh-cache)")
            else:
                cache.purge_expired()
                stats = cache.stats()
                if verbose:
                    reporter.console.print(
                        f"Cache: {stats['packages']} packages, "
                        f"{stats['vulnerabilities']} CVEs cached "
                        f"({get_cache_db_path()})"
                    )
        except Exception as e:
            reporter.console.print(f"[yellow]Cache warning:[/] {e} (continuing without cache)")
            cache = None

    try:
        result = run_safe_compile(
            src_files=list(src_files),
            output_file=output_file,
            passthrough_args=passthrough_args,
            min_severity=config.min_severity,
            allowlist=allowlist,
            max_iterations=config.max_iterations,
            dry_run=dry_run,
            reporter=reporter,
            cache=cache,
            cert_path=cert,
        )
    except PipCompileError as e:
        reporter.console.print(f"\n[red]pip-compile failed:[/] {e}")
        if e.stderr:
            reporter.console.print(f"[dim]{e.stderr}[/]")
        sys.exit(EXIT_COMPILE_FAILED)
    except UnsolvableConstraintsError as e:
        reporter.console.print(f"\n[red]Resolution impossible:[/] {e}")
        reporter.console.print(
            "\n[yellow]Consider adding some CVEs to an allowlist with --allow-list[/]"
        )
        sys.exit(EXIT_COMPILE_FAILED)
    except (OSVAPIError, OSVNetworkError) as e:
        reporter.console.print(f"\n[red]OSV.dev error:[/] {e}")
        sys.exit(EXIT_ERROR)
    except SafePipCompileError as e:
        reporter.console.print(f"\n[red]Error:[/] {e}")
        sys.exit(EXIT_ERROR)

    reporter.report_final_summary(result)

    if json_report:
        reporter.generate_json_report(json_report, result)
        reporter.console.print(f"\nJSON report written to {json_report}")

    if result.status == CompileStatus.CLEAN:
        sys.exit(EXIT_CLEAN)
    elif result.status == CompileStatus.PIP_COMPILE_FAILED:
        sys.exit(EXIT_COMPILE_FAILED)
    elif config.strict and result.remaining_vulns:
        sys.exit(EXIT_UNRESOLVED)
    elif result.remaining_vulns:
        reporter.console.print(
            "\n[yellow]Warning: unresolved CVEs remain (non-strict mode)[/]"
        )
        sys.exit(EXIT_CLEAN)
    else:
        sys.exit(EXIT_CLEAN)


if __name__ == "__main__":
    main()
