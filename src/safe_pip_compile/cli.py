from __future__ import annotations

import importlib.metadata
import os
import sys

import click

try:
    __version__ = importlib.metadata.version("safe-pip-compile")
except importlib.metadata.PackageNotFoundError:
    __version__ = "unknown"

from safe_pip_compile.allowlist import load_allowlist
from safe_pip_compile.cache import VulnCache, get_cache_db_path, get_cache_dir
from safe_pip_compile.config import load_config
from safe_pip_compile.core import run_safe_compile
from safe_pip_compile.exceptions import (
    AllowlistError,
    OSVAPIError,
    OSVNetworkError,
    PipCompileError,
    PinnedPackagesBlockError,
    SafePipCompileError,
    UnsolvableConstraintsError,
)
from safe_pip_compile.models import CompileStatus
from safe_pip_compile.reporter import Reporter
from safe_pip_compile.terminal_ui import (
    multiselect_prompt,
    write_cve_warning_to_output,
)

EXIT_CLEAN = 0
EXIT_UNRESOLVED = 1
EXIT_COMPILE_FAILED = 2
EXIT_ERROR = 3


@click.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
        help_option_names=["-h", "--help"],
    ),
)
@click.version_option(
    __version__,
    "--version",
    "-V",
    package_name="safe-pip-compile",
    message="%(prog)s version %(version)s",
)
@click.argument("src_files", nargs=-1, type=str)
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
    # Build a temporary reporter using the raw CLI verbosity so we can print
    # errors during the argument-parsing phase (before config is loaded).
    early_reporter = Reporter(verbosity=verbose)

    # Separate src_files positional args into real paths vs pip-compile flags.
    # Click cannot tell these apart when ignore_unknown_options=True, so we do it here.
    real_src_files: list[str] = []
    for arg in src_files:
        if arg.startswith("-"):
            # Looks like a flag — pass it through to pip-compile.
            passthrough_args.append(arg)
            if verbose:
                early_reporter.console.print(
                    f"[dim]Passing unknown flag to pip-compile: {arg}[/]"
                )
        else:
            if not os.path.exists(arg):
                early_reporter.console.print(
                    f"[red]Error:[/] Path '{arg}' does not exist."
                )
                sys.exit(EXIT_ERROR)
            real_src_files.append(arg)
    src_files = tuple(real_src_files)


    file_config = load_config()
    config = file_config.merge_cli(
        max_iterations=max_iterations,
        min_severity=min_severity,
        allowlist_path=allow_list,
        strict=strict,
        output_file=output_file if output_file is not None else None,
        json_report=json_report if json_report is not None else None,
        # For boolean flags, only override when the user explicitly passed them
        # (i.e. the CLI value differs from the Click default of False/0).
        dry_run=dry_run if dry_run else None,
        cert=cert if cert is not None else None,
        no_cache=no_cache if no_cache else None,
        refresh_cache=refresh_cache if refresh_cache else None,
        verbose=verbose if verbose else None,
    )

    # Use merged config values as the effective settings for this run.
    if not json_report:
        json_report = config.json_report
    if not dry_run:
        dry_run = config.dry_run
    if not cert:
        cert = config.cert
    if not no_cache:
        no_cache = config.no_cache
    if not refresh_cache:
        refresh_cache = config.refresh_cache
    if not verbose:
        verbose = config.verbose
    reporter = Reporter(verbosity=verbose)

    if not src_files:
        src_files = ("requirements.in",)

    if not output_file:
        output_file = config.output_file or "requirements.txt"

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

    temp_files_to_cleanup = []
    source_display_paths = list(src_files)
    try:
        while True:
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
                    source_display_paths=source_display_paths,
                )
                break
            except PipCompileError as e:
                reporter.console.print(f"\n[red]pip-compile failed:[/] {e}")
                if e.stderr:
                    reporter.console.print(f"[dim]{e.stderr}[/]")
                sys.exit(EXIT_COMPILE_FAILED)
            except UnsolvableConstraintsError as e:
                import re
                reporter.console.print(f"\n[red]Resolution impossible:[/] {e}")

                conflict_match = re.search(
                    r"(?:Cannot install |No matching distribution found for )"
                    r"([\w.-]+)==([^\s]+)",
                    e.pip_stderr or ""
                )
                if conflict_match:
                    pkg_name = conflict_match.group(1)
                    pkg_version = conflict_match.group(2)
                    reporter.console.print(
                        f"\n[bold yellow]Conflict detected:[/] The pinned version "
                        f"{pkg_name}=={pkg_version} has vulnerabilities and conflicts "
                        f"with the required security constraints."
                    )

                    if click.confirm(
                        f"Do you want to automatically unpin '{pkg_name}' "
                        "in your input files and retry?"
                    ):
                        new_src, changes = _unpin_package_to_temp(
                            src_files, pkg_name, get_cache_dir()
                        )
                        for orig, unpinned in changes:
                            reporter.console.print(
                                f"  [dim]Changed:[/] {orig} -> {unpinned}"
                            )

                        for f in new_src:
                            if f not in src_files and f not in temp_files_to_cleanup:
                                temp_files_to_cleanup.append(f)
                        src_files = new_src

                        reporter.console.print(
                            f"\n[green]Successfully unpinned {pkg_name} "
                            "to temporary files. Retrying...[/]\n"
                        )
                        continue
                    reporter.console.print(
                        f"\n[yellow]Warning:[/] dependencies are resolved in {output_file}, "
                        "but unresolved CVEs remain. Please audit before using it."
                    )
                    sys.exit(EXIT_COMPILE_FAILED)

                reporter.console.print(
                    "\n[yellow]* Consider unpinning non critical libraries/ adding some CVEs to an allowlist with --allow-list[/]"
                )
                sys.exit(EXIT_COMPILE_FAILED)
            except PinnedPackagesBlockError as e:
                pinned = e.pinned_packages

                reporter.console.print(
                    f"\n[yellow]⚠  {len(pinned)} pinned "
                    f"package{'s' if len(pinned) > 1 else ''} "
                    "have CVEs that require a version upgrade to fix:[/]"
                )

                reporter.console.print()
                reporter.console.print(
                    "Unpin all required libraries? "
                    "[[bold green]y[/]]es / [[bold red]n[/]]o / [[bold blue]c[/]]ustom: ",
                    end="",
                )

                try:
                    choice = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "n"

                while choice not in ("y", "yes", "n", "no", "c", "custom"):
                    reporter.console.print(
                        "  Please enter [bold]y[/], [bold]n[/], or [bold]c[/]: ",
                        end="",
                    )
                    try:
                        choice = input().strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        choice = "n"
                        break

                if choice in ("y", "yes"):
                    # Constrain all detected packages to their minimum safe version.
                    for pkg in pinned:
                        min_ver = pkg.fix_versions[0] if pkg.fix_versions else None
                        new_src, changes = _unpin_package_to_temp(
                            src_files, pkg.name, get_cache_dir(), min_version=min_ver
                        )
                        for orig, updated in changes:
                            reporter.console.print(
                                f"  [dim]Changed:[/] {orig} → {updated}"
                            )
                        for f in new_src:
                            if f not in src_files and f not in temp_files_to_cleanup:
                                temp_files_to_cleanup.append(f)
                        src_files = new_src
                    reporter.console.print(
                        f"\n[green]Constrained {len(pinned)} package"
                        f"{'s' if len(pinned) > 1 else ''} to safe versions. Retrying…[/]\n"
                    )
                    continue

                elif choice in ("n", "no"):
                    # Write CVE warning header into the already-written output file.
                    if not dry_run:
                        write_cve_warning_to_output(output_file, pinned)
                    reporter.console.print(
                        f"\n[yellow]Warning:[/] Dependencies are resolved in "
                        f"{output_file} but the following packages still have "
                        "CVEs due to pinned versions. Review before using in production."
                    )
                    reporter.report_vulnerabilities(e.blocking_vulns)
                    sys.exit(EXIT_UNRESOLVED)

                else:  # custom
                    selected_indices = multiselect_prompt(pinned)
                    if not selected_indices:
                        reporter.console.print(
                            "\n[yellow]No packages selected — skipping unpin.[/]"
                        )
                        if not dry_run:
                            write_cve_warning_to_output(output_file, pinned)
                        reporter.report_vulnerabilities(e.blocking_vulns)
                        sys.exit(EXIT_UNRESOLVED)

                    selected = [pinned[i] for i in selected_indices]
                    for pkg in selected:
                        min_ver = pkg.fix_versions[0] if pkg.fix_versions else None
                        new_src, changes = _unpin_package_to_temp(
                            src_files, pkg.name, get_cache_dir(), min_version=min_ver
                        )
                        for orig, updated in changes:
                            reporter.console.print(
                                f"  [dim]Changed:[/] {orig} → {updated}"
                            )
                        for f in new_src:
                            if f not in src_files and f not in temp_files_to_cleanup:
                                temp_files_to_cleanup.append(f)
                        src_files = new_src
                    reporter.console.print(
                        f"\n[green]Constrained {len(selected)} package"
                        f"{'s' if len(selected) > 1 else ''} to safe versions. Retrying…[/]\n"
                    )
                    continue


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
    finally:
        for f in temp_files_to_cleanup:
            try:
                os.remove(f)
            except Exception:
                pass


def _unpin_package_to_temp(
    src_files: tuple[str, ...],
    pkg_name: str,
    cache_dir: str,
    min_version: str | None = None,
) -> tuple[tuple[str, ...], list[tuple[str, str]]]:
    """Rewrite a source file to replace a pinned package constraint.

    If *min_version* is given the pin is replaced with ``pkg>=min_version``
    (i.e. the minimum known-safe version).  Otherwise the constraint is
    removed entirely, leaving just the bare package name.
    """
    import re
    import tempfile
    import os
    # Match the package name followed by any version constraint (==, >=, <=, ~=, !=, <, >)
    pattern = re.compile(
        rf"^({re.escape(pkg_name)})(?:==|>=|<=|~=|!=|<|>)[^\s#]+",
        re.IGNORECASE,
    )
    replacement = rf"\1>={min_version}" if min_version else r"\1"

    new_src_files = []
    changes = []

    for file_path in src_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            changed = False
            new_lines = []
            for line in lines:
                if pattern.match(line):
                    new_line = pattern.sub(replacement, line)
                    new_lines.append(new_line)
                    changes.append((line.strip(), new_line.strip()))
                    changed = True
                else:
                    new_lines.append(line)

            if changed:
                fd, temp_path = tempfile.mkstemp(
                    prefix="req-unpinned-", suffix=".in", dir=cache_dir
                )
                os.close(fd)
                with open(temp_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                new_src_files.append(temp_path)
            else:
                new_src_files.append(file_path)
        except Exception:
            new_src_files.append(file_path)

    return tuple(new_src_files), changes


if __name__ == "__main__":
    main()
