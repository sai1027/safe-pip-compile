from __future__ import annotations

import os
import re
import sys
import tempfile
from typing import TYPE_CHECKING

from safe_pip_compile.allowlist import filter_allowed
from safe_pip_compile.cache import VulnCache, get_cache_dir
from safe_pip_compile.cached_client import CachedOSVClient
from safe_pip_compile.constraints import generate_constraints, merge_constraints
from safe_pip_compile.exceptions import (
    PipCompileError,
    PinnedPackagesBlockError,
    UnsolvableConstraintsError,
)
from safe_pip_compile.models import (
    AllowlistEntry,
    CompileResult,
    CompileStatus,
    IterationResult,
    PinnedBlockingPackage,
    Severity,
    Vulnerability,
)
from safe_pip_compile.osv_client import OSVClient
from safe_pip_compile.parser import parse_requirements
from safe_pip_compile.pip_compile import run_pip_compile

if TYPE_CHECKING:
    from safe_pip_compile.reporter import Reporter


def run_safe_compile(
    src_files: list[str],
    output_file: str,
    passthrough_args: list[str],
    min_severity: Severity,
    allowlist: list[AllowlistEntry],
    max_iterations: int,
    dry_run: bool,
    reporter: Reporter,
    osv_client: OSVClient | None = None,
    cache: VulnCache | None = None,
    cert_path: str | None = None,
    source_display_paths: list[str] | None = None,
) -> CompileResult:
    accumulated_constraints: list[str] = []
    all_iterations: list[IterationResult] = []
    all_vulns: list[Vulnerability] = []
    seen_pkg_versions: set[tuple[str, str]] = set()

    cache_dir = get_cache_dir()
    constraints_fd, constraints_path = tempfile.mkstemp(
        prefix=".safe-pip-compile-constraints-",
        suffix=".txt",
        dir=cache_dir,
    )
    os.close(constraints_fd)

    raw_client = osv_client or OSVClient(cert_path=cert_path)
    own_client = osv_client is None

    if cache is not None:
        client = CachedOSVClient(raw_client, cache)
    else:
        client = None

    try:
        for iteration in range(1, max_iterations + 1):
            iter_result = IterationResult(iteration=iteration)
            reporter.start_iteration(iteration, max_iterations)

            constraints_file_arg = None
            if accumulated_constraints:
                with open(constraints_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(accumulated_constraints) + "\n")
                constraints_file_arg = constraints_path

            if constraints_file_arg or _has_temporary_source(src_files):
                reporter.report_resolver_inputs(src_files, constraints_file_arg)

            from contextlib import nullcontext
            console = getattr(reporter, "console", None)
            status_ctx = (
                console.status("[bold white]Resolving dependencies...", spinner="dots")
                if console is not None
                else nullcontext()
            )
            with status_ctx:
                pip_result = run_pip_compile(
                    src_files=src_files,
                    output_file=output_file if not dry_run else None,
                    extra_args=passthrough_args,
                    constraints_file=constraints_file_arg,
                )

            if pip_result.failed:
                iter_result.pip_compile_succeeded = False
                all_iterations.append(iter_result)

                if iteration == 1:
                    raise PipCompileError(
                        "Initial pip-compile failed",
                        returncode=pip_result.returncode,
                        stderr=pip_result.stderr,
                    )
                else:
                    raise UnsolvableConstraintsError(
                        constraints=accumulated_constraints,
                        pip_stderr=pip_result.stderr,
                    )

            if not dry_run:
                _sanitize_compile_output(
                    output_file=output_file,
                    constraints_path=constraints_path,
                    src_files=src_files,
                    source_display_paths=source_display_paths,
                )

            if dry_run and iteration == 1:
                output_for_parsing = _get_dry_run_output(pip_result, src_files)
            else:
                output_for_parsing = output_file

            packages = parse_requirements(output_for_parsing)
            iter_result.packages = packages
            reporter.report_packages(packages)

            current_pkg_versions = {
                (pkg.normalized_name, pkg.version) for pkg in packages
            }
            if current_pkg_versions <= seen_pkg_versions and iteration > 1:
                reporter.report_stuck(all_vulns[-len(packages):] if all_vulns else [])
                all_iterations.append(iter_result)
                return CompileResult(
                    status=CompileStatus.STUCK,
                    iterations=all_iterations,
                    final_packages=packages,
                    remaining_vulns=iter_result.vulnerabilities,
                    all_vulns_found=all_vulns,
                )
            seen_pkg_versions.update(current_pkg_versions)

            reporter.report_querying_osv(len(packages))

            if client is not None:
                vulnerabilities = client.batch_query_and_fetch(packages)
            else:
                vuln_map = raw_client.batch_query(packages)

                if not vuln_map:
                    reporter.report_clean(iteration, output_file)
                    all_iterations.append(iter_result)
                    return CompileResult(
                        status=CompileStatus.CLEAN,
                        iterations=all_iterations,
                        final_packages=packages,
                        all_vulns_found=all_vulns,
                    )

                all_vuln_ids = list({
                    vid for ids in vuln_map.values() for vid in ids
                })
                vulnerabilities = raw_client.fetch_vulnerabilities(all_vuln_ids)

                # Map each fetched vulnerability back to its queried package.
                # A vulnerability may not carry affected_package in the OSV
                # response, so we derive it from the vuln_map query context.
                _vid_to_pkg: dict[str, str] = {
                    vid: pkg_name
                    for pkg_name, vid_list in vuln_map.items()
                    for vid in vid_list
                }
                _pkg_ver_map: dict[str, str] = {
                    pkg.normalized_name: pkg.version for pkg in packages
                }
                _filled: list[Vulnerability] = []
                for v in vulnerabilities:
                    if not v.affected_package:
                        _pname = _vid_to_pkg.get(v.id, "")
                        _norm = _pname.lower().replace("_", "-")
                        v = Vulnerability(
                            id=v.id,
                            aliases=v.aliases,
                            summary=v.summary,
                            severity=v.severity,
                            cvss_score=v.cvss_score,
                            affected_package=_pname,
                            affected_version=_pkg_ver_map.get(_norm, ""),
                            fixed_versions=v.fixed_versions,
                            details_url=v.details_url,
                        )
                    _filled.append(v)
                vulnerabilities = _filled

            # ----------------------------------------------------------------
            # Unified post-processing (both cached and non-cached paths):
            #   1. Deduplicate by (normalised_package, vuln_id) — the same CVE
            #      can arrive via multiple query paths (e.g. "Pillow"/"pillow").
            #   2. Fill in affected_version from the resolved packages list for
            #      any remaining empty values (safety net for the cached path).
            # ----------------------------------------------------------------
            _pv: dict[str, str] = {pkg.normalized_name: pkg.version for pkg in packages}
            _seen_keys: set[tuple[str, str]] = set()
            _deduped: list[Vulnerability] = []
            for v in vulnerabilities:
                _norm = v.affected_package.lower().replace("_", "-") if v.affected_package else ""
                _key = (_norm, v.id)
                if _key in _seen_keys:
                    continue
                _seen_keys.add(_key)
                if v.affected_package and not v.affected_version:
                    v = Vulnerability(
                        id=v.id,
                        aliases=v.aliases,
                        summary=v.summary,
                        severity=v.severity,
                        cvss_score=v.cvss_score,
                        affected_package=v.affected_package,
                        affected_version=_pv.get(_norm, ""),
                        fixed_versions=v.fixed_versions,
                        details_url=v.details_url,
                    )
                _deduped.append(v)
            vulnerabilities = _deduped

            if not vulnerabilities:
                reporter.report_clean(iteration, output_file)

                all_iterations.append(iter_result)
                return CompileResult(
                    status=CompileStatus.CLEAN,
                    iterations=all_iterations,
                    final_packages=packages,
                    all_vulns_found=all_vulns,
                )

            severity_filtered = [
                v for v in vulnerabilities if v.severity.meets_threshold(min_severity)
            ]

            blocking_vulns, allowed_vulns = filter_allowed(
                severity_filtered, allowlist
            )

            iter_result.vulnerabilities = vulnerabilities
            iter_result.filtered_vulns = blocking_vulns
            all_vulns.extend(vulnerabilities)

            if not blocking_vulns:
                filtered_count = len(vulnerabilities) - len(blocking_vulns)
                reporter.report_clean_after_filtering(
                    iteration, filtered_count, output_file
                )
                all_iterations.append(iter_result)
                return CompileResult(
                    status=CompileStatus.CLEAN,
                    iterations=all_iterations,
                    final_packages=packages,
                    all_vulns_found=all_vulns,
                )

            reporter.report_vulnerabilities(blocking_vulns)

            new_constraints = generate_constraints(blocking_vulns, packages)

            if not new_constraints:
                reporter.report_unfixable(blocking_vulns)
                all_iterations.append(iter_result)
                return CompileResult(
                    status=CompileStatus.UNFIXABLE_CVES,
                    iterations=all_iterations,
                    final_packages=packages,
                    remaining_vulns=blocking_vulns,
                    all_vulns_found=all_vulns,
                )

            if set(new_constraints) <= set(accumulated_constraints):
                reporter.report_stuck(blocking_vulns)
                all_iterations.append(iter_result)
                return CompileResult(
                    status=CompileStatus.STUCK,
                    iterations=all_iterations,
                    final_packages=packages,
                    remaining_vulns=blocking_vulns,
                    all_vulns_found=all_vulns,
                )

            # Proactively detect pinned packages that would block the next pip-compile run.
            # We do this before accumulating constraints so the user gets one batch prompt
            # instead of discovering conflicts one-by-one through pip-compile failures.
            pinned_blockers = _find_pinned_blockers(blocking_vulns, src_files)
            if pinned_blockers:
                raise PinnedPackagesBlockError(pinned_blockers, blocking_vulns)

            accumulated_constraints = merge_constraints(
                accumulated_constraints, new_constraints
            )
            iter_result.constraints_added = new_constraints
            reporter.report_constraints(new_constraints)
            all_iterations.append(iter_result)

        last_vulns = all_iterations[-1].filtered_vulns if all_iterations else []
        reporter.report_max_iterations(max_iterations, last_vulns)
        return CompileResult(
            status=CompileStatus.MAX_ITERATIONS,
            iterations=all_iterations,
            final_packages=all_iterations[-1].packages if all_iterations else [],
            remaining_vulns=last_vulns,
            all_vulns_found=all_vulns,
        )

    finally:
        try:
            os.unlink(constraints_path)
        except OSError:
            pass
        if client is not None:
            client.close()
        elif own_client:
            raw_client.close()


def _get_dry_run_output(pip_result, src_files: list[str]) -> str:
    if src_files:
        base = os.path.splitext(src_files[0])[0]
        return base + ".txt"
    return "requirements.txt"


def _sanitize_compile_output(
    output_file: str,
    constraints_path: str,
    src_files: list[str],
    source_display_paths: list[str] | None,
) -> None:
    if not os.path.exists(output_file):
        return

    source_display_paths = source_display_paths or src_files
    source_replacements = {
        src: _display_path_for_source(src, display)
        for src, display in zip(src_files, source_display_paths)
    }
    constraint_variants = set(_path_variants(constraints_path))

    with open(output_file, encoding="utf-8") as f:
        lines = f.readlines()

    sanitized: list[str] = []
    for line in lines:
        # Drop internal constraints file references from the via-comment block.
        if "#   -c " in line and any(path in line for path in constraint_variants):
            continue

        new_line = line
        for src_path, display_path in source_replacements.items():
            for variant in _path_variants(src_path):
                r_variant = f"-r {variant}"
                r_display = f"-r {display_path}"
                if r_variant in new_line:
                    new_line = new_line.replace(r_variant, "User")
                elif r_display in new_line:
                    new_line = new_line.replace(r_display, "User")
                elif variant in new_line:
                    new_line = new_line.replace(variant, display_path)

        sanitized.append(new_line)

    py = sys.version_info
    header = (
        f"#\n"
        f"# This file is autogenerated by safe-pip-compile for Python {py.major}.{py.minor}\n"
        f"#\n"
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(header)
        f.writelines(sanitized)


def _display_path_for_source(src_path: str, display_path: str) -> str:
    if _is_temporary_source(src_path):
        return os.path.basename(display_path)
    return display_path


def _has_temporary_source(src_files: list[str]) -> bool:
    return any(_is_temporary_source(path) for path in src_files)


def _is_temporary_source(path: str) -> bool:
    return os.path.basename(path).startswith("req-unpinned-")


def _path_variants(path: str) -> tuple[str, ...]:
    normalized = os.path.normpath(path)
    absolute = os.path.abspath(path)
    variants = {
        path,
        normalized,
        absolute,
        path.replace("\\", "/"),
        normalized.replace("\\", "/"),
        absolute.replace("\\", "/"),
    }
    return tuple(variants)


def _find_pinned_blockers(
    blocking_vulns: list[Vulnerability],
    src_files: list[str],
) -> list[PinnedBlockingPackage]:
    """Detect packages that are pinned with == in source files and have fixable blocking CVEs.

    Only non-temporary source files are scanned (temp files have already been unpinned).
    Returns one PinnedBlockingPackage per affected package, with all vuln IDs and fix
    versions aggregated and the worst severity recorded.
    """
    real_src_files = [f for f in src_files if not _is_temporary_source(f)]
    if not real_src_files:
        return []

    # Aggregate vuln data per package name (normalized).
    vuln_by_pkg: dict[str, list[Vulnerability]] = {}
    for vuln in blocking_vulns:
        if not vuln.affected_package or not vuln.fixed_versions:
            # Skip unfixable vulns — generate_constraints already handled them.
            continue
        key = vuln.affected_package.lower().replace("_", "-")
        vuln_by_pkg.setdefault(key, []).append(vuln)

    result: list[PinnedBlockingPackage] = []
    for _key, vulns in vuln_by_pkg.items():
        pkg_name = vulns[0].affected_package
        # Build a pattern that matches both - and _ separators (PEP 503).
        escaped = re.escape(pkg_name)
        normalized_pat = escaped.replace(r"\-", r"[-_]").replace(r"\_", r"[-_]")
        pin_pattern = re.compile(rf"^\s*{normalized_pat}\s*==", re.IGNORECASE)

        is_pinned = False
        for src_file in real_src_files:
            try:
                with open(src_file, encoding="utf-8") as fh:
                    for line in fh:
                        if pin_pattern.match(line):
                            is_pinned = True
                            break
            except OSError:
                pass
            if is_pinned:
                break

        if not is_pinned:
            continue

        all_vuln_ids = tuple(dict.fromkeys(v.display_id for v in vulns))
        all_fix_versions = tuple(dict.fromkeys(fv for v in vulns for fv in v.fixed_versions))
        worst_severity = max(vulns, key=lambda v: v.severity.value).severity
        affected_version = vulns[0].affected_version

        result.append(
            PinnedBlockingPackage(
                name=pkg_name,
                version=affected_version,
                vuln_ids=all_vuln_ids,
                fix_versions=all_fix_versions,
                severity=worst_severity,
            )
        )

    return result

