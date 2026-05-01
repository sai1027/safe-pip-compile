from __future__ import annotations

import os
import tempfile
from typing import TYPE_CHECKING

from safe_pip_compile.allowlist import filter_allowed, load_allowlist
from safe_pip_compile.cache import VulnCache
from safe_pip_compile.cached_client import CachedOSVClient
from safe_pip_compile.constraints import generate_constraints, merge_constraints
from safe_pip_compile.exceptions import (
    PipCompileError,
    UnsolvableConstraintsError,
)
from safe_pip_compile.models import (
    AllowlistEntry,
    CompileResult,
    CompileStatus,
    IterationResult,
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
) -> CompileResult:
    accumulated_constraints: list[str] = []
    all_iterations: list[IterationResult] = []
    all_vulns: list[Vulnerability] = []
    seen_pkg_versions: set[tuple[str, str]] = set()

    output_dir = os.path.dirname(os.path.abspath(output_file)) or "."
    constraints_fd, constraints_path = tempfile.mkstemp(
        prefix=".safe-pip-compile-constraints-",
        suffix=".txt",
        dir=output_dir,
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
                    reporter.report_clean(iteration)
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

                for vuln in vulnerabilities:
                    if not vuln.affected_package:
                        for pkg_name, vid_list in vuln_map.items():
                            if vuln.id in vid_list:
                                vulnerabilities = [
                                    Vulnerability(
                                        id=v.id,
                                        aliases=v.aliases,
                                        summary=v.summary,
                                        severity=v.severity,
                                        cvss_score=v.cvss_score,
                                        affected_package=pkg_name,
                                        affected_version=next(
                                            (p.version for p in packages if p.normalized_name == pkg_name.lower().replace("_", "-")),
                                            v.affected_version,
                                        ),
                                        fixed_versions=v.fixed_versions,
                                        details_url=v.details_url,
                                    ) if v.id == vuln.id else v
                                    for v in vulnerabilities
                                ]

            if not vulnerabilities:
                reporter.report_clean(iteration)
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
                reporter.report_clean_after_filtering(iteration, filtered_count)
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
