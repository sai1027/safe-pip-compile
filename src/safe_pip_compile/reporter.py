from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from safe_pip_compile.models import (
    CompileResult,
    CompileStatus,
    ResolvedPackage,
    Vulnerability,
)


class Reporter:
    def __init__(self, verbosity: int = 0, console: Console | None = None):
        self.console = console or Console()
        self.verbosity = verbosity

    def start_iteration(self, n: int, max_n: int) -> None:
        self.console.print(
            f"\n[bold blue][Iteration {n}/{max_n}][/] Running pip-compile..."
        )

    def report_resolver_inputs(
        self, src_files: list[str], constraints_file: str | None = None
    ) -> None:
        self.console.print(
            "  Using these constraints and requirement files to resolve dependencies:"
        )
        if constraints_file:
            self.console.print(f"    -c {constraints_file}")
        for src_file in src_files:
            self.console.print(f"    -r {src_file}")

    def report_packages(self, packages: list[ResolvedPackage]) -> None:
        if self.verbosity >= 1:
            for pkg in packages:
                self.console.print(f"  {pkg.name}=={pkg.version}")
        self.console.print(f"  Resolved [bold]{len(packages)}[/] packages")

    def report_querying_osv(self, count: int) -> None:
        self.console.print(f"  Querying OSV.dev for {count} packages...")

    def report_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        if not vulns:
            return

        self.console.print(
            f"\n  [bold red]{len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'} found:[/]"
        )

        table = Table(show_header=True, header_style="bold", padding=(0, 1))
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("Vulnerability", style="red")
        table.add_column("Severity", justify="center")
        table.add_column("Fix Available", style="green")

        for vuln in vulns:
            severity_style = _severity_style(vuln.severity.name)
            fix = vuln.fixed_versions[0] if vuln.fixed_versions else "None"

            table.add_row(
                vuln.affected_package,
                vuln.affected_version,
                vuln.display_id,
                f"[{severity_style}]{vuln.severity.name}[/]",
                f">= {fix}" if vuln.fixed_versions else "[red]No fix[/]",
            )

        self.console.print(table)

    def report_constraints(self, constraints: list[str]) -> None:
        self.console.print(
            f"\n  [bold]Adding constraints:[/] {', '.join(constraints)}"
        )

    def report_clean(
        self, iteration: int, output_file: str = "requirements.txt"
    ) -> None:
        self.console.print(
            f"\n  [bold green]No vulnerabilities found.[/] "
            f"{output_file} is clean "
            f"({'on first pass' if iteration == 1 else f'after {iteration} iterations'})."
        )

    def report_clean_after_filtering(
        self,
        iteration: int,
        filtered_count: int,
        output_file: str = "requirements.txt",
    ) -> None:
        self.console.print(
            f"\n  [bold green]All clear.[/] "
            f"{filtered_count} vulnerabilit{'y' if filtered_count == 1 else 'ies'} "
            f"filtered by severity/allowlist. "
            f"{output_file} is clean after {iteration} iteration{'s' if iteration > 1 else ''}."
        )

    def report_unfixable(self, vulns: list[Vulnerability]) -> None:
        self.console.print(
            f"\n  [bold red]No fix available[/] for {len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'}:"
        )
        self.report_vulnerabilities(vulns)
        self.console.print(
            "\n  [yellow]Use --allow-list to accept these CVEs if the risk is acceptable.[/]"
        )

    def report_stuck(self, vulns: list[Vulnerability]) -> None:
        self.console.print(
            "\n  [bold red]Resolution is stuck:[/] constraints from previous iteration "
            "did not change the output. The resolver cannot find a non-vulnerable combination."
        )
        if vulns:
            self.report_vulnerabilities(vulns)

    def report_max_iterations(
        self, max_iterations: int, vulns: list[Vulnerability]
    ) -> None:
        self.console.print(
            f"\n  [bold red]Max iterations ({max_iterations}) reached.[/] "
            f"Remaining vulnerabilities:"
        )
        if vulns:
            self.report_vulnerabilities(vulns)

    def report_final_summary(self, result: CompileResult) -> None:
        total_vulns = len(result.all_vulns_found)
        resolved = total_vulns - len(result.remaining_vulns)
        iterations = len(result.iterations)

        status_msg = {
            CompileStatus.CLEAN: "[bold green]CLEAN[/]",
            CompileStatus.UNFIXABLE_CVES: "[bold red]UNFIXABLE CVEs[/]",
            CompileStatus.STUCK: "[bold red]STUCK[/]",
            CompileStatus.MAX_ITERATIONS: "[bold yellow]MAX ITERATIONS[/]",
            CompileStatus.PIP_COMPILE_FAILED: "[bold red]COMPILE FAILED[/]",
        }

        panel_content = (
            f"Status: {status_msg.get(result.status, result.status.value)}\n"
            f"Iterations: {iterations}\n"
            f"CVEs found: {total_vulns}\n"
            f"CVEs resolved: {resolved}\n"
            f"CVEs remaining: {len(result.remaining_vulns)}"
        )

        self.console.print(
            Panel(panel_content, title="[bold]Summary[/]", border_style="blue")
        )

    def generate_json_report(self, filepath: str, result: CompileResult) -> None:
        report = {
            "status": result.status.value,
            "iterations": len(result.iterations),
            "total_vulns_found": len(result.all_vulns_found),
            "remaining_vulns": len(result.remaining_vulns),
            "packages": [
                {"name": p.name, "version": p.version}
                for p in result.final_packages
            ],
            "vulnerabilities": [
                {
                    "id": v.id,
                    "aliases": list(v.aliases),
                    "package": v.affected_package,
                    "version": v.affected_version,
                    "severity": v.severity.name,
                    "cvss_score": v.cvss_score,
                    "fixed_versions": list(v.fixed_versions),
                    "url": v.details_url,
                }
                for v in result.all_vulns_found
            ],
            "remaining": [
                {
                    "id": v.id,
                    "aliases": list(v.aliases),
                    "package": v.affected_package,
                    "severity": v.severity.name,
                }
                for v in result.remaining_vulns
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)


def _severity_style(severity_name: str) -> str:
    styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "UNKNOWN": "dim",
    }
    return styles.get(severity_name, "white")
