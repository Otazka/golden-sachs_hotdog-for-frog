"""The run summary: one line per stakeholder use case, printed at the end of every run of
`test_suites/`, plus a Markdown copy in `reports/acceptance-report.md` for the jury.

Outcomes per test: pass, fail, known gap (an expected failure, `xfail`: the product does not
do it yet and the test says so), fixed gap (an `xfail` that now passes) and skip.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from test_suites.catalog import BY_ID, USE_CASES

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS = REPO_ROOT / "reports"
LATENCY_FILE = REPORTS / "latency.json"
WIDTH = 92


@dataclass
class Tally:
    passed: int = 0
    failed: int = 0
    gaps: int = 0
    fixed: int = 0
    skipped: int = 0
    gap_notes: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.gaps + self.fixed + self.skipped


def policy_version() -> str:
    """The same version the firewall stamps on every Decision."""
    path = REPO_ROOT / "policy.yaml"
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12] if path.exists() else "-"


def _short(nodeid: str) -> str:
    return nodeid.split("::", 1)[-1]


def _gap_reason(report) -> str:
    return str(getattr(report, "wasxfail", "")).removeprefix("reason: ").strip()


def _label(nodeid: str) -> str:
    """`test_x[email-in-words]` -> `email-in-words`; `test_the_audit_log` -> `the audit log`."""
    name = _short(nodeid)
    if "[" in name:
        return name[name.index("[") + 1:-1]
    return name.removeprefix("test_").replace("_", " ")


class Summary:
    def __init__(self) -> None:
        self.cases: dict[str, list[str]] = {}  # nodeid -> use case ids
        self.tally: dict[str, Tally] = defaultdict(Tally)
        self.pairs: dict[str, dict[str, bool]] = defaultdict(dict)  # Control -> good/bad -> ok
        self.started = time.perf_counter()

    # -- pytest hooks call these ------------------------------------------------------------

    def collect(self, items) -> None:
        self.started = time.perf_counter()
        for item in items:
            ids = [uc for mark in item.iter_markers("uc") for uc in mark.args]
            if ids:
                self.cases[item.nodeid] = ids

    def record(self, report) -> None:
        ids = self.cases.get(report.nodeid)
        if not ids:
            return
        if report.when == "setup" and report.passed:
            return
        if report.when == "teardown" and not report.failed:
            return
        for kind, marker in (("good", "test_good_case_is_allowed["),
                             ("bad", "test_bad_case_is_stopped[")):
            if marker in report.nodeid:
                control = report.nodeid.split(marker, 1)[1].rstrip("]")
                self.pairs[control][kind] = report.passed and not hasattr(report, "wasxfail")
        for uc in ids:
            tally = self.tally[uc]
            name = _short(report.nodeid)
            if hasattr(report, "wasxfail"):
                if report.passed:
                    tally.fixed += 1
                else:
                    tally.gaps += 1
                    tally.gap_notes.append(f"{_label(report.nodeid)}: {_gap_reason(report)}")
            elif report.passed:
                tally.passed += 1
            elif report.failed:
                tally.failed += 1
                tally.failures.append(name)
            elif report.skipped:
                tally.skipped += 1

    # -- the verdict per use case -----------------------------------------------------------

    def status(self, uc: str) -> tuple[str, str]:
        """(label, colour) for one use case."""
        tally = self.tally.get(uc, Tally())
        if tally.failed:
            return "✘ FAIL", "red"
        if BY_ID[uc].awaiting and tally.fixed == 0 and tally.gaps + tally.skipped:
            return "⏳ AWAITING", "yellow"
        if tally.total == 0:
            return "· not run", "white"
        if tally.passed + tally.fixed == 0:
            return "⏳ AWAITING", "yellow"
        return "✔ PASS", "green"

    def ran(self) -> bool:
        return bool(self.tally)

    # -- terminal ---------------------------------------------------------------------------

    def render(self, tr) -> None:
        if not self.ran():
            return
        seconds = time.perf_counter() - self.started
        bar = "═" * WIDTH
        line = "─" * WIDTH
        tr.write_line("")
        tr.write_line(bar, cyan=True)
        title = "  AI CONTROL LAYER · ACCEPTANCE SUITE"
        version = f"policy.yaml {policy_version()}  "
        tr.write_line(title + version.rjust(WIDTH - len(title)), cyan=True, bold=True)
        tr.write_line(bar, cyan=True)
        tr.write_line(f"  {'Use case':<48}{'Req':<11}{'Tests':>6}   Result", bold=True)
        tr.write_line("  " + line[2:], cyan=True)
        for case in USE_CASES:
            tally = self.tally.get(case.id, Tally())
            label, colour = self.status(case.id)
            tr.write(f"  {case.id}  {case.title:<41}{case.requirement:<11}{tally.total:>6}   ")
            tr.write(label, **{colour: True, "bold": True})
            extra = []
            if tally.gaps:
                extra.append(f"{tally.gaps} known gap{'s' * (tally.gaps > 1)}")
            if tally.fixed:
                extra.append(f"{tally.fixed} gap{'s' * (tally.fixed > 1)} now fixed")
            if extra:
                tr.write("  · " + ", ".join(extra), yellow=True)
            tr.write_line("")
        tr.write_line("  " + line[2:], cyan=True)
        self._render_totals(tr, seconds)
        self._render_pairs(tr)
        self._render_latency(tr)
        self._render_notes(tr)
        path = self.write_markdown(seconds)
        tr.write_line(f"  Report for the jury: {path.relative_to(REPO_ROOT)}", cyan=True)
        tr.write_line(bar, cyan=True)

    def _render_totals(self, tr, seconds: float) -> None:
        tallies = [self.tally.get(case.id, Tally()) for case in USE_CASES]
        green = sum(self.status(case.id)[0].startswith("✔") for case in USE_CASES)
        passed = sum(t.passed + t.fixed for t in tallies)
        failed = sum(t.failed for t in tallies)
        gaps = sum(t.gaps for t in tallies)
        tr.write(f"  {green}/{len(USE_CASES)} use cases proven   ", bold=True)
        tr.write(f"{passed} passed", green=True, bold=True)
        tr.write("   ")
        tr.write(f"{failed} failed", red=bool(failed), green=not failed, bold=True)
        if gaps:
            tr.write(f"   {gaps} known gaps", yellow=True)
        tr.write_line(f"   {seconds:.1f} s")

    def _render_pairs(self, tr) -> None:
        if not self.pairs:
            return
        complete = [c for c, p in self.pairs.items() if p.get("good") and p.get("bad")]
        ok = len(complete) == len(self.pairs)
        tr.write("  Positive + negative case per Control (R6): ")
        tr.write(f"{len(complete)}/{len(self.pairs)} Controls", green=ok, red=not ok, bold=True)
        missing = sorted(set(self.pairs) - set(complete))
        tr.write_line(f"   missing: {', '.join(missing)}" if missing else "")

    def _render_latency(self, tr) -> None:
        latency = read_latency()
        if latency:
            tr.write_line(
                f"  Firewall overhead per request: p50 {latency['overhead_p50_ms']:.1f} ms · "
                f"p95 {latency['overhead_p95_ms']:.1f} ms  ({latency['requests']} requests, "
                "every Control on, mock model)"
            )

    def gap_lines(self) -> list[tuple[str, str]]:
        """One line per known gap; a use case that awaits the product gets a single line."""
        lines = []
        for case in USE_CASES:
            tally = self.tally.get(case.id, Tally())
            if case.awaiting and (tally.gaps or tally.skipped):
                waiting = tally.gaps + tally.skipped
                lines.append((case.id, f"{waiting} cases wait for the {case.awaiting}"))
            else:
                lines += [(case.id, note) for note in tally.gap_notes]
        return lines

    def _render_notes(self, tr) -> None:
        notes = self.gap_lines()
        failures = [(uc, name) for uc in BY_ID for name in self.tally.get(uc, Tally()).failures]
        if failures:
            tr.write_line("  Failed:", red=True, bold=True)
            for uc, name in failures:
                tr.write_line(f"    {uc}  {name}", red=True)
        if notes:
            tr.write_line("  Known gaps (the product does not do this yet; tracked, not hidden):",
                          yellow=True)
            for uc, note in notes:
                tr.write_line(f"    {uc}  {_clip(note, 110)}", yellow=True)

    # -- Markdown ---------------------------------------------------------------------------

    def write_markdown(self, seconds: float) -> Path:
        REPORTS.mkdir(exist_ok=True)
        path = REPORTS / "acceptance-report.md"
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        rows = []
        for case in USE_CASES:
            tally = self.tally.get(case.id, Tally())
            label, _ = self.status(case.id)
            rows.append(
                f"| {case.id} | {case.title} | {case.requirement} | {case.who} | "
                f"{tally.total} | {tally.passed + tally.fixed} | {tally.failed} | {tally.gaps} | "
                f"{label} |"
            )
        lines = [
            "# Acceptance report",
            "",
            f"Generated {now} by `make acceptance` in {seconds:.1f} s, "
            f"against `policy.yaml` version `{policy_version()}`.",
            "",
            "| Use case | | Req | Serves | Tests | Passed | Failed | Known gaps | Result |",
            "|---|---|---|---|---|---|---|---|---|",
            *rows,
            "",
        ]
        if self.pairs:
            lines += ["## Positive and negative case per Control (R6)", "",
                      "| Control | Good case allowed | Bad case blocked or redacted |",
                      "|---|---|---|"]
            mark = {True: "✔", False: "✘"}
            lines += [f"| `{c}` | {mark[bool(p.get('good'))]} | {mark[bool(p.get('bad'))]} |"
                      for c, p in sorted(self.pairs.items())]
            lines.append("")
        latency = read_latency()
        if latency:
            lines += [
                "## Latency",
                "",
                f"Firewall overhead per request, every Control on, mock model, "
                f"{latency['requests']} requests: **p50 {latency['overhead_p50_ms']:.1f} ms, "
                f"p95 {latency['overhead_p95_ms']:.1f} ms**.",
                "",
                "| Control | p50 ms | p95 ms |",
                "|---|---|---|",
                *[f"| `{name}` | {v['p50']:.2f} | {v['p95']:.2f} |"
                  for name, v in latency["per_control"].items()],
                "",
            ]
        notes = self.gap_lines()
        if notes:
            lines += ["## Known gaps", "",
                      "Expected failures: the product does not do this yet. Each turns green "
                      "on its own when it is fixed.", ""]
            lines += [f"- **{uc}** {note}" for uc, note in notes]
            lines.append("")
        awaiting = [case for case in USE_CASES if case.awaiting]
        if awaiting:
            lines += ["## Awaiting the product", ""]
            lines += [f"- **{case.id}** {case.title}: {case.awaiting}" for case in awaiting]
            lines.append("")
        path.write_text("\n".join(lines))
        return path


def read_latency() -> dict | None:
    try:
        return json.loads(LATENCY_FILE.read_text())
    except (OSError, ValueError):
        return None


def _clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"


SUMMARY = Summary()
