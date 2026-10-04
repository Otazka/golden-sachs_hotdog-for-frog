"""The stakeholder use cases the acceptance suites prove. Every test is tagged with one of
these ids (`@pytest.mark.uc("UC-02")`); the run summary and the report are built from this list.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UseCase:
    id: str
    title: str
    requirement: str
    who: str  # the stakeholders it serves
    awaiting: str = ""


USE_CASES = [
    UseCase("UC-01", "Pass clean requests unchanged", "R2", "Judges, developers"),
    UseCase("UC-02", "Redact personal data in answers", "R2.1", "IT, judges, compliance"),
    UseCase("UC-03", "Slider: add card data to the filter", "R1", "IT, judges"),
    UseCase("UC-04", "Block prompt injection, say why", "R2.1/R2.2", "Judges, CISO, developers"),
    UseCase("UC-05", "Default deny for tools, block writes", "R2.1", "IT, CISO"),
    UseCase("UC-06", "Stop runaway loop and cost spike", "R3", "IT, CISO"),
    UseCase("UC-07", "Block unsafe code and model files", "R4", "Judges, CISO"),
    UseCase("UC-08", "Change policy live, no restart", "R1", "IT, judges, developers"),
    UseCase("UC-09", "Broken config keeps last good policy", "R1", "IT, judges"),
    UseCase("UC-10", "Audit log with no raw secrets", "R5", "CISO, compliance"),
    UseCase("UC-12", "Every denial names rule and reason", "R5", "CISO, developers"),
    UseCase("UC-13", "Measure latency overhead", "Perf", "Judges, developers"),
    UseCase("UC-14", "Run the whole suite in one command", "R6", "IT, judges"),
]

BY_ID = {case.id: case for case in USE_CASES}
