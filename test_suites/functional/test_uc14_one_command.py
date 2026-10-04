"""UC-14: one command runs everything, offline, and every use case is traceable (R6).

`make acceptance` runs this folder and prints one line per stakeholder use case. These tests
check the suite itself: every use case of the catalog has tests, the command exists, the test
data parses and nothing needs a network or an API key.
"""

from __future__ import annotations

import os
import re

import pytest
import yaml

from test_suites.catalog import USE_CASES
from test_suites.harness import DATA, REPO_ROOT

pytestmark = [pytest.mark.uc("UC-14"), pytest.mark.req("R6")]

SUITES = REPO_ROOT / "test_suites" / "functional"


def tagged_use_cases() -> set[str]:
    found: set[str] = set()
    for path in SUITES.glob("test_*.py"):
        found |= set(re.findall(r'uc\("(UC-\d\d)"\)', path.read_text()))
    return found


def test_every_use_case_of_the_catalog_has_tests():
    assert {case.id for case in USE_CASES} <= tagged_use_cases()


def test_every_test_file_is_tagged_with_a_use_case():
    untagged = [p.name for p in SUITES.glob("test_*.py") if 'mark.uc("UC-' not in p.read_text()]
    assert untagged == []


def test_one_make_target_runs_the_suite():
    makefile = (REPO_ROOT / "Makefile").read_text()
    assert re.search(r"^acceptance:", makefile, re.MULTILINE)
    assert "pytest test_suites" in makefile


@pytest.mark.parametrize("path", sorted(DATA.glob("*.yaml")), ids=lambda p: p.name)
def test_the_test_data_parses(path):
    assert isinstance(yaml.safe_load(path.read_text()), dict)


def test_no_api_key_is_needed(gateway):
    """The suite runs on the built-in mock model; a key in the environment changes nothing."""
    keys = [name for name in os.environ if name.endswith("_API_KEY")]
    assert gateway.chat("Hello").answer == "Mock response: Hello", f"env keys present: {keys}"
