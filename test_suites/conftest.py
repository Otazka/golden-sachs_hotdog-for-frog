"""Fixtures for the acceptance suites.

Every test gets its own copy of the real Policy (`policy.yaml`), its own SQLite file and its
own firewall app, all in a temp dir. See harness.py for the helpers.
"""

from __future__ import annotations

import pytest

from test_suites.harness import Gateway, build_gateway
from test_suites.report import SUMMARY


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "uc(id): stakeholder use case, e.g. UC-02")
    config.addinivalue_line("markers", "req(ids): challenge requirement, e.g. R2.1")
    config.addinivalue_line("markers", "ml: needs the real injection model (the `ml` extra)")


# The run summary per use case (see report.py).


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    SUMMARY.collect(items)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    SUMMARY.record(report)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    SUMMARY.render(terminalreporter)


@pytest.fixture(autouse=True)
def offline_injection_model(request, monkeypatch):
    """The Presets run injection_classifier with the real ONNX model. Tests must not depend on
    whether the `ml` extra is installed, so the model is a stub that scores everything safe.
    Tests marked `ml` get the real model."""
    if request.node.get_closest_marker("ml"):
        return
    from firewall_app.controls.injection_model import MockScorer

    monkeypatch.setattr(
        "firewall_app.controls.injection_classifier.onnx_scorer",
        lambda model, model_dir: MockScorer({}),
    )


@pytest.fixture
def make_gateway(tmp_path, monkeypatch):
    """`make_gateway()` starts a firewall on a temp copy of policy.yaml."""
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    counter = 0

    def make() -> Gateway:
        nonlocal counter
        counter += 1
        return build_gateway(tmp_path / f"fw{counter}")

    return make


@pytest.fixture
def gateway(make_gateway) -> Gateway:
    return make_gateway()
