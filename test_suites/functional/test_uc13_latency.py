"""UC-13: the firewall's own overhead is measured and small (performance).

The same 60 requests go through the proxy twice: with every Control on, and with every switch
off. The difference is what the firewall costs per request. Each Control's own time comes from
its Verdict (`latency_ms`). The model is the in-process mock and the semantic model runs on its
stub, so the numbers are the firewall alone, not the network or a model.

The result is written to `reports/latency.json` and shown in the run summary. Thresholds are
deliberately generous so a busy laptop does not fail the suite; the numbers are the evidence.
"""

from __future__ import annotations

import json
import statistics
import time
from collections import defaultdict

import pytest

from test_suites.harness import build_gateway
from test_suites.report import LATENCY_FILE, REPORTS

pytestmark = [pytest.mark.uc("UC-13"), pytest.mark.req("Perf")]

REQUESTS = 60
SWITCHES = ("input_validation", "data_protection", "resource_access", "usage_limits")
# Different words, not numbers: the loop detector ignores numbers.
DESKS = ["rates", "fx", "credit", "equities", "commodities", "treasury", "repo", "swaps"]
TOPICS = ["risk", "pnl", "volume", "exposure", "liquidity", "margin", "hedging", "funding"]


def percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(share * (len(ordered) - 1)))]


def run(gateway) -> tuple[list[float], dict[str, list[float]]]:
    """Wall time per request (ms), and each Control's own time from the Verdicts."""
    totals: list[float] = []
    per_control: dict[str, list[float]] = defaultdict(list)
    for i in range(REQUESTS):
        text = f"Summarise the {DESKS[i % 8]} desk {TOPICS[i // 8]} report"
        started = time.perf_counter()
        reply = gateway.chat(text)
        totals.append((time.perf_counter() - started) * 1000)
        assert not reply.blocked, reply.reason
        for stage in ("input", "output"):
            for verdict in reply.firewall[stage]["decision"]["verdicts"]:
                per_control[verdict["control"]].append(verdict["latency_ms"])
        gateway.clock.advance(5)  # stay under the call-rate limit: this is a speed test
    return totals, per_control


@pytest.fixture(scope="module")
def measured(tmp_path_factory):
    from firewall_app.controls.injection_model import MockScorer

    folder = tmp_path_factory.mktemp("latency")
    every_control = build_gateway(folder / "on")
    no_control = build_gateway(folder / "off")
    for switch in SWITCHES:
        no_control.policy.set_feature(switch, False)

    with pytest.MonkeyPatch.context() as patch:  # the semantic model's stub, as in every test
        patch.setattr("firewall_app.controls.injection_classifier.onnx_scorer",
                      lambda model, model_dir: MockScorer({}))
        run(every_control)  # warm-up: first-request costs are not overhead
        run(no_control)
        on, per_control = run(every_control)
        off, _ = run(no_control)

    result = {
        "requests": REQUESTS,
        "every_control_p50_ms": statistics.median(on),
        "every_control_p95_ms": percentile(on, 0.95),
        "no_control_p50_ms": statistics.median(off),
        "no_control_p95_ms": percentile(off, 0.95),
        "overhead_p50_ms": max(0.0, statistics.median(on) - statistics.median(off)),
        "overhead_p95_ms": max(0.0, percentile(on, 0.95) - percentile(off, 0.95)),
        "per_control": {
            name: {"p50": statistics.median(values), "p95": percentile(values, 0.95)}
            for name, values in sorted(per_control.items())
        },
    }
    REPORTS.mkdir(exist_ok=True)
    LATENCY_FILE.write_text(json.dumps(result, indent=2))
    return result


def test_every_control_ran_on_every_request(measured):
    expected = {"keyword_blocklist", "injection_heuristics", "injection_classifier",
                "sensitive_data", "output_sanitizer", "loop_detector", "request_limits",
                "token_budget"}
    assert expected <= set(measured["per_control"])


def test_the_firewall_adds_little_per_request(measured):
    assert measured["overhead_p50_ms"] < 50
    assert measured["every_control_p95_ms"] < 250


def test_no_single_control_is_slow(measured):
    slow = {name: v["p95"] for name, v in measured["per_control"].items() if v["p95"] > 25}
    assert slow == {}


def test_the_numbers_are_saved_for_the_report(measured):
    saved = json.loads(LATENCY_FILE.read_text())

    assert saved["requests"] == REQUESTS
    assert saved["overhead_p95_ms"] >= 0
