"""UC-10: the audit trail is complete, exportable and keeps no raw secrets (R5).

Security wants every interaction on record, allowed ones too; compliance wants it exportable and
free of the data it is meant to protect. Every Check writes one Audit Event; `audit.store_content`
says how much content is kept (`full`, `redacted`, `none`); the `audit` switch turns recording
off. The input event of a question that contains personal data is a known gap, recorded in UC-02.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from test_suites.report import policy_version

pytestmark = [pytest.mark.uc("UC-10"), pytest.mark.req("R5")]

EMAIL = "ivan.petrov@bank.com"
CARD = "4111 1111 1111 1111"
REQUIRED = {
    "check_id", "ts", "stage", "transport", "agent_id", "owner", "team", "user", "model",
    "action", "reason", "risk_score", "findings", "verdicts", "policy_version",
    "total_latency_ms", "prompt_tokens", "completion_tokens",
}


def test_every_check_is_recorded_allowed_ones_too(gateway):
    gateway.chat("Plan my day.")
    gateway.chat("Any update on Project Falcon?")

    events = gateway.events()

    assert [e["stage"] for e in events].count("input") == 2
    assert [e["stage"] for e in events].count("output") == 1, "the blocked one never ran"
    assert {e["action"] for e in events} == {"allow", "block"}


def test_an_event_answers_who_what_which_rule_and_which_policy(gateway):
    gateway.chat("Any update on Project Falcon?")

    (event,) = gateway.events(action="block")

    assert REQUIRED <= set(event)
    assert (event["agent_id"], event["owner"], event["team"]) == (
        "research-assistant", "alice@bank.example", "markets-research")
    assert event["model"] == "mock"
    assert event["policy_version"] == policy_version()
    assert event["verdicts"] and event["findings"]
    assert event["total_latency_ms"] >= 0


def test_the_user_behind_the_agent_is_recorded(gateway):
    gateway.chat("Plan my day.", user="ivan")

    assert {e["user"] for e in gateway.events()} == {"ivan"}


def test_tokens_are_recorded_for_cost_reporting(gateway):
    gateway.chat("one two three four")

    (output,) = gateway.events(stage="output")
    assert output["prompt_tokens"] > 0 and output["completion_tokens"] > 0


# ---- export ------------------------------------------------------------------------------------


def test_export_as_jsonl_has_one_parseable_line_per_event(gateway):
    gateway.chat("Plan my day.")
    gateway.chat("Any update on Project Falcon?")

    lines = gateway.export("jsonl").strip().splitlines()

    rows = [json.loads(line) for line in lines]
    assert len(rows) == len(gateway.events())
    assert all(REQUIRED <= set(row) for row in rows)


def test_export_as_csv_opens_in_a_spreadsheet(gateway):
    gateway.chat("Plan my day.")

    rows = list(csv.DictReader(io.StringIO(gateway.export("csv"))))

    assert len(rows) == len(gateway.events())
    assert {"agent_id", "action", "reason", "policy_version"} <= set(rows[0])


def test_export_can_be_filtered_for_an_investigation(gateway):
    gateway.chat("Plan my day.")
    gateway.chat("Any update on Project Falcon?")

    lines = gateway.export("jsonl", action="block").strip().splitlines()

    assert [json.loads(line)["action"] for line in lines] == ["block"]


def test_the_metrics_match_the_events(gateway):
    gateway.chat("Plan my day.")
    gateway.chat("Any update on Project Falcon?")

    metrics = gateway.metrics()

    assert metrics["total_checks"] == len(gateway.events())
    assert metrics["by_action"].get("block") == 1


# ---- what content is kept ----------------------------------------------------------------------


@pytest.mark.parametrize("store_content", ["redacted", "none"])
def test_the_answer_event_keeps_no_raw_personal_data(gateway, store_content):
    gateway.policy.set_store_content(store_content)
    gateway.chat(f"Client {EMAIL}, card {CARD}.")

    (event,) = gateway.events(stage="output")

    assert EMAIL not in json.dumps(event) and CARD not in json.dumps(event)


def test_none_keeps_the_decision_but_no_content_at_all(gateway):
    gateway.policy.set_store_content("none")
    gateway.chat("Plan my day.")

    for event in gateway.events():
        assert event["content_before"] is None and event["content_after"] is None
        assert event["action"]


def test_full_keeps_before_and_after_for_forensics(gateway):
    """`full` is the forensic setting: the raw value is kept on purpose, next to the cleaned one."""
    gateway.policy.set_store_content("full")
    gateway.chat(f"Client {EMAIL}.")

    (event,) = gateway.events(stage="output")

    assert EMAIL in json.dumps(event["content_before"])
    assert EMAIL not in json.dumps(event["content_after"])


def test_the_explanation_fields_never_hold_the_value(gateway):
    gateway.chat(f"Client {EMAIL}, card {CARD}.")

    for event in gateway.events():
        explanation = json.dumps([event["reason"], event["findings"], event["verdicts"]])
        assert EMAIL not in explanation and CARD not in explanation


# ---- the switch ----------------------------------------------------------------------------------


def test_recording_can_be_switched_off_and_on(gateway):
    gateway.chat("Plan my day.")
    before = len(gateway.events())

    gateway.policy.set_feature("audit", False)
    gateway.chat("Plan my week.")
    assert len(gateway.events()) == before

    gateway.policy.set_feature("audit", True)
    gateway.chat("Plan my month.")
    assert len(gateway.events()) > before
