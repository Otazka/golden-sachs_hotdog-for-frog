"""UC-01: ordinary work passes through untouched (R2).

A firewall that blocks normal work is switched off by Monday. With every Control on, an ordinary
question, a code snippet, a table, a Polish sentence or a link to an internal page must reach the
model and come back exactly as the model wrote it, with no Finding and an `allow` Decision that
names the Policy version that decided.
"""

from __future__ import annotations

import pytest

from test_suites.harness import TRADER_KEY
from test_suites.report import policy_version

pytestmark = [pytest.mark.uc("UC-01"), pytest.mark.req("R2")]

CLEAN = {
    "question": "What were the main drivers of revenue growth last quarter?",
    "polish": "Podsumuj wyniki kwartalne w trzech punktach.",
    "german": "Bitte fasse das Protokoll der Sitzung kurz zusammen.",
    "code": "def add(a, b):\n    return a + b\n\nprint(add(2, 3))",
    "json": '{"ticker": "ACME", "price": 101.5, "currency": "USD"}',
    "table": "| Desk | PnL |\n|---|---|\n| Rates | 1.2m |\n| FX | 0.8m |",
    "numbers": "Order 2026-10-04 at 14:30, version 3.11.4, ticket JIRA-12345, 1,234,567.89 USD.",
    "internal-link": "See the guide at https://wiki.bank.internal/vpn for the setup.",
    "emoji": "Great result this quarter 📈 well done team!",
    "long": "The committee reviewed the quarterly figures in detail. " * 150,
}


@pytest.mark.parametrize("text", CLEAN.values(), ids=CLEAN.keys())
def test_ordinary_text_reaches_the_model_and_comes_back_unchanged(gateway, text):
    reply = gateway.chat(text)

    assert reply.status == 200
    assert reply.answer == f"Mock response: {text}"
    assert reply.finish_reason == "stop"
    assert reply.firewall["action"] == "allow"
    assert reply.reached_the_model
    assert reply.firewall["input"]["decision"]["findings"] == []
    assert reply.firewall["output"]["decision"]["findings"] == []


def test_every_decision_names_the_policy_version_that_made_it(gateway):
    reply = gateway.chat("Hello")

    assert reply.firewall["policy_version"] == policy_version()


def test_every_agent_in_the_policy_gets_through(gateway):
    for key in (None, TRADER_KEY):
        reply = gateway.chat("Hello") if key is None else gateway.chat("Hello", key=key)
        assert not reply.blocked


def test_a_whole_conversation_passes_and_the_last_question_is_answered(gateway):
    messages = [
        {"role": "system", "content": "You are a helpful assistant for the research desk."},
        {"role": "user", "content": "Summarise the meeting."},
        {"role": "assistant", "content": "The meeting covered the budget."},
        {"role": "user", "content": "And the next steps?"},
    ]

    reply = gateway.chat(messages=messages)

    assert not reply.blocked
    assert reply.answer == "Mock response: And the next steps?"


def test_the_model_usage_is_reported_back(gateway):
    reply = gateway.chat("one two three four")

    assert reply.body["usage"]["prompt_tokens"] > 0
    assert reply.body["usage"]["completion_tokens"] > 0


@pytest.mark.parametrize(
    ("stage", "body", "field"),
    [
        ("input", {"messages": [{"role": "user", "content": "Plan my day."}]}, "messages"),
        ("output", {"message": {"role": "assistant", "content": "Here is the plan."}}, "message"),
        ("tool_result", {"tool": {"resource": "files", "action": "read_file",
                                  "args": {"path": "/demo/README.txt"}},
                         "tool_result": "Demo workspace. Nothing secret here."}, "tool_result"),
    ],
    ids=["input", "output", "tool_result"],
)
def test_the_check_api_lets_clean_content_through_at_every_stage(gateway, stage, body, field):
    result = gateway.check(stage, body)

    assert result["decision"]["action"] == "allow"
    assert result[field] == body[field]


def test_an_allowed_resource_call_is_allowed(gateway):
    decision = gateway.tool_call("files", "read_file", path="/demo/README.txt")

    assert decision["action"] == "allow"
    assert decision["findings"] == []
