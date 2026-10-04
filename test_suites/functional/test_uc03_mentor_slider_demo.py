"""UC-03: the mentor's demo, step by step (R1, R2.1).

"The IT person ticks a box: output filtering is on, personal data disappears. Then they extend
the control, no personal data plus no credit data, and the second attempt removes more. The
Agent noticed nothing." Here the box and the slider are lines in `policy.yaml`: the
`data_protection` switch and the `enabled` flag of each `sensitive_data` category. The Agent
sends exactly the same request every time; only the Policy file changes, and no restart happens.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.uc("UC-03"), pytest.mark.req("R1", "R2.1")]

EMAIL = "ivan.petrov@bank.com"
PHONE = "+48 600 123 456"
CARD = "4111 1111 1111 1111"
IBAN = "GB82WEST12345698765432"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
RECORD = f"Client {EMAIL}, phone {PHONE}, card {CARD}, account {IBAN}, key {AWS_KEY}."

PERSONAL = ("email", "phone")
FINANCIAL = ("card", "iban")
SECRETS = ("aws_access_key", "github_token", "llm_api_key", "private_key", "jwt",
           "generic_secret")


def only(gateway, enabled: tuple[str, ...]) -> None:
    """Move the slider: exactly these categories are on."""
    data = gateway.policy.load()
    for category in data["controls"]["sensitive_data"]["params"]["categories"]:
        category["enabled"] = category["name"] in enabled
    gateway.policy.save(data)


def visible(gateway) -> set[str]:
    """Which of the five values reach the Agent, asking exactly the same thing every time."""
    answer = gateway.chat(RECORD).answer
    names = {"email": EMAIL, "phone": PHONE, "card": CARD, "iban": IBAN, "key": AWS_KEY}
    return {name for name, value in names.items() if value in answer}


def test_the_whole_demo_without_a_restart(gateway):
    gateway.policy.set_feature("data_protection", False)
    assert visible(gateway) == {"email", "phone", "card", "iban", "key"}, "0. nothing filtered"

    gateway.policy.set_feature("data_protection", True)
    only(gateway, PERSONAL)
    assert visible(gateway) == {"card", "iban", "key"}, "1. the box: personal data is gone"

    only(gateway, PERSONAL + FINANCIAL)
    assert visible(gateway) == {"key"}, "2. the slider: card and account are gone too"

    only(gateway, PERSONAL + FINANCIAL + SECRETS)
    assert visible(gateway) == set(), "3. and secrets"


def test_every_step_is_decided_by_a_new_policy_version(gateway):
    versions = []
    for step in ((), PERSONAL, PERSONAL + FINANCIAL, PERSONAL + FINANCIAL + SECRETS):
        only(gateway, step)
        versions.append(gateway.chat(RECORD).firewall["policy_version"])

    assert len(set(versions)) == 4, "each edit of policy.yaml is a new version, applied at once"


def test_moving_the_slider_back_shows_the_data_again(gateway):
    only(gateway, PERSONAL + FINANCIAL)
    assert visible(gateway) == {"key"}

    only(gateway, PERSONAL)

    assert visible(gateway) == {"card", "iban", "key"}


def test_the_agent_sees_what_was_removed_and_why(gateway):
    only(gateway, PERSONAL + FINANCIAL)

    reply = gateway.chat(RECORD)

    found = {f["type"] for f in reply.firewall["output"]["decision"]["findings"]}
    assert found == {"email", "phone", "card", "iban"}
    for label in ("[EMAIL]", "[PHONE]", "[CARD]", "[IBAN]"):
        assert label in reply.answer
    assert reply.firewall["action"] == "redact"


def test_a_category_can_stop_the_answer_instead_of_cleaning_it(gateway):
    """The other end of the slider: Block instead of Redact for one kind of data."""
    gateway.policy.set_mode("sensitive_data", "block")
    gateway.policy.set_category("card", on_match="block")

    reply = gateway.chat(f"Card {CARD}.")

    assert reply.blocked
    assert CARD not in reply.answer
