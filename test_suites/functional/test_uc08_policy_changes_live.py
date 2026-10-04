"""UC-08: the Policy changes behaviour on the next request, no restart (R1).

Judges will edit `policy.yaml` during the demo and expect the firewall to follow at once. The
firewall re-reads the file before every Check; nothing else writes it (the settings API is
read-only). Every test here edits the file of a running firewall and sends the next request.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.uc("UC-08"), pytest.mark.req("R1")]

EMAIL = "ivan.petrov@bank.com"


# ---- 1. the master switches ------------------------------------------------------------------


def test_data_protection_off_and_on(gateway):
    assert EMAIL not in gateway.chat(f"Mail {EMAIL}").answer

    gateway.policy.set_feature("data_protection", False)
    assert EMAIL in gateway.chat(f"Mail {EMAIL}").answer

    gateway.policy.set_feature("data_protection", True)
    assert EMAIL not in gateway.chat(f"Mail {EMAIL}").answer


def test_input_validation_off_and_on(gateway):
    assert gateway.chat("Any update on Project Falcon?").blocked

    gateway.policy.set_feature("input_validation", False)
    assert not gateway.chat("Any update on Project Falcon?").blocked

    gateway.policy.set_feature("input_validation", True)
    assert gateway.chat("Any update on Project Falcon?").blocked


def test_resource_access_off_and_on(gateway):
    def read_keys():
        return gateway.tool_call("files", "read_file", path="/home/me/.ssh/id_rsa")["action"]

    assert read_keys() == "block"
    gateway.policy.set_feature("resource_access", False)
    assert read_keys() == "allow"
    gateway.policy.set_feature("resource_access", True)
    assert read_keys() == "block"


def test_usage_limits_off_lets_a_loop_run(gateway):
    gateway.policy.set_feature("usage_limits", False)

    replies = [gateway.chat(f"Is the build green? {i}") for i in range(10)]

    assert not any(r.blocked for r in replies)


def test_the_settings_api_shows_which_switch_is_off(gateway):
    gateway.policy.set_feature("data_protection", False)

    controls = {c["id"]: c for c in gateway.client.get("/v1/settings/controls").json()}

    assert controls["sensitive_data"]["feature_on"] is False
    assert controls["keyword_blocklist"]["feature_on"] is True


# ---- 2. rules, Agents and models --------------------------------------------------------------


def test_a_new_forbidden_phrase_applies_to_the_next_request(gateway):
    assert not gateway.chat("Any news on Project Eagle?").blocked

    gateway.policy.set_params("keyword_blocklist", keywords=["project falcon", "project eagle"])

    assert gateway.chat("Any news on Project Eagle?").blocked


def test_a_new_agent_can_work_as_soon_as_it_is_in_the_policy(gateway):
    assert gateway.chat("Hello", key="new-agent-key").blocked, "unknown key: blocked"

    data = gateway.policy.load()
    data["agents"].append({"key": "new-agent-key", "id": "report-writer",
                           "owner": "carol@bank.example", "team": "research"})
    gateway.policy.save(data)

    assert not gateway.chat("Hello", key="new-agent-key").blocked


def test_removing_an_agent_locks_it_out_on_the_next_request(gateway):
    assert not gateway.chat("Hello", key="trading-agent-key").blocked

    data = gateway.policy.load()
    data["agents"] = [a for a in data["agents"] if a["key"] != "trading-agent-key"]
    gateway.policy.save(data)

    reply = gateway.chat("Hello", key="trading-agent-key")
    assert reply.blocked
    assert "unknown agent" in reply.reason


def test_a_model_taken_off_the_allowed_list_is_refused_next_time(gateway):
    assert not gateway.chat("Hello").blocked  # the mock model

    data = gateway.policy.load()
    data["allowed_models"] = [m for m in data["allowed_models"] if m != "mock"]
    gateway.policy.save(data)

    reply = gateway.chat("Hello")
    assert reply.blocked
    assert "not in allowed_models" in reply.reason


def test_a_mode_change_applies_to_the_next_request(gateway):
    assert gateway.chat("Any update on Project Falcon?").blocked

    gateway.policy.set_mode("keyword_blocklist", "monitor")

    assert not gateway.chat("Any update on Project Falcon?").blocked


# ---- 3. proof of what decided -----------------------------------------------------------------


def test_every_edit_gives_a_new_policy_version_on_the_decisions(gateway):
    before = gateway.chat("Hello").firewall["policy_version"]

    gateway.policy.set_mode("keyword_blocklist", "monitor")
    after = gateway.chat("Hello").firewall["policy_version"]

    assert before != after
    assert gateway.policy_view()["version"] == after


def test_the_policy_cannot_be_rewritten_over_the_api(gateway):
    """Only the file changes the Policy: no hidden second way for anyone to switch Controls."""
    response = gateway.client.put("/v1/settings/policy", content="controls: {}")

    assert response.status_code in (404, 405)
    assert gateway.chat("Any update on Project Falcon?").blocked
