"""UC-09: a broken Policy file never breaks the firewall (R1).

A judge will save a typo. The firewall keeps the last good Policy, keeps protecting, keeps
answering, and shows what is wrong (`last_error` in the settings API and the console). Fixing
the file brings the new version in without a restart. Two cases are deliberately different and
documented here: an empty file is a valid Policy with no Agents, so everything is blocked (fail
closed); a misspelled Control name is skipped with a visible warning.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.uc("UC-09"), pytest.mark.req("R1")]

EMAIL = "ivan.petrov@bank.com"

BROKEN = {
    "invalid-yaml": "controls: [this is: not valid",
    "not-a-mapping": "- just\n- a\n- list\n",
    "tabs-and-garbage": "agents:\n\t- key: x\n\t  id: [",
}


def still_protecting(gateway) -> None:
    """The last good Policy is still in force: PII is cleaned, forbidden phrases blocked."""
    assert EMAIL not in gateway.chat(f"Mail {EMAIL}").answer
    assert gateway.chat("Any update on Project Falcon?").blocked


@pytest.mark.parametrize("text", BROKEN.values(), ids=BROKEN.keys())
def test_an_unreadable_file_keeps_the_last_good_policy(gateway, text):
    good = gateway.policy_view()["version"]

    gateway.policy.write_text(text)

    still_protecting(gateway)
    view = gateway.policy_view()
    assert view["last_error"], "the problem is shown to the operator"
    assert view["version"] == good


@pytest.mark.parametrize(
    ("edit", "words"),
    [
        (lambda d: d["controls"]["keyword_blocklist"].update(mode="blokc"), "mode"),
        (lambda d: d["controls"]["sensitive_data"]["params"].update(categoriez=[]),
         "categoriez"),
        (lambda d: d["controls"]["loop_detector"]["params"].update(max_similar=-1),
         "max_similar"),
        (lambda d: d["agents"].append(dict(d["agents"][0])), "duplicate"),
    ],
    ids=["misspelled-mode", "unknown-parameter", "out-of-range-value", "duplicate-agent-key"],
)
def test_an_invalid_value_is_refused_and_named(gateway, edit, words):
    data = gateway.policy.load()
    edit(data)
    gateway.policy.save(data)

    still_protecting(gateway)
    assert words in gateway.policy_view()["last_error"]


def test_fixing_the_file_brings_the_new_policy_in_and_clears_the_error(gateway):
    gateway.policy.write_text("controls: [broken")
    assert gateway.policy_view()["last_error"]

    gateway.policy.restore()
    gateway.policy.set_mode("keyword_blocklist", "monitor")

    assert gateway.policy_view()["last_error"] is None
    assert not gateway.chat("Any update on Project Falcon?").blocked


def test_a_deleted_file_keeps_the_last_good_policy(gateway):
    gateway.policy.delete()

    still_protecting(gateway)
    assert "cannot read" in gateway.policy_view()["last_error"]

    gateway.policy.restore()
    assert gateway.policy_view()["last_error"] is None


def test_several_bad_saves_in_a_row_never_take_protection_down(gateway):
    for text in BROKEN.values():
        gateway.policy.write_text(text)
        still_protecting(gateway)


def test_an_empty_file_fails_closed(gateway):
    """An empty file is a valid Policy that names no Agent: every request is refused."""
    gateway.policy.write_text("")

    reply = gateway.chat("Hello")

    assert reply.blocked
    assert "unknown agent" in reply.reason


def test_a_misspelled_control_name_is_skipped_with_a_visible_warning(gateway):
    data = gateway.policy.load()
    data["controls"]["keyword_blocklst"] = data["controls"].pop("keyword_blocklist")
    gateway.policy.save(data)

    warnings = gateway.policy_view()["warnings"]

    assert any("keyword_blocklst" in w for w in warnings), "the console shows the typo"
    assert not gateway.chat("Any update on Project Falcon?").blocked, "that Control is off"
