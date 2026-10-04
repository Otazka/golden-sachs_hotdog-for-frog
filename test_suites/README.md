# Acceptance suites

The stakeholder acceptance tests: each of the 13 use cases the stakeholders and the brief ask for,
proven end to end through the real `policy.yaml`. `tests/` proves each part works as built; this
folder proves the product does what was asked. Both layers run in `make test` and both must be
green.
For the jury's one-page guide see [`TEST_SUITCASE.md`](TEST_SUITCASE.md).

```bash
make acceptance                                              # all use cases, ~30 s, offline
uv run pytest test_suites/functional/test_uc04_prompt_injection.py   # one use case
uv run pytest test_suites -k "slider or loop"                # by name
```

The run ends with a table per use case and writes `reports/acceptance-report.md` and
`reports/latency.json` (both generated, not committed).

## Layout

```text
test_suites/
  TEST_SUITCASE.md          one page for the jury
  catalog.py       the 13 use cases (id, title, requirement, stakeholders)
  report.py        the run summary and reports/acceptance-report.md
  conftest.py      fixtures (`gateway`, `make_gateway`) and the pytest hooks of the summary
  harness.py       a firewall on a temp copy of policy.yaml, clients, Policy edits, fake clock
  data/            test cases as YAML: personal_data, injections, exploits
  functional/      one file per use case: test_ucNN_*.py
  manual/          step-by-step manual checks through the chat
```

## How a test works

```python
def test_switching_a_category_off_and_on_changes_the_next_answer(gateway):
    assert CARD not in gateway.chat(text).answer        # through the proxy, mock model
    gateway.policy.set_category("card", enabled=False)  # edit policy.yaml, like an operator
    assert CARD in gateway.chat(text).answer            # the next request follows it
```

- `gateway` is a firewall on a fresh copy of `policy.yaml` with its own SQLite file.
- `gateway.policy` edits that file: `set_feature`, `set_mode`, `set_params`, `set_category`,
  `set_store_content`, `write_text` (anything, valid or not), `delete`, `restore`.
- `gateway.chat(...)` goes through the OpenAI-compatible proxy; the `mock` model echoes the last
  user message. `gateway.check(stage, body)`, `tool_call(...)` and `tool_result(...)` use the
  check API. `events`, `export`, `metrics`, `budgets`, `breakers`, `policy_view` read the
  settings API.
- `gateway.clock.advance(seconds)` moves the Controls' time (windows, cooldowns, budgets).
- On `block` assert the Decision and its reason (the caller enforces it); on `redact` assert the
  returned content no longer holds the value.

## Adding a test

1. Put it in the use case's file, or create `functional/test_ucNN_<name>.py` with
   `pytestmark = [pytest.mark.uc("UC-NN"), pytest.mark.req("R…")]`. A new use case also needs a
   line in `catalog.py`.
2. New cases for an existing test are one line in `data/*.yaml`.
3. Only tests that pass against the product are kept here. Never weaken an assertion to make a
   test pass: if the product misses a case, raise it with the team instead.
4. Check the test can fail: switch the Control off in `policy.yaml`, run it, put it back.
