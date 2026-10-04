# Acceptance tests: a guide for the jury

```bash
make acceptance          # or: uv run pytest test_suites
```

About 30 seconds, offline, no API key. `make test` runs these together with the code tests. The run ends with one line per stakeholder use case and
writes the same table to `reports/acceptance-report.md`.

```text
  UC-02  Redact personal data in answers          R2.1           35   ✔ PASS
  UC-07  Block unsafe code and model files        R4             36   ✔ PASS
  13/13 use cases proven   335 passed   0 failed   28.7 s
  Positive + negative case per Control (R6): 10/10 Controls
  Firewall overhead per request: p50 10.3 ms · p95 10.7 ms
```

- **✔ PASS**: every test of the use case passes.

## Positive and negative cases (R6)

Every Control that runs in `policy.yaml` has at least one **good case** (an ordinary request it
lets through) and one **bad case** (a request it blocks or cleans), both through the real
firewall: `functional/test_uc14_good_and_bad_per_control.py`, shown as the `R6` line of the run
and as a table in the report. A Control added to the Policy without such a pair fails the suite.

| Control | Good case (allowed) | Bad case (blocked or redacted) |
|---|---|---|
| `keyword_blocklist` | a question about the quarterly report | "Any update on Project Falcon?" |
| `sensitive_data` | a date, a time and a ticket number | an email address in the answer |
| `output_sanitizer` | a link to `wiki.bank.internal` | an image that sends data to an outside domain |
| `attack_signatures` | `torch.load(..., weights_only=True)` in a tool call | `os.system('cat /etc/passwd')` in a tool call |
| `injection_heuristics` | "What is prompt injection?" | the Polish "ignore all previous instructions…" |
| `injection_classifier` | a question about the expense rules | a reworded attack the patterns miss |
| `resource_access` | read `/demo/README.txt` | read `/home/me/.ssh/id_rsa` |
| `loop_detector` | the same question up to the Policy's limit | once more inside a minute |
| `request_limits` | a 150-token prompt | a 9,000-token prompt |
| `token_budget` | the first request of the day | the next one, once the day's budget is used |

The use-case files below go much further: 335 passing tests, each use case with both sides.

## How the tests work

- Each test starts its own firewall on a fresh copy of the real `policy.yaml`, with its own database. Nothing is mocked inside the firewall.
- The model is the built-in `mock`, which repeats the question. Whatever a test sends comes back as the "model answer" the firewall must inspect.
- Tests change behaviour the way you will during the demo: by **editing the Policy file** of the running firewall. The next request follows it, no restart.
- Time (windows, cooldowns, daily budgets) runs on a test clock, so nothing waits.
- Each test proves a pair: the attack is stopped **and** ordinary work passes.
- **The tests are checked against the product:** switching a Control off in `policy.yaml` makes its tests fail, and the R6 line shows `9/10 Controls · missing: <name>`.

## What each use case proves

| Use case | Tests | What is proven |
|---|---|---|
| UC-01 Clean requests pass | 18 | Questions, code, tables, Polish and German text, internal links come back exactly as written, with no Finding, for every Agent and every Stage. |
| UC-02 Personal data redacted | 35 | Email (also `[at]`/`[dot]`), phone, card (spaces, dashes, full-width digits, Luhn-checked), IBAN (checksum) are replaced in answers and in Resource results; look-alikes (non-Luhn numbers, dates, versions) are untouched; the reason never repeats the value. |
| UC-03 The mentor's slider | 5 | The same request, four Policy edits: nothing filtered → personal data → plus card and account → plus secrets. Each step is a new Policy version, no restart. |
| UC-04 Prompt injection | 33 | Three layers (signatures, patterns, model) back each other up. English, Polish, German, leetspeak, invisible characters, base64, hex, URL, rot13 are blocked before the model; injection hidden in a document is cut out and the rest kept; the semantic model catches reworded attacks; fail-open and fail-closed when the model is down; ordinary questions about injection pass. |
| UC-05 Default deny, writes blocked | 60 | Reads only where granted, writes need more; paths outside every folder are denied; `..`, Windows paths, `~`, URLs, empty or missing paths cannot get around it; folders granted or removed in the Policy apply on the next call. |
| UC-06 Runaway loop and cost spike | 50 | A repeating Agent is stopped before the model; with the circuit breaker on (off in the demo Policy) it stays stopped until cooldown or reset; daily, per-user and per-run token budgets; oversized prompts blocked, endless replies cut; one huge word cannot stall the firewall. |
| UC-07 Unsafe code and model files | 36 | Known historical attacks from an external signature feed: pickle and unsafe `torch.load`, YAML python tags, `os.system`, shell chaining, download-and-run, Log4Shell, `trust_remote_code`, pickled model downloads, runtime MCP installs, hidden BCC, `DROP TABLE`, `rm -rf`; each Finding cites its OWASP ASI code; safe look-alikes pass; editing the feed applies without restart; a missing feed fails closed. |
| UC-08 Policy changes live | 12 | Each master switch off and on, a new forbidden phrase, a new or removed Agent, a model taken off the list: all apply to the next request; the Policy cannot be rewritten over the API. |
| UC-09 Broken config | 12 | Invalid YAML, wrong types, unknown parameters, duplicate keys, a deleted file: the last good Policy keeps protecting and the error is shown. An empty file fails closed; a misspelled Control name shows a warning. |
| UC-10 Audit trail | 14 | One event per Check, allowed ones too, with who, what, which rule and which Policy version; JSONL and CSV export; no raw personal data in `redacted` or `none` mode; recording can be switched off. |
| UC-12 Every denial explained | 28 | Nine ways to say no (phrase, injection, known exploit, secret, outbound link, size, loop, budget, folder): each names the Control, gives a reason and structured Findings, and never repeats what it protects; usage denials name the owner to call. |
| UC-13 Latency | 4 | 60 requests with every Control on vs. all off: about 10 ms overhead per request; per-Control times in the report. |
| UC-14 One command, R6 | 28 | A good and a bad case for each of the 10 Controls; every use case has tests; the command exists; test data parses; no key needed. |

## Try it yourself

Change the Policy and run again: set `data_protection: false` under `features:` in `policy.yaml`
and UC-02 turns red; put it back and it is green. To test by hand in the chat, see
[`manual/list_read_tools.md`](manual/list_read_tools.md).
