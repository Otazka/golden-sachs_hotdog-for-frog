.PHONY: test unit test-suites acceptance lint up down logs

# Both layers: the code tests (tests/) and the stakeholder acceptance tests (test_suites/).
test:
	uv run pytest -q --no-header -rN

# Only the code tests: the quick loop while writing a Control.
unit:
	uv run pytest tests -q

test-suites: acceptance

# The judge-facing suite: one line per stakeholder use case, report in reports/.
acceptance:
	uv run pytest test_suites -q --no-header -rN

lint:
	uv run ruff check .

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f
