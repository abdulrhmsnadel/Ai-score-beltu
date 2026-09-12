.PHONY: test lint check

test:
	python -m pytest -q

lint:
	ruff check src tests

check: test lint
