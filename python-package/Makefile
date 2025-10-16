# Makefile for ferret-scan Python package

.PHONY: help test test-verbose clean install-dev setup-env

help:
	@echo "Available targets:"
	@echo "  setup-env     - Create virtual environment and install dependencies"
	@echo "  test          - Run all tests"
	@echo "  test-verbose  - Run tests with verbose output"
	@echo "  clean         - Clean up temporary files and virtual environment"
	@echo "  install-dev   - Install package in development mode"

setup-env:
	python -m venv test_env
	test_env/bin/pip install -r requirements.txt
	@echo "Virtual environment created. Activate with: source test_env/bin/activate"

test:
	@if [ ! -d "test_env" ]; then \
		echo "Virtual environment not found. Run 'make setup-env' first."; \
		exit 1; \
	fi
	test_env/bin/python tests/run_tests.py

test-verbose:
	@if [ ! -d "test_env" ]; then \
		echo "Virtual environment not found. Run 'make setup-env' first."; \
		exit 1; \
	fi
	test_env/bin/python -m unittest discover -s tests -p 'test_*.py' -v

install-dev:
	@if [ ! -d "test_env" ]; then \
		echo "Virtual environment not found. Run 'make setup-env' first."; \
		exit 1; \
	fi
	test_env/bin/pip install -e .

clean:
	rm -rf test_env/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete