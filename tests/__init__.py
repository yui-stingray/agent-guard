# Where: tests/__init__.py
# What: package marker so tests.cli.* absolute imports resolve under a clean install.
# Why: tests/cli/ helpers are imported as `from tests.cli.helpers import ...`; without
#      this marker `tests` is a namespace package and CI (pip install -e, no PYTHONPATH)
#      fails collection with ModuleNotFoundError: No module named 'tests'.
