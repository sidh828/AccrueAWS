"""Which tests need the real cedar CLI.

Most of the guard's tests shell out to `cedar` (see guard/authorize.py), so
someone without Rust can't run them. They're skipped when the CLI isn't
installed, so everyone can still run the rest. CI sets ACCRUE_REQUIRE_CEDAR=1,
which turns a missing CLI into an error instead: otherwise a broken install
would skip the tests that matter most and the run would still pass.
"""

import os
import shutil

import pytest

# Test files, or single tests, that run the cedar CLI. A test anywhere else
# can be marked with @pytest.mark.cedar instead.
NEEDS_CEDAR = (
    "tests/test_authorize.py",
    "tests/test_ledger.py::test_concurrent_authorize_calls_serialize",
)


def pytest_configure(config):
    config.addinivalue_line("markers", "cedar: runs the cedar CLI; skipped when it isn't installed")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.nodeid.startswith(NEEDS_CEDAR):
            item.add_marker(pytest.mark.cedar)
    if shutil.which(os.environ.get("ACCRUE_CEDAR_BIN", "cedar")):
        return
    if os.environ.get("ACCRUE_REQUIRE_CEDAR") == "1":
        raise pytest.UsageError("ACCRUE_REQUIRE_CEDAR=1, but the cedar CLI isn't on PATH")
    skip = pytest.mark.skip(reason="needs the cedar CLI: cargo install cedar-policy-cli --version 4.12.0")
    for item in items:
        if item.get_closest_marker("cedar"):
            item.add_marker(skip)
