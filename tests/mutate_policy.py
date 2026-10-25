"""Do the tests have teeth? Delete each forbid in family.cedar, one at a
time, in a scratch copy of the repo, and check the test suite fails.

    .venv/bin/python tests/mutate_policy.py [rule,rule,...]

A rule whose removal no test notices is SURVIVED: it needs a test. The
structural check that every rule has an outcome is left out, so a rule only
counts as caught when a test of its behavior fails.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STRUCTURAL = "tests/test_family.py::test_every_rule_in_the_policy_has_an_outcome"


def main(only=None):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "mutant"
        shutil.copytree(REPO, work, ignore=shutil.ignore_patterns(
            ".venv", ".git", "node_modules", "dist", "*.db*", "__pycache__"))
        policy = work / "guard/policies/family.cedar"
        original = policy.read_text()
        rules = [r for r in re.findall(r'@id\("([a-z_]+)"\)\nforbid', original)
                 if not only or r in only]
        env = {**os.environ, "PYTHONPATH": str(work), "ACCRUE_REQUIRE_CEDAR": "1"}
        caught = []
        for rule in rules:
            mutant = re.sub(r'@id\("%s"\)\nforbid.*?;\n' % rule, "", original, count=1, flags=re.S)
            assert mutant != original, rule
            policy.write_text(mutant)
            run = subprocess.run([sys.executable, "-m", "pytest", "tests", "-x", "-q",
                                  "-p", "no:cacheprovider", "--deselect", STRUCTURAL],
                                 cwd=work, env=env, capture_output=True, text=True)
            failed = [line[7:] for line in run.stdout.splitlines() if line.startswith("FAILED")]
            if run.returncode != 0:
                caught.append(rule)
            print(f"{rule:26} {'caught' if run.returncode else 'SURVIVED':9} "
                  f"{failed[0][:80] if failed else ''}", flush=True)
        print(f"\n{len(caught)} of {len(rules)} rules are caught when removed")
        return len(caught) == len(rules)


if __name__ == "__main__":
    sys.exit(0 if main(sys.argv[1].split(",") if len(sys.argv) > 1 else None) else 1)
