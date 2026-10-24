"""Demo: replay PRIMER.md's 50x-$9,999 scenario — this time with memory.

Run from the repo root:  python3 -m guard.main
"""

from . import ledger
from .authorize import authorize_transfer


def main():
    # In memory, so every run starts from an empty ledger and prints the
    # same thing. A ledger.db on disk kept the last run's DENY, which
    # tripped the breaker and made every later run print five DENYs.
    conn = ledger.connect(":memory:")
    session_id = "sess-001"

    for i in range(1, 6):
        decision = authorize_transfer(conn, session_id, "acct-1234", 999_900)  # $9,999
        print(f"transfer #{i}: {decision}")

    conn.close()


if __name__ == "__main__":
    main()
