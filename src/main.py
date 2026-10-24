"""Demo: replay PRIMER.md's 50x-$9,999 scenario — this time with memory.

Run from the repo root:  python3 -m src.main
"""

from . import ledger
from .authorize import authorize_transfer


def main():
    conn = ledger.connect("ledger.db")
    session_id = "sess-001"

    for i in range(1, 6):
        decision = authorize_transfer(conn, session_id, "acct-1234", 9999)
        print(f"transfer #{i}: {decision}")

    conn.close()


if __name__ == "__main__":
    main()
