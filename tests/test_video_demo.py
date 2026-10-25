"""dashboard/video_demo.py plays every beat of VIDEO.md against a real guard,
and each beat comes out the way the shot list says."""

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.cedar


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_every_beat_plays_as_the_shot_list_says():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ACCRUE_", "NTFY_"))}
    out = subprocess.run(
        [sys.executable, "dashboard/video_demo.py", "--auto", "0", "--simulate-desktop",
         "--port", str(free_port()), "--ip", "127.0.0.1"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=240).stdout
    for expected in [
        "allowed  $120 pay_bill to ohio-power.example",           # 1: normal day
        "allowed  $50 buy_gift_card to giftcards.example",
        "released  $450 buy_gift_card to giftcards.example  (gift_card_daily_cap)",  # 2: scam
        "Claude Desktop is told: Not paid yet: $450.00",          # 3: through the proxy
        "released  $450 send_zelle to zelle:new-contact",         # 4: switch tactics
        "held  $480 pay_bill to ace-plumbing.example",            # 5: waiting for you
        "the agent tries to text the code: block",                # 6: secrets
        "'ok': False, 'first_bad_event_id': 4",                   # 7: tamper names the row
    ]:
        assert expected in out, f"missing {expected!r} in:\n{out}"
