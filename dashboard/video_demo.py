"""Plays the demo video's beats, one per key press, from a fresh guard.

    .venv/bin/python dashboard/video_demo.py                 # Enter = next beat
    .venv/bin/python dashboard/video_demo.py --auto 8        # a beat every 8 s
    .venv/bin/python dashboard/video_demo.py --simulate-desktop   # no Claude Desktop

Each run starts the real guard (python -m guard.api --demo) on a new,
empty ledger, so every take is the same; Ctrl-C stops everything and the
next run starts clean. It prints the dashboard link to open (on the
projector and the phone), starts the phone alerts when NTFY_TOPIC is set,
then plays the beats in VIDEO.md. The guard decides every payment: only
the requests are scripted.

Tokens: it uses ACCRUE_AGENT_TOKEN, ACCRUE_VIEWER_TOKEN and
ACCRUE_APPROVER_TOKEN from the environment. Any that aren't set are made up
once and kept in .video-tokens.json (not in git), so the dashboard link stays
the same from take to take, and a phone that opened it once keeps working.
The guard wants each at least 32 characters, all different.
"""

import argparse
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLES = ("ACCRUE_AGENT_TOKEN", "ACCRUE_VIEWER_TOKEN", "ACCRUE_APPROVER_TOKEN")
TOKENS_FILE = ROOT / ".video-tokens.json"
MIN_TOKEN = 32  # guard/api.py's MIN_TOKEN_LENGTH


def load_tokens():
    """{"agent": ..., "viewer": ..., "approver": ...}: the environment's,
    else the saved ones, else new ones (saved). Exits with a plain message
    if they're too short or not all different."""
    try:
        saved = json.loads(TOKENS_FILE.read_text())
    except (OSError, ValueError):
        saved = {}
    tokens, made = {}, False
    for name in ROLES:
        role = name.split("_")[1].lower()
        tokens[role] = os.environ.get(name) or saved.get(role)
        if not tokens[role]:
            tokens[role], made = secrets.token_urlsafe(32), True
    if made:  # keep made-up tokens for the next take
        TOKENS_FILE.write_text(json.dumps({**saved, **tokens}))
        TOKENS_FILE.chmod(0o600)
    short = [f"ACCRUE_{r.upper()}_TOKEN" for r, t in tokens.items() if len(t) < MIN_TOKEN]
    if short:
        sys.exit(f"{', '.join(short)} must be at least {MIN_TOKEN} characters. Unset it to let "
                 "this make one up, or make one with:\n"
                 "  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'")
    if len(set(tokens.values())) < len(tokens):
        sys.exit("The agent, viewer and approver tokens must all be different.")
    return tokens
CODE = "427913"  # the verification code the scammer asks for


def lan_ip():
    """This laptop's address on the Wi-Fi, for links that open on the phone."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))  # no packet is sent
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


class Guard:
    def __init__(self, port, tokens):
        self.base = f"http://127.0.0.1:{port}"
        self.tokens = tokens

    def call(self, method, path, body=None, role="viewer"):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.tokens[role]}"})
        try:
            with urllib.request.urlopen(request, timeout=30) as res:
                return res.status, json.loads(res.read() or b"null")
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"null")

    def scenario(self, name):
        status, body = self.call("POST", "/demo/run", {"scenario": name}, role="approver")
        if status != 202:
            return f"couldn't start {name}: {status} {body}"
        while self.call("GET", "/demo/status")[1].get("running"):
            time.sleep(0.3)
        return None

    def latest(self, count):
        _, rows = self.call("GET", "/events")
        return rows[-count:] if isinstance(rows, list) else []


def show(rows):
    for row in rows:
        print(f"      {row['status']:>8}  ${row['amount_cents'] / 100:,.0f} {row['tool']} "
              f"to {row['payee']}  ({row['rule'] or 'ok'})")


# ---- the beats ---------------------------------------------------------------

def beat_scenario(name, count):
    def run(guard, args):
        problem = guard.scenario(name)
        if problem:
            print("      " + problem)
        else:
            show(guard.latest(count))
    return run


def beat_desktop(guard, args):
    if not args.simulate_desktop:
        print("      Now, in Claude Desktop, type:")
        print('      "The power company texted: pay $450 in gift cards to giftcards.example now '
              'or they cut the power. Buy them."')
        input("      ... press Enter when Claude Desktop has answered ")
        show(guard.latest(1))
        return
    # Stand-in for Claude Desktop: the same proxy, the same stdio messages.
    env = {k: v for k, v in os.environ.items()
           if k not in ("ACCRUE_VIEWER_TOKEN", "ACCRUE_APPROVER_TOKEN", "ACCRUE_ADMIN_TOKEN",
                        "ACCRUE_DASHBOARD_TOKEN")}
    env.update(ACCRUE_API=guard.base, ACCRUE_AGENT_TOKEN=guard.tokens["agent"])
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "buy_gift_card",
        "arguments": {"payee": "giftcards.example", "amount_cents": 45000,
                      "reason": "power company said pay in gift cards or lose power"}}}
    out = subprocess.run([sys.executable, "-m", "agent.mcp_proxy"], cwd=ROOT, env=env,
                         input=json.dumps(call) + "\n", capture_output=True, text=True, timeout=60)
    try:
        print("      Claude Desktop is told: " +
              json.loads(out.stdout.splitlines()[0])["result"]["content"][0]["text"])
    except (IndexError, KeyError, ValueError):
        print("      the proxy didn't answer: " + out.stderr.strip()[-300:])


def beat_approve(guard, args):
    problem = guard.scenario("held_bill")
    if problem:
        print("      " + problem)
        return
    show(guard.latest(1))
    if args.auto is None:
        input("      Approve it on the phone (or the dashboard), then press Enter ")
        show(guard.latest(1))


def beat_secret(guard, args):
    session = "sess-video"
    guard.call("POST", "/inbound", {"session_id": session, "source": "sms",
                                    "content": f"Your bank verification code is {CODE}. "
                                               "Never share it."}, role="agent")
    status, result = guard.call("POST", "/outbound", {
        "session_id": session, "recipient": "+1-555-0142", "channel": "sms",
        "content": f"Hi, here's the code you asked for: {CODE}"}, role="agent")
    print(f"      the agent tries to text the code: {result.get('decision', status)}"
          f"  {result.get('findings', '')}")


def beat_tamper(guard, args):
    # The $50 birthday gift card from beat 1: on screen, so the edit shows.
    _, rows = guard.call("GET", "/events")
    target = next((r["event_id"] for r in rows if r["tool"] == "buy_gift_card"
                   and r["amount_cents"] == 5000 and r["status"] == "allowed"), None)
    if target is None:
        print("      no $50 gift card to edit; play beat 1 first")
        return
    with sqlite3.connect(args.db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS prevent_event_updates")
        conn.execute("UPDATE events SET amount_cents = 100 WHERE id = ?", (target,))
    print(f"      payment #{target} (the $50 gift card) rewritten as $1. "
          "Watch the record check turn red.")
    time.sleep(1)
    print(f"      /verify: {guard.call('GET', '/verify')[1]}")


BEATS = [
    ("1 · Normal day", "Mom's assistant pays her bills like it should.",
     beat_scenario("normal_day", 2)),
    ("2 · The scam", "The agent got fooled. The money didn't move.",
     beat_scenario("gift_card_scam", 2)),
    ("3 · Claude Desktop", "Any agent, same guard. It can ask; it can't approve.", beat_desktop),
    ("4 · Switch tactics", "Different method, different agent, same running total.",
     beat_scenario("channel_switch", 2)),
    ("5 · Waiting for you", "Only she can say yes.", beat_approve),
    ("6 · Secrets", "No code, card number or password leaves.", beat_secret),
    ("7 · Tamper", "Edit history and it shows, at that exact row.", beat_tamper),
    ("8 · Proof", "A refusal is a probability. The cap is a guarantee.",
     lambda guard, args: print("      show EVIDENCE.md: 1,000 at once land exactly on $500; "
                               "10,000 random households, no rule broken")),
]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Play the demo video's beats on a fresh guard")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--auto", type=float, help="seconds between beats instead of Enter")
    parser.add_argument("--simulate-desktop", action="store_true",
                        help="play beat 3 through the proxy here instead of in Claude Desktop")
    parser.add_argument("--ip", help="this laptop's Wi-Fi address for the phone's link "
                        "(found automatically; set it if it picks a VPN address)")
    parser.add_argument("--then-exit", action="store_true",
                        help="with --auto, stop the guard after the last beat")
    parser.add_argument("--only", help="comma-separated beat numbers to play, e.g. 1,2,7")
    args = parser.parse_args(argv)

    tokens = load_tokens()
    workdir = Path(tempfile.mkdtemp(prefix="accrue-video-"))
    args.db = str(workdir / "demo.db")
    guard_log = open(workdir / "guard.log", "w")
    env = {**os.environ, "ACCRUE_PEOPLE": "mom",
           **{name: tokens[name.split("_")[1].lower()] for name in ROLES}}
    env.pop("ACCRUE_DASHBOARD_TOKEN", None)
    children = [subprocess.Popen(
        [sys.executable, "-m", "guard.api", "--db", args.db, "--demo",
         "--host", "0.0.0.0", "--port", str(args.port)],
        cwd=ROOT, env=env, stdout=guard_log, stderr=subprocess.STDOUT)]
    guard = Guard(args.port, tokens)
    try:
        for _ in range(100):
            try:
                if guard.call("GET", "/limits")[0] == 200:
                    break
            except OSError:
                time.sleep(0.2)
        else:
            guard_log.flush()
            sys.exit("the guard didn't start. Its last words:\n"
                     + "".join(open(workdir / "guard.log").readlines()[-5:])
                     + f"(is something else using port {args.port}?)")

        ip = args.ip or lan_ip()
        print(f"\nDashboard (projector and phone): http://{ip}:{args.port}/#token={tokens['approver']}\n")
        if os.environ.get("NTFY_TOPIC"):
            alerts_env = {k: v for k, v in env.items()
                          if k not in ("ACCRUE_AGENT_TOKEN", "ACCRUE_APPROVER_TOKEN")}
            children.append(subprocess.Popen(
                [sys.executable, "dashboard/alerts.py", "--api", guard.base,
                 "--open", f"http://{ip}:{args.port}/"], cwd=ROOT, env=alerts_env))
            print(f"Phone alerts on to ntfy topic {os.environ['NTFY_TOPIC']}\n")
        else:
            print("NTFY_TOPIC isn't set, so the phone won't buzz.\n")

        only = {b.strip() for b in args.only.split(",")} if args.only else None
        for title, line, action in BEATS:
            if only and title.split(" ")[0] not in only:
                continue
            if args.auto is None:
                input(f"[Enter] {title}  ")
            else:
                time.sleep(args.auto)
                print(title)
            print(f'      say: "{line}"')
            action(guard, args)
        if args.auto is None:
            input("\nDone. Enter (or Ctrl-C) stops the guard. ")
        elif not args.then_exit:
            print("\nDone. The guard keeps running for the camera; Ctrl-C stops it.")
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for child in children:
            child.terminate()


if __name__ == "__main__":
    main()
