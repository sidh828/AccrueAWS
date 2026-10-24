"""Phone alerts: one line on what was stopped and why, one tap to open the
dashboard.

Follows the guard's GET /events and pushes every newly stopped or held
payment to ntfy (https://ntfy.sh). The phone runs the ntfy app, subscribed
to the same topic.

    NTFY_TOPIC=<topic> python3 dashboard/alerts.py --open http://<laptop-ip>:8001/
    python3 dashboard/alerts.py --dry-run      # print alerts, send nothing

Anyone who knows an ntfy.sh topic name can read it, so use one nobody will
guess and keep it out of git.
"""

import argparse
import json
import os
import time
import urllib.request

# Keep in sync with RULES in app.js. Never "Cedar" or "ledger".
RULES = {
    "gift_card_daily_cap": "Gift card blocked: over today's gift card limit",
    "daily_cap": "Blocked: over today's limit",
    "new_payee_cap": "Blocked: first payment to someone new is over the limit",
    "known_bill_cap": "Blocked: bill is much higher than last month's",
    "breaker": "Paused: too many blocked attempts in a row",
}
TOOLS = {"pay_bill": "bill", "buy_gift_card": "gift card", "send_zelle": "Zelle payment"}


def money(cents):
    dollars, rest = divmod(cents, 100)
    return f"${dollars:,}" + (f".{rest:02d}" if rest else "")


def alert_for(row):
    """The phone alert for one event row, or None if it needs none."""
    if row["status"] not in ("released", "held"):
        return None
    tool = TOOLS.get(row["tool"], row["tool"].replace("_", " "))
    why = RULES.get(row["rule"]) or row.get("explanation") or "Stopped by a spending rule"
    message = f"{why}. {money(row['amount_cents'])} {tool} to {row['payee']}."
    if row["status"] == "held":
        return {"title": "Needs your OK", "message": message, "priority": 4}
    return {"title": "Stopped", "message": message, "priority": 3}


def send(alert, topic, click, server="https://ntfy.sh"):
    # JSON publishing keeps non-ASCII payees out of HTTP headers.
    body = json.dumps({"topic": topic, "click": click, **alert}).encode()
    request = urllib.request.Request(server, data=body, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(request, timeout=10).close()


def watch(api, deliver, every=1.0, replay=False):
    """Poll /events forever and deliver an alert for each new stopped or
    held row. Skips rows from before startup unless replay is set."""
    since = 0 if replay else None
    while True:
        try:
            with urllib.request.urlopen(f"{api}/events?since={since or 0}", timeout=5) as res:
                rows = json.load(res)
        except (OSError, ValueError) as err:
            print(f"can't read {api}/events ({err}), retrying", flush=True)
            rows = None
        if rows is not None and since is None:
            since = max((row["event_id"] for row in rows), default=0)
            rows = []
        for row in rows or []:
            since = max(since, row["event_id"])
            alert = alert_for(row)
            if alert:
                deliver(alert)
        time.sleep(every)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Push stopped and held payments to a phone via ntfy")
    parser.add_argument("--api", default="http://127.0.0.1:8001", help="the guard's API")
    parser.add_argument("--open", default="http://127.0.0.1:8001/", help="dashboard URL a tap opens")
    parser.add_argument("--server", default="https://ntfy.sh")
    parser.add_argument("--dry-run", action="store_true", help="print alerts instead of sending them")
    parser.add_argument("--replay", action="store_true", help="also alert on rows from before startup")
    args = parser.parse_args(argv)
    topic = os.environ.get("NTFY_TOPIC")
    if not topic and not args.dry_run:
        parser.error("set NTFY_TOPIC, or use --dry-run")

    def deliver(alert):
        if args.dry_run:
            print(f"[{alert['title']}] {alert['message']}", flush=True)
            return
        try:
            send(alert, topic, args.open, args.server)
            print(f"sent [{alert['title']}] {alert['message']}", flush=True)
        except OSError as err:
            print(f"couldn't send ({err}): {alert['message']}", flush=True)

    try:
        watch(args.api, deliver, replay=args.replay)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
