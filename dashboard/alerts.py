"""Phone alerts: one line on what was stopped and why, one tap to open the
dashboard.

Follows the guard's GET /events and pushes every newly stopped or held
payment to ntfy (https://ntfy.sh). The phone runs the ntfy app, subscribed
to the same topic.

    NTFY_TOPIC=<topic> python3 dashboard/alerts.py --open http://<laptop-ip>:8000/
    python3 dashboard/alerts.py --dry-run      # print alerts, send nothing

A push that fails is kept and retried, backing off up to a minute. More
than three alerts at once go out as one summary, so a flood of blocked
attempts can't flood the phone. On startup it alerts only on payments
still waiting for an OK; --replay alerts on everything already there.

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
MAX_SEPARATE = 3  # more alerts than this at once go out as one summary


def text(value, fallback):
    return value if isinstance(value, str) and value else fallback


def money(cents):
    if type(cents) is not int:
        return "An unknown amount"
    if cents < 0:
        return "-" + money(-cents)
    dollars, rest = divmod(cents, 100)
    return f"${dollars:,}" + (f".{rest:02d}" if rest else "")


def alert_for(row):
    """The phone alert for one event row, or None if it needs none. Copes
    with odd fields: tool and payee start out as whatever the agent sent."""
    status = row.get("status")
    if status not in ("released", "held"):
        return None
    tool, rule = row.get("tool"), row.get("rule")
    label = TOOLS.get(tool) if isinstance(tool, str) else None
    label = label or text(tool, "payment").replace("_", " ")
    why = (RULES.get(rule) if isinstance(rule, str) else None) or text(
        row.get("explanation"), "Waiting for your OK" if status == "held" else "Stopped by a spending rule")
    what = f"{money(row.get('amount_cents'))} {label} to {text(row.get('payee'), 'an unknown payee')}"
    message = f"{why}. {what}."
    if status == "held":
        return {"title": "Needs your OK", "message": message, "priority": 4}
    return {"title": "Stopped", "message": message, "priority": 3}


def summary(alerts):
    """One alert standing in for several."""
    held = sum(alert["title"] == "Needs your OK" for alert in alerts)
    stopped = len(alerts) - held
    parts = [f"{n} {'payment' if n == 1 else 'payments'} {what}"
             for n, what in ((held, "waiting for your OK"), (stopped, "stopped")) if n]
    return {
        "title": "Needs your OK" if held else "Stopped",
        "message": " and ".join(parts) + ". Open the dashboard to see them.",
        "priority": max(alert["priority"] for alert in alerts),
    }


def send(alert, topic, click, server="https://ntfy.sh"):
    # JSON publishing keeps non-ASCII payees out of HTTP headers.
    body = json.dumps({"topic": topic, "click": click, **alert}).encode()
    request = urllib.request.Request(server, data=body, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(request, timeout=10).close()


class Watcher:
    """Turns new stopped or held rows into alerts. step() does one poll and
    one round of sending; run() repeats it forever.

    deliver(alert) returns True once the alert is out. Anything it couldn't
    send stays queued and is retried with backoff."""

    def __init__(self, api, deliver, replay=False):
        self.api = api
        self.deliver = deliver
        self.since = 0 if replay else None  # None until the first read
        self.unsent = []
        self.failures = 0
        self.retry_at = 0.0

    def step(self, now):
        rows = self._read()
        if rows is not None:
            first = self.since is None
            self.since = self.since or 0
            for row in rows:
                try:
                    event_id = row["event_id"]
                    if type(event_id) is not int:
                        raise ValueError(f"event_id {event_id!r} isn't an integer")
                    self.since = max(self.since, event_id)
                    alert = alert_for(row)
                except Exception as err:  # one odd row mustn't stop the alerts
                    print(f"skipping a row I can't read ({err!r}): {row!r:.200}", flush=True)
                    continue
                # On the first read, only a payment still waiting needs the
                # family now; the rest happened before we were watching.
                if alert and (not first or row.get("status") == "held"):
                    self.unsent.append(alert)
        self._send(now)

    def run(self, every=1.0):
        while True:
            self.step(time.monotonic())
            time.sleep(every)

    def _read(self):
        url = f"{self.api}/events?since={self.since or 0}"
        try:
            with urllib.request.urlopen(url, timeout=5) as res:
                rows = json.load(res)
        except (OSError, ValueError) as err:
            print(f"can't read {self.api}/events ({err}), retrying", flush=True)
            return None
        if not isinstance(rows, list):
            print(f"{self.api}/events didn't return a list, retrying", flush=True)
            return None
        return rows

    def _send(self, now):
        if not self.unsent or now < self.retry_at:
            return
        if len(self.unsent) > MAX_SEPARATE:
            self.unsent = [summary(self.unsent)]
        while self.unsent:
            if not self.deliver(self.unsent[0]):
                self.failures += 1
                self.retry_at = now + min(60, 2 ** self.failures)
                return
            self.unsent.pop(0)
            self.failures = 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Push stopped and held payments to a phone via ntfy")
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="the guard's API")
    parser.add_argument("--open", default="http://127.0.0.1:8000/", help="dashboard URL a tap opens")
    parser.add_argument("--server", default="https://ntfy.sh")
    parser.add_argument("--dry-run", action="store_true", help="print alerts instead of sending them")
    parser.add_argument("--replay", action="store_true", help="also alert on rows from before startup")
    args = parser.parse_args(argv)
    topic = os.environ.get("NTFY_TOPIC")
    if not topic and not args.dry_run:
        parser.error("set NTFY_TOPIC, or use --dry-run")
    if "token=" in args.open:
        # Alerts go through ntfy.sh, where anyone who knows the topic can
        # read them, so a link that can approve payments must never ride along.
        parser.error("--open must not carry the dashboard token; use the read-only link")

    def deliver(alert):
        if args.dry_run:
            print(f"[{alert['title']}] {alert['message']}", flush=True)
            return True
        try:
            send(alert, topic, args.open, args.server)
        except OSError as err:
            print(f"couldn't send, will retry ({err}): {alert['message']}", flush=True)
            return False
        print(f"sent [{alert['title']}] {alert['message']}", flush=True)
        return True

    try:
        Watcher(args.api, deliver, replay=args.replay).run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
