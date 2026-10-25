# Demo video: shot list

About 2:30 (check the length limit on Discord and cut beat 8 or 4 first).
Every beat is played by `dashboard/video_demo.py` on a fresh guard, so all
takes are the same. Each result below is what the guard actually did in a
rehearsal, not what we hope it does.

## Before recording

1. Build the dashboard once: `(cd dashboard/react-frontend && npm ci && npm run build)`.
2. Load the keys (`set -a; . ./.env; set +a`), including `NTFY_TOPIC`, so the
   phone buzzes. The phone has the ntfy app, subscribed to that topic.
3. Start the runner:

   ```bash
   .venv/bin/python dashboard/video_demo.py --ip <laptop Wi-Fi IP>
   ```

   It prints the dashboard link. Open it on the laptop (full screen) and once
   on the phone. Press Enter for each beat. Ctrl-C between takes; the next run
   starts clean.
   - No Claude Desktop? Add `--simulate-desktop`, and beat 3 runs through
     the same proxy in the terminal.
   - Re-shoot one beat with `--only 1,2,3`. The guard plays its scenarios
     in a fixed order, so always include the beats before it.
4. Layout: the dashboard on most of the screen, the runner's terminal small in
   a corner, and the phone in frame (or a phone screen recording cut in).
   Record with OBS or the OS screen recorder.

Never show the token. The dashboard takes it out of the address bar; don't
show the runner's first lines on camera.

## Shot list

| # | Time | On screen | You do | Phone | Say |
|---|---|---|---|---|---|
| 0 | 0:00–0:15 | Scam text on a phone: "Power gets cut in 30 min unless you pay in gift cards" | — | — | "Scammers used to fool Grandma. Now they fool her AI assistant." Add the FBI elder-fraud figure, with its source on screen. |
| 1 | 0:15–0:30 | **Normal day.** $120 power bill and a $50 gift card, both **Allowed**. The bar shows $50: the power bill is a known bill, so it doesn't count. | Enter | Paid someone new ($50 gift card) | "Mom's assistant pays her bills like it should." |
| 2 | 0:30–0:50 | **The scam.** Two $450 gift cards, both **Stopped** (gift card limit). The red attempt panel shows what would have happened. | Enter | Stopped, twice | "The agent got fooled. The money didn't move." |
| 3 | 0:50–1:05 | **Claude Desktop.** The same scam typed into Claude Desktop. It answers: *Not paid yet … waiting for the family's OK.* | Type the prompt the runner shows, then Enter | Needs your OK | "Any agent, same guard. It can ask; it can't approve." |
| 4 | 1:05–1:20 | **Switch tactics.** $450 by Zelle to a new contact: **Stopped**. A sub-agent's $300 gift card: **Waiting**, payments paused. | Enter | Stopped, Needs your OK | "Different method, different agent, same running total." |
| 5 | 1:20–1:35 | **Waiting for you.** A $480 plumber's bill is held: payments are paused. | Enter, then tap **Approve** on the phone (or the dashboard) | Needs your OK, then it's approved | "Only she can say yes." |
| 6 | 1:35–1:50 | **Secrets.** The agent tries to text the bank code it just received to an unknown number: **block** (received code, unknown recipient). Show the runner's line. | Enter | — | "No code, card number or password leaves." |
| 7 | 1:50–2:05 | **Tamper.** The $50 gift card is rewritten as $1 in the database. Within 5 s the **Payment record check** turns red and names that payment. | Enter, then scroll to the record check | — | "Edit history and it shows, at that exact row." |
| 8 | 2:05–2:30 | **Proof.** EVIDENCE.md: 1,000 at once land exactly on $500; 10,000 random households, no rule broken; latency p50 8 ms. | Enter | — | "A refusal is a probability. The cap is a guarantee." End on the repo, the commit graph since `pre-event`, and AI_USAGE.md. |

## What changed from the 8 PM plan's shot list

- **Beat 2 is the guard's scripted scam,** since there's no live agent
  (`agent/agent.py`) yet. Only the requests are scripted; the guard decides
  each one.
- **Beats 4 and 5 swapped places,** because the guard plays its scenarios
  in a fixed order: normal day, scam, switch, held bill.
- **The plumber's bill is held by the pause after repeated blocked
  attempts, not as "a bill 30% higher".** Say "payments are paused", not
  "30% higher".
- **Beat 6 isn't a payment scenario.** The runner sends the code through the
  outbound wall (`/outbound`), so the result shows in the terminal, not on the
  dashboard.
- **The red-team beat is cut:** `redteam.py` doesn't exist. Per the plan, don't
  mention it.
- **Before beat 3, Claude Desktop needs:** the proxy in its config (see
  `agent/mcp_proxy.py`) with only `ACCRUE_API` and `ACCRUE_AGENT_TOKEN` (plus
  `ACCRUE_DELEGATION_TOKEN` if you minted one), and the runner's agent token.
  Export `ACCRUE_AGENT_TOKEN` before starting the runner, so it's the same one.
