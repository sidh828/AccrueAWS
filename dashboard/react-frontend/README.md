# Accrue React frontend — Tier 1 starter

A light, projector-readable dashboard designed for the frozen `CLAUDE.md` API contract.

## Where it goes

Copy `react-frontend/` into your existing repo's `dashboard/` directory. **Do not delete or rename** the existing `index.html`, `app.js`, `fake_api.py`, or `alerts.py`. This frontend is an additive replacement for the UI, not a change to the guard contract.

## Start locally (two terminals, from the repo root)

Terminal A:

```bash
python3 dashboard/fake_api.py --step 3
```

Terminal B:

```bash
cd dashboard/react-frontend
npm install
npm run dev
```

Then visit **http://127.0.0.1:5173/**. The fake guard is at port 8001; Vite proxies `/events`, `/stream`, and `/override` to it. Avoid navigating to `http://127.0.0.1:8001` if you want the React version — that still serves the legacy plain dashboard.

Run `npm test` to test integer-cent formatting and status-derived totals; run `npm run build` to produce `dist/` for deployment.

If the backend uses a different port, change `vite.config.js`. If you run the built UI on a separate origin, configure a **trusted** API host (via `VITE_API_BASE`) plus secure backend CORS, and appropriate authentication. Do not expose `POST /override` publicly without an authorized daughter session.

## What's working

- Overview and Activity views; activity filter and expandable transaction details
- Segmented *actual* spending bar, with a separate illustrative hatched projection for one blocked attempt
- Category summary and gift card standard-limit meter
- Held request approvals/denials sent to `POST /override` (with confirmation for approve)
- `/events?since=0` snapshot followed by `/stream` SSE; falls back to full snapshot polling if SSE fails
- UI updates when an existing event ID changes following override
- Breaker warning based on `held` events labeled with `breaker`
- Mobile-responsive layout with high-contrast status states; no untrusted markup inserted via `innerHTML`

## Important honest demo limitations / backend questions

1. **Current effective limits aren't available.** `$500` daily and `$100` gift card are the *standard* limits from `CLAUDE.md`, not necessarily the stricter tainted-session limits. The frontend labels them as such. Ask backend to support an authorized `/summary` endpoint or attach verified limits/aggregates to an existing read response — after team approval; don't change the frozen contract unilaterally.
2. **Denied/held requests aren't spent.** The spending hero counts only `status: allowed`. The hatched projection shows *one* attempt, never the sum of every rejected attempt.
3. **Only `status: held` is approvable.** `pending` means the guard may still be deciding. The fake backend's override only accepts `held`; this UI mirrors that behavior.
4. **`/events?since=lastId` misses updates to old IDs.** Full snapshots plus SSE upserts avoid getting stale after an override; if backend changes the event protocol, retest.
5. **The provided fake API is just a simulation.** Its override changes status without performing real rule reevaluation; its hash chain is not a production tamper-evident implementation. Do not claim the UI proves security — run tests against the real guard.
6. **Authentication is not specified in the frozen interface.** The user-facing Approve/Deny flow must eventually require server-side authorization for the family member. CORS alone is not authentication. Protect sensitive payees, event history and phone push topics.
7. **Phone notification URL:** when testing ntfy, use the Vite URL (`http://<laptop-ip>:5173/`) for `alerts.py --open`, not the fake API's old dashboard URL. Use `npm run dev:lan` on a trusted network only, and check firewall access.
8. **Serving production assets:** the built `dist/` needs to be served by the demo backend or a dedicated web server with `/events`, `/stream`, `/override` routed appropriately. Keep the existing plain dashboard as a fallback until integration is reliable.

## Suggested demo (real API once available)

1. Start with normal payment(s): the solid bar moves and the activity feed labels them Allowed.
2. Run gift-card scam attempts: the blocked attempt appears as hatching, and activity explains the gift-card rule.
3. Trigger breaker/held request: orange Needs your OK card appears (do not approve until explicitly authorized).
4. Approve/deny an eligible held request: `POST /override`, wait for confirmation, and show the event updating live.
5. Switch to the Activity view: expand individual events to show explanations and agent chains.

## Styling

`styles.css` holds the light fintech design tokens. Typography uses Manrope + DM Sans with local system fallbacks, and Lucide React icons. You can replace these styles with Figma-derived tokens without changing components. Color never carries meaning alone; each event also has a status label.
