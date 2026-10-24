# How we used AI

For each block of work: what we asked the AI, what we rejected and why, how
we checked its output, and which decisions a human made. Updated at 2 PM,
6 PM and 11 PM.

## Before the event

The imported accrue prototype (everything at the
[`pre-event`](https://github.com/sidh828/AccrueAWS/tree/pre-event) tag) was
itself built with heavy AI help. Many of its pull requests were written with
Claude Code, and some of its PR reviews were AI-assisted too. The PRs on
[dharvikgupta29/accrue](https://github.com/dharvikgupta29/accrue/pulls?q=is%3Apr)
say so.

## Sat Oct 24, 11:45 AM to noon: repo setup (Siddh, with Claude Code)

**Asked:** Siddh gave Claude Code (Claude Opus 5.5) the team plan and asked
it to fill this repo from accrue.

**What it did:**

- The import commit and the `pre-event` tag. It left out `experiments/` and
  the four tests that exercise it, since the plan imports only `src/`,
  `tests/` and the policies.
- `CLAUDE.md`, transcribed from the plan's invariants, interface contract,
  spending rules, implementation notes and layout. It also listed three gaps
  in the contract for the team to settle before the noon freeze.
- Moved `src/` to `guard/` to match the plan's layout.
- This file and the README.

**How we checked:** the 53 imported tests pass against cedar 4.12.0 both
before and after the move to `guard/`, and the demo prints the same
decisions. Still to do: a human reads `CLAUDE.md` against the plan before
the freeze.

**Rejected:** nothing yet.

**Human decisions:** the problem, architecture, contract, spending rules,
roles and layout all come from the team plan, not from this session.
_To fill in: how the plan itself was drafted._

## Sat Oct 24, noon to 12:15 PM: plain dashboard (Siddh, with Claude Code)

**Asked:** Siddh asked Claude Code to get as far as it could on the
dashboard's Tier 1 (wired to /events, Approve/Deny, phone alert) and to list
next steps.

**What it did:**

- Added the CI workflow. It was held back from the import until the push
  token had the `workflow` scope.
- `dashboard/fake_api.py`: a stand-in API that speaks the contract
  (`/events`, `/stream`, `/override`) and plays a scripted day for Mom, so
  the dashboard doesn't wait on `guard/api.py`.
- `dashboard/index.html` and `app.js`: the plain dashboard. It has the
  running-total bar, the pause banner, "Needs your OK" with Approve/Deny, the
  gift-card meter and the timeline. It puts API strings on the page as text,
  never as HTML, because payees come from the agent's side.
- `dashboard/alerts.py`: phone alerts through ntfy for stopped and held
  payments.
- `tests/test_dashboard.py`: the stand-in's rows match the contract's event
  row, an override settles a held payment exactly once, and alerts are in
  plain English.

**How we checked:** 56 tests pass. We ran the stand-in and hit each endpoint
with curl, ran the alert watcher in dry-run mode, and rendered the dashboard
in headless Firefox, empty and populated, then looked at the screenshots.
That caught two bugs, both fixed: the limit label ran off the screen when the
line sat at the right edge, and the watcher's output was lost when piped.

**Rejected:** nothing yet.

**Human decisions:** none in this block. The contract questions it raised
are for the team.

## Sat Oct 24, 12:15 to 12:45 PM: dashboard review fixes (Siddh, with Claude Code)

**Asked:** Siddh had Claude Code run an AI code review of the dashboard (the
Shipwright code-reviewer agent), then chose which findings to fix: six of
the eight.

**What it did:** fixed those six in one PR.

- Held payments stay in "Needs your OK" after midnight.
- Names the agent chooses can't break the page.
- Redraws are batched, so Approve/Deny clicks aren't lost.
- Failed phone alerts are retried, and floods are summed up.
- The stand-in server has limits and timeouts.
- New tests cover all of it.

**How we checked:** we confirmed the review's top finding by running it (a
cross-site POST approved a held payment on the stand-in). After the fixes,
66 tests pass, and 8 of the new tests fail on the old code. We also rendered
the dashboard in headless Firefox with a payment held since yesterday and a
hostile row (tool `constructor`, rule `toString`, null fields).

**Rejected:** the review's remaining findings were deferred, not rejected.
`/override` has no login, and approvals don't reach other tabs. Both need
team decisions in issue #1.

**Human decisions:** Siddh picked which findings to fix.
