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

## Sat Oct 24, 11:40 AM to 1:05 PM: guard review and guard Tier 1 (Dharvik, with Claude Code)

**Asked:** Dharvik gave Claude Code (Claude Opus 5.5) the team plan, the
accrue repo and this one, and asked for a detailed review. Then, one step
at a time: post the review for the team, make the four known bug-fix
commits, and keep going on `guard/`.

**What it did:**

- Reviewed the plan and both repos, and posted the result as issue #1:
  confirmed bugs, contract gaps, to-dos for each person, demo risks, and Q&A
  for judging. It reproduced each bug by running the guard against the
  real Cedar CLI before writing it up.
- #2 (merged): the plan's four bug fixes, one commit and one regression
  test each:
  - the breaker ordered by row id
  - lowercase scope names
  - indexed queries with a 24-hour window
  - a timeout on the Cedar call
- #4: integer cents everywhere, a `request_id` that makes retries safe, and
  the policy file as a parameter.
- #7: the family spending rules in `guard/policies/family.cedar`, plus:
  - `authorize_payment` returning allow, deny or hold
  - holds the family settles by appending a row (`resolve`), so no row
    ever changes
  - event rows shaped as the contract's
  - failing closed to a hold when Cedar is unavailable
- #11: a hash chain over every ledger row, and `verify()`. It names the
  first bad row, and an anchor or a key catches someone re-hashing after an
  edit.

**How we checked:**

- Every bug was reproduced first with a probe script against Cedar 4.12.0,
  and the same script was re-run after the fixes.
- Each regression test fails on the old code. One (the 24-hour window)
  failed there for the wrong reason, a missing helper, so we re-ran that
  scenario against the old code by hand to confirm the behavior was wrong.
- `cedar validate` passes for both policies; a test runs it for the family
  policy.
- The suite went 56 → 60 → 65 → 88 → 97 passing, and the concurrency
  tests were run several times. Fifty $50 payments fired at once allow
  exactly $500.
- Measured instead of assumed:
  - about 2.4 ms per Cedar call
  - `authorize` with 200k rows went from about 34 ms to about 5 ms
  - `verify()` takes about 14 ms over 2,000 rows
- CI is green on #2, #4 and #7.

**Rejected or changed:**

- **cedarpy:** not adopted. The plan's fallback was for a slow CLI, and
  the CLI measured at about 2.4 ms.
- **The plan's `pending` row:** dropped from the reservation step. The
  decision happens inside one locked transaction, so no other request can
  ever see a pending row. Only `held` waits.
- **Holding first payments over $200:** Claude had proposed it. We changed
  it to deny, to match the dashboard's stand-in API, which the team already
  had.
- **Two of Claude's tests were wrong, not the guard.** They expected a hold
  where the stricter $100 daily cap after a scam flag correctly denies.
  Running the tests caught it, and the tests were fixed.
- **The external review:** an AI-generated adoption review of accrue from
  Oct 14 overlapped with this one. Its findings were checked against the
  code before being used, and two (a global policy path and missing
  coverage tooling) were added to the to-dos.

**Human decisions (Dharvik):**

- what to review
- posting the review as issue #1 for everyone
- the order of the work: bug fixes, then cents, then the family rules, the
  hash chain before the API
- going ahead on the unanswered contract proposals, but posting them on
  #1 first with a 3 PM deadline for objections
- turning on the PR auto-fix monitor

The rule-to-outcome table and the "new rows only" log were Claude's
proposals. Dharvik adopted them pending the team's answer on #1. Siddh
reviewed and merged #2.

## Sat Oct 24, 1:05 PM to 3:30 PM: the rest of guard Tier 1, end to end (Dharvik, with Claude Code)

**Asked:** Dharvik asked Claude Code (Claude Opus 5.5), one step at a time:
- the hash chain, then the API
- a more realistic test than the gift-card demo
- fixes for the gaps that test found
- then: land everything on `main`, wire it to Benji's agent and walls,
  write `explain.py`, and this entry

**What it did:**

- **#11, the hash chain and `verify()`.** Each row hashes the one before
  it. An edit, a deletion or an inserted row is named. An anchor kept
  off the box, or `ACCRUE_LEDGER_KEY`, catches re-hashing after an edit.
- **#13, `guard/api.py`.** The contract over HTTP, behaving like Siddh's
  stand-in so the dashboard works unchanged.
- **#14, `guard/sim.py`, Margaret's September.** A fictional 78-year-old's
  real-looking month (six months of bank history, then September) with
  eight real elder-fraud patterns that adapt when blocked, and a daughter
  who acts on alerts. It found two gaps:
  - a patient $250-every-3-days scam took $2,400 and was never noticed
  - three of her own payments were denied, with no way to approve them
- **#15, the gap fixes,** posted on issue #1 first:
  - a $500-per-30-days cap on recently added payees
  - `notice` FYIs for payments that went through to new payees
  - known bills and family-approved payments left out of the day's total
  - over the limit to a payee she has paid before is a hold, not a deny

  Scam losses for the month went from $1,995 to $395. Her own payments
  denied went from 3 to 0.
- **#17 and #18, landing it all on `main`.**
  - **One API with Benji's walls** (#16) inside, so `/inbound` and
    `/outbound` share taint with `/authorize`.
  - **The tool now decides which categories a payment can claim,** so a
    gift card can't be labelled as groceries.
  - **`guard/local.py`** runs the real guard in-process for Benji's
    attack suite.
  - **`tests/test_e2e.py`** runs that suite with "Our guard" on the real
    engine, and the video's scam beat through the agent's tools over HTTP.
- **#18, `guard/explain.py`.** A plain-English sentence for every
  decision, built only from logged numbers, and a checker that rejects
  any AI-written sentence whose numbers don't match.

**How we checked:**

- The suite went 97 → 110 → 114 → 220 → 234 → 240 passing. That includes
  Benji's walls and attack suite, and the end-to-end tests over real HTTP
  with the real Cedar CLI.
- Against the real guard, Benji's attack suite has no errors and nothing
  over $500. The only leak is the one his suite discloses as a known gap.
- We ran the guard live with Mom's scam day and opened the real
  dashboard in a browser. It showed "$350 of $500 spent today", with the
  approved payment counted once.
- Each gap was an `xfail(strict=True)` test before the fix and a plain
  test after.
- Measured: `verify()` takes about 14 ms over 2,000 rows, and `authorize`
  stays at about 5 ms.

**Mistakes, and what caught them:**

- **#13 and #15 never reached `main`.** They were opened against stacked
  branches that were merged before them, so they merged into dead
  branches while showing "MERGED". Caught by checking `main`'s files
  directly. #17 lands them, and all of Claude's PRs now target `main`.
- **The live run reported the wrong rule** for a $450 gift card
  (`daily_cap` rather than `gift_card_daily_cap`). Fixed, and tested.
- **The first version of the explanation checker** accepted a real number
  attached to the wrong thing ("about $500 in gift cards"). Its own test
  caught it, and each rule now checks only its relevant numbers.
- **Several test fixtures relied on assumptions the new rules changed,**
  such as a "known" payee paid only 2 days earlier. They were updated,
  and each change is explained in its commit.
- **The simulation started with two months of history.** It was moved to
  six, which a bank import would realistically have. That's disclosed in
  #15, and it's the reason the car insurance isn't a first payment.

**Rejected or changed:**

- **FastAPI for the API:** not used. It came in with #16, but the
  dashboard depends on the standard-library server's stream and token
  rule.
- **#16's mapping of every bill to "bill":** changed. It would have made
  rent count against the $500 limit.
- **An AI writer for explanations:** not wired yet. Only the template and
  the checker run.

**Human decisions (Dharvik):**

- build the hash chain before the API
- build the household simulation
- fix both gaps it found
- post the rule changes on #1 before coding
- "do all of it" for landing, end to end and `explain.py`

Benji merged #11 to #14, and Siddh merged #15.

## Sat Oct 24, 3:30 PM to 9:00 PM: guard Tier 2, a hostile review, and the proof (Dharvik, with Claude Code)

**Asked:** Dharvik asked Claude Code (Claude Opus 5.5), one step at a time:
- the Tier 2 guard work: guarantee tests, delegation tokens, policy replay
- "review brutally, scrutinize everything", then benchmark and push
- fix what's in `guard/`, and write up the rest for each owner
- close #26's gaps in walls/ (Benji's folder, with Benji reviewing)
- a plan for the team from 8 PM to submission, then "blaze through" his part of it

**What it did:**

- **#21, the guarantees, checked after the fact.** `tests/guarantees.py`
  reads a whole ledger and lists every allowed payment that broke a rule.
  The property, concurrency and chaos tests all end with it.
- **#22, signed delegation tokens.** A sub-agent's budget and tools can
  only shrink. **#23, policy replay:** what a draft rule would have done to
  real history.
- **#24:** fixed `main`'s red CI (the 60-at-once test hit the lock timeout
  on a slow runner).
- **A hostile review at 4:30 PM.** It attacked the guarantees directly and
  ran every finding. **#25** fixes the guard's holes:
  - the same known bill paid ten times: $1,200 allowed. It now counts once
    a cycle
  - "$1 to verify, then $450" to a new payee: allowed. It's now a hold, and
    $0 payments are refused
  - a scam text in one chat, then paying from another: allowed. It now
    taints the whole household for 6 hours
  - "person": "mom2", or "mоm" with a Cyrillic о: a fresh $500 a day. Fixed
    with the `ACCRUE_PEOPLE` allowlist
  - the React demo replayed decisions typed into a script. The guard now
    serves `/demo/run` and decides each request

  The findings in other folders went on issue #26, with owners and repros,
  instead of into their code.
- **#29, a payout outbox.** Money moves at most once per payment, even when
  an agent retries a request.
- **#30, CLAUDE.md's contract** brought up to date with `main` (it needed
  everyone's OK; Benji merged it).
- **#32 and #33, in Benji's walls at Dharvik's request:** a card number
  sent one group at a time, or with words between the groups, and SSNs
  with dots or no separators, are now blocked. Ordinary numbers (rooms,
  zips, phones, prices) still go through.
- **#38:** `.env` kept out of git before anyone wrote an API key into it.
- **#40 and #44, a writer queue and `EVIDENCE.md`.** A storm test found
  that 600 requests at once left 308 timed out on the database lock. They
  were held, so nothing went over the cap, but real payments got stuck.
  Decisions now queue before SQLite's lock: 1,000 at once land exactly on
  $500, with none timing out. `EVIDENCE.md` lists every claim with its
  command and tonight's result.
- **Reviews:**
  - #36 (the guard serves the React build) and #39 (Claude Desktop through
    an MCP proxy): each run live before approving
  - #43 (React CI): checked its action pin is the official release
  - #37 (role-based logins): changes requested
- **A team plan page for 8 PM to submission:** owners, commands, the demo
  run sheet, judge Q&A and what to cut.

**How we checked:**

- The suite went 240 → 395 passing, with the real Cedar CLI.
- 10,000 random households × 40 steps (about 400,000 decisions): 0
  guarantees broken.
- The concurrency and chaos tests passed 20 runs out of 20.
- Mutation: each of the 12 spending rules was deleted in turn, and a
  behavioral test failed every time.
- The attack suite on the real guard: 18 attacks, 16 blocked, 2 capped,
  nothing leaked.
- Latency over HTTP, measured: p50 8.3 ms, p99 10.0 ms.
- At 9:05 PM, on a clean `main`: all four demo scenarios were run on a
  fresh guard, and `/verify` said `ok: true`. A hand edit was refused, and
  once the lock was dropped, `/verify` named the edited row.

**Mistakes, and what caught them:**

- **#32's first card check** ran Luhn alone, which about 1 in 10 ordinary
  numbers pass. Its own test of ordinary numbers caught it, and a card now
  also needs a card's shape (15 or 16 digits, starting 2 to 6). The next
  version missed the attack because labels like "group 1" broke the
  sequence. Now only 4- to 6-digit groups count.
- **#33's first fix** still let "4111 1111 and 1111 1111" through: the two
  groups merged into one 8-digit run. A test caught it.
- **The first mutation run** counted the two delegation rules as caught
  only because a structural test failed. That test is left out now, and
  both are caught by token tests.
- **#40 merged without its last commit.** GitHub's PR page lagged behind
  the branch, so it merged with placeholders where the numbers should be.
  The 9 PM check of `main`'s own files caught it, and #44 adds the
  numbers back.
- **The plan page described the `held_bill` scene wrongly** (a bill rule,
  not the breaker). The demo run caught it, and the page was corrected.

**Rejected or changed:**

- **An AI writer for explanations:** still not wired. `/events` builds
  explanations on every read, so it would need a cache, and it couldn't be
  tested against a real model tonight. It must never run inside the locked
  transaction.
- **Loosening the storm test** to accept lock timeouts as "fail closed":
  rejected. The cause was fixed instead.
- **#37's role-based logins tonight:** changes requested. The real guard's
  attack suite got 401s, and it changes the frozen contract after the
  freeze.
- **Claude merging its own PRs unreviewed:** blocked by its permissions.
  A teammate merged #38.

**Human decisions (Dharvik):**

- run the hostile review, and fix only `guard/` while writing up the rest
  on #26
- have Claude fix #26's wall items in Benji's folder, with Benji reviewing
- the dotted-SSN tests
- the plan's scope for the last stretch
- reviewing and merging #40, and the merges of #27, #28, #31, #36 and #41
  after review
