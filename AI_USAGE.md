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
