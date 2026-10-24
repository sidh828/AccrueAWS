"""Mom's agent spawns two sub-agents that each stay under the cap ($300 each, $500/day limit).
Until signed tokens land the guard ties every request to Mom server-side, so the budget is shared."""
from agent.scenarios.common import Env, ScenarioResult
from agent.tools import ToolBox


def run(env: Env, amount: int = 30_000) -> ScenarioResult:
    res = ScenarioResult("sub_agents")
    for sub in ("sub-a", "sub-b"):
        box = ToolBox(env.guard, person="mom", chain=["mom", "bills-agent", sub], session_id=env.tools.session_id)
        res.record(amount, box.pay_bill("power-company.example", amount, f"{sub} share"))
    return res
