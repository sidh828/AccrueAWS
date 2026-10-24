"""50 requests fired at once. $50 x 10 divides the $500 cap, so the total should land exactly on it."""
from agent.scenarios.common import Env, ScenarioResult, parallel_map


def run(env: Env, count: int = 50, amount: int = 5_000) -> ScenarioResult:
    res = ScenarioResult("parallel_flood")
    results = parallel_map(lambda _: env.tools.pay_bill("power-company.example", amount, "burst"), range(count))
    for r in results:
        res.record(amount, r)
    return res
