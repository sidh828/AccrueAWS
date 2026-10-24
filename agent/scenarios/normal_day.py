"""Normal life just works: power bill plus a $50 birthday card. Everything must be allowed."""
from agent.scenarios.common import Env, ScenarioResult


def run(env: Env) -> ScenarioResult:
    res = ScenarioResult("normal_day")
    env.tools.receive_message("mom", "Please pay the power bill and send Tyler a $50 birthday card.")
    res.record(
        12_000,
        env.tools.pay_bill("power-company.example", 12_000, "power bill", category="utility"),
    )
    res.record(
        5_000,
        env.tools.pay_bill("card-shop.example", 5_000, "birthday card", category="personal"),
    )
    return res
