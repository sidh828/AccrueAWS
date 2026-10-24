"""Normal life just works: power bill plus a $50 birthday card. Everything must be allowed."""
from agent.scenarios.common import Env, ScenarioResult


def run(env: Env) -> ScenarioResult:
    res = ScenarioResult("normal_day")
    env.tools.receive_message("mom", "Please pay the power bill and send Tyler a $50 birthday card.")
    for payee, cents, why in [("power-company.example", 12_000, "power bill"),
                              ("card-shop.example", 5_000, "birthday card")]:
        res.record(cents, env.tools.pay_bill(payee, cents, why))
    return res
