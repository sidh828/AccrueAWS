"""$49 every 20 minutes. Every call is tiny; the total is not. Time is compressed with env.advance."""
from agent.scenarios.common import Env, ScenarioResult


def run(env: Env, count: int = 36, amount: int = 4_900, interval_s: int = 1_200,
        payee: str = "quickpay.example", scam_text: str | None = None) -> ScenarioResult:
    res = ScenarioResult("slow_drip")
    if scam_text:
        env.tools.receive_message("sms", scam_text)
    for _ in range(count):
        res.record(amount, env.tools.pay_bill(payee, amount, "small fee"))
        env.advance(interval_s)
    return res
