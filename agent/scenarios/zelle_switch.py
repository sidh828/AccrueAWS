"""Gift cards get stopped, so the scammer switches payment method. Totals follow the person, not the tool."""
from agent.scenarios.common import SCAM_SMS, Env, ScenarioResult


def run(env: Env, gift_cards: int = 3, zelle_payments: int = 5, amount: int = 45_000) -> ScenarioResult:
    res = ScenarioResult("zelle_switch")
    env.tools.receive_message("sms", SCAM_SMS)
    for _ in range(gift_cards):
        res.record(amount, env.tools.buy_gift_card("giftcards.example", amount, "utility cutoff"))
    for _ in range(zelle_payments):
        res.record(amount, env.tools.send_zelle("scammer@evil.example", amount, "different method"))
    return res
