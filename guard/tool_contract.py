"""Payment-tool category defaults and validation shared by the API and agent."""
from __future__ import annotations

DEFAULT_TOOL_CATEGORIES = {
    "pay_bill": "bill",
    "buy_gift_card": "gift_card",
    "send_zelle": "transfer",
}

_PAYMENT_ONLY_CATEGORIES = {"gift_card", "transfer"}


def category_matches_tool(tool: str, category: str) -> bool:
    if tool == "pay_bill":
        return category not in _PAYMENT_ONLY_CATEGORIES
    return DEFAULT_TOOL_CATEGORIES.get(tool) == category
