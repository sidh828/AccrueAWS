"""Payment-tool categories shared by the agent and the guard.

The guard's rule is the one in guard/authorize.py (TOOL_CATEGORIES): which
categories each tool may pay. It's an allow-list, because the agent sends
the category - "pay_bill" labelled "groceries" must not be a way to buy a
gift card past its cap. This module derives from it, so the agent's tools,
its stand-in guard (agent.tools.FakeGuard) and the real guard can't
disagree.
"""
from __future__ import annotations

from guard.authorize import TOOL_CATEGORIES

# What a tool sends when the caller doesn't name a category. A plain "bill"
# is accepted but is never a known bill: name "utility" or "rent" for that.
DEFAULT_TOOL_CATEGORIES = {
    "pay_bill": "bill",
    "buy_gift_card": "gift_card",
    "send_zelle": "transfer",
    "send_wire": "transfer",
    "send_crypto": "crypto",
}


def category_matches_tool(tool: str, category: str) -> bool:
    return category in TOOL_CATEGORIES.get(tool, ())
