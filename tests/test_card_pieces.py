"""A card number sent one group at a time - to a known contact, so nothing
else stops it - is blocked by the message that completes it. Ordinary
numbers in separate messages are not."""

from agent.tools import FakeGuard, ToolBox
from walls.inbound import SessionStore
from walls.outbound import OutboundWall
from walls.secrets import SecretStore


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def wall():
    return OutboundWall(SecretStore(), SessionStore(), contacts={"friend@example.com"})


def test_a_card_sent_in_pieces_to_a_known_contact_is_blocked():
    w = wall()
    groups = ["4111", "1111", "1111", "1111"]
    decisions = [w.check("s", "friend@example.com", "sms", f"group {i} is {g}")["decision"]
                 for i, g in enumerate(groups, 1)]
    assert decisions == ["allow", "allow", "allow", "block"]


def test_ordinary_numbers_in_separate_messages_go_through():
    w = wall()
    for text in ["meet at 3", "room 1204", "my number is 614 555 0123", "it's $45.50",
                 "zip 43210", "flight 2291"]:
        assert w.check("s", "friend@example.com", "sms", text)["decision"] == "allow", text


def test_card_pieces_expire_after_one_hour():
    clock = Clock()
    guard = FakeGuard(clock=clock)
    guard.outbound_wall.add_contact("friend")
    tools = ToolBox(guard, session_id="expiring-pieces")

    for digits in ("4111", "1111", "1111"):
        assert tools.send_message("friend", "sms", digits)["decision"] == "allow"

    clock.t += 3601
    assert tools.send_message("friend", "sms", "1111")["decision"] == "allow"


def test_card_pieces_are_isolated_by_session():
    clock = Clock()
    guard = FakeGuard(clock=clock)
    guard.outbound_wall.add_contact("friend")
    first = ToolBox(guard, session_id="first-session")
    second = ToolBox(guard, session_id="second-session")

    for digits in ("4111", "1111", "1111"):
        assert first.send_message("friend", "sms", digits)["decision"] == "allow"

    assert second.send_message("friend", "sms", "1111")["decision"] == "allow"
