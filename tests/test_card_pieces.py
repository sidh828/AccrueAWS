from agent.tools import FakeGuard, ToolBox


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def test_card_pieces_to_known_contact_block_when_they_complete_card():
    clock = Clock()
    guard = FakeGuard(clock=clock)
    guard.outbound_wall.add_contact("friend")
    tools = ToolBox(guard, session_id="card-pieces")

    results = [
        tools.send_message("friend", "sms", f"group {index}: {digits}")
        for index, digits in enumerate(("4111", "1111", "1111", "1111"), 1)
    ]

    assert [result["decision"] for result in results] == [
        "allow", "allow", "allow", "block",
    ]
    assert any(finding["kind"] == "card_number" for finding in results[-1]["findings"])


def test_ordinary_number_groups_across_messages_are_allowed():
    clock = Clock()
    guard = FakeGuard(clock=clock)
    guard.outbound_wall.add_contact("friend")
    tools = ToolBox(guard, session_id="ordinary-numbers")

    for number in ("1204", "2291", "1204", "2291"):
        assert tools.send_message("friend", "sms", number)["decision"] == "allow"


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
