"""#26's outbound gaps, each now blocked, and ordinary numbers still allowed."""

import pytest

from walls.inbound import SessionStore
from walls.outbound import OutboundWall
from walls.secrets import SecretStore


@pytest.mark.parametrize("text", [
    "card 4111 then 1111 then 1111 then 1111",
    "4111 1111 and 1111 1111",
    "my ssn 123456789",
    "ssn 123.45.6789",
    "123.45.6789",
    "SSN: 123.45.6789",
    "social security 123.45.6789",
    "her ssn is 123.45.6789.",
    "123-45.6789",
])
def test_disguised_secrets_are_blocked(text):
    w = OutboundWall(SecretStore(), SessionStore())
    assert w.check("s", "x@example.com", "sms", text)["decision"] == "block"


def test_ordinary_numbers_are_not():
    w = OutboundWall(SecretStore(), SessionStore())
    for text in ["room 1204, zip 43210, call 614 555 0123", "meet at 3:30", "it's $45.50"]:
        assert w.check("s", "x@example.com", "sms", text)["decision"] == "allow", text


@pytest.mark.parametrize("text", ["000.12.3456", "666.12.3456", "version 1.2.3"])
def test_dotted_numbers_that_cant_be_ssns_are_allowed(text):
    w = OutboundWall(SecretStore(), SessionStore())
    assert w.check("s", "x@example.com", "sms", text)["decision"] == "allow"


# The two gaps the attack suite disclosed: a received code sent in pieces,
# and a code in sound-alike words (or reversed).

def _wall_with_code(code="427193"):
    secrets = SecretStore()
    secrets.record_code(code)
    return OutboundWall(secrets, SessionStore())


@pytest.mark.parametrize("pieces", [
    ["first part 427", "then 193"],
    ["42", "7193"],
    ["four two seven", "one nine three"],
    ["42", "71", "93"],
    ["the code starts 427", "unrelated chat", "and ends 193"],
])
def test_a_received_code_sent_in_pieces_is_blocked_when_it_completes(pieces):
    w = _wall_with_code()
    decisions = [w.check("s", "x@example.com", "sms", p)["decision"] for p in pieces]
    assert decisions[-1] == "block"
    assert "block" not in decisions[:-1]


@pytest.mark.parametrize("text", [
    "for two seven won nine three",
    "fore too seven won nein three",
    "four to seven one nine tree",
    "391724",
    "three nine one seven two four",
])
def test_a_received_code_in_sound_alikes_or_reversed_is_blocked(text):
    assert _wall_with_code().check("s", "x@example.com", "sms", text)["decision"] == "block"


def test_a_stray_sound_alike_cannot_hide_a_code():
    # "to" read as 2 would break the run; the plain reading still matches.
    text = "code four two seven, to be safe, one nine three"
    assert _wall_with_code().check("s", "x@example.com", "sms", text)["decision"] == "block"


def test_pieces_from_another_session_do_not_combine():
    w = _wall_with_code()
    assert w.check("a", "x@example.com", "sms", "427")["decision"] == "allow"
    assert w.check("b", "x@example.com", "sms", "193")["decision"] == "allow"


@pytest.mark.parametrize("pieces", [
    ["I went to the store for two hours", "won the game at 7"],
    ["meet me at 4 to 5", "room 193"],
    ["it ate for ten minutes", "too late"],
])
def test_ordinary_chat_after_a_code_arrives_still_goes_through(pieces):
    w = _wall_with_code()
    assert [w.check("s", "x@example.com", "sms", p)["decision"] for p in pieces] == ["allow"] * len(pieces)


def test_sound_alikes_never_make_a_card_or_ssn():
    # Cards and SSNs read digit_runs, which never treats "to" or "for" as a digit.
    from walls.normalize import digit_runs
    assert [[t.digits for t in run] for run in digit_runs("123 to 45 for 6789")] == [["123"], ["45"], ["6789"]]
    w = OutboundWall(SecretStore(), SessionStore())
    assert w.check("s", "x@example.com", "sms", "123 to 45 for 6789")["decision"] == "allow"
