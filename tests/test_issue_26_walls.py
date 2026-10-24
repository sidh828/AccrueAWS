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
])
def test_disguised_secrets_are_blocked(text):
    w = OutboundWall(SecretStore(), SessionStore())
    assert w.check("s", "x@example.com", "sms", text)["decision"] == "block"


def test_ordinary_numbers_are_not():
    w = OutboundWall(SecretStore(), SessionStore())
    for text in ["room 1204, zip 43210, call 614 555 0123", "meet at 3:30", "it's $45.50"]:
        assert w.check("s", "x@example.com", "sms", text)["decision"] == "allow", text
