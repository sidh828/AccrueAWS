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
