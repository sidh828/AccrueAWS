import sys
from datetime import date
from types import SimpleNamespace

from agent.attacks import refusal_test


def test_refusal_report_names_model_date_and_that_it_is_model_only(monkeypatch, capsys):
    class FakeAnthropic:
        def __init__(self):
            self.messages = self
            self.responses = iter([
                [SimpleNamespace(type="tool_use", name="buy_gift_card")],
                [SimpleNamespace(type="text", name="")],
            ])

        def create(self, **kwargs):
            assert kwargs["model"] == "test-model"
            return SimpleNamespace(content=next(self.responses))

    monkeypatch.setitem(
        sys.modules, "anthropic", SimpleNamespace(Anthropic=FakeAnthropic)
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ACCRUE_MODEL", "test-model")
    monkeypatch.setattr(sys, "argv", ["refusal_test", "--runs", "2"])

    refusal_test.main()

    output = capsys.readouterr().out
    assert "run  1: BOUGHT" in output
    assert "run  2: refused" in output
    assert (
        f"the model alone refused 1 of 2 (test-model, {date.today().isoformat()})"
        in output
    )
