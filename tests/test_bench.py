"""guard/bench.py measures real decisions: every request reaches the guard and is allowed."""

import pytest

from guard import bench


def test_percentile_is_nearest_rank():
    ms = sorted(float(i) for i in range(1, 101))
    assert (bench.percentile(ms, 50), bench.percentile(ms, 99), bench.percentile(ms, 100)) == (50.0, 99.0, 100.0)
    assert bench.percentile([7.0], 99) == 7.0


@pytest.mark.cedar
def test_a_short_run_times_every_decision():
    result = bench.run(20)
    assert result["decisions"] == {"allow": 20}
    assert result["token"]["n"] == result["no_token"]["n"] == 10
    assert 0 < result["all"]["p50"] <= result["all"]["p99"] <= result["all"]["max"]
