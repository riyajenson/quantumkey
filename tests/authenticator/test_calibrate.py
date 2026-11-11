"""E-04: choosing Argon2id parameters for a target unlock time."""

import json

from quantumkey.authenticator import calibrate
from quantumkey.authenticator.vault import KdfParams


def fake_measure(kdf: KdfParams, repeats: int) -> float:
    # 100 ms per pass per 64 MiB: cost grows with both memory and passes.
    return 100.0 * kdf.time_cost * kdf.memory_kib / 65_536


GRID = [KdfParams(t, m, 1) for m in (19_456, 65_536) for t in (1, 2, 3, 4)]


def test_recommend_picks_the_most_work_that_fits_the_target():
    table = calibrate.measure_grid(GRID, repeats=1, measure=fake_measure)
    # Work = time_cost x memory. Within 250 ms: 64 MiB x 2 (200 ms, 131072) beats
    # 19 MiB x 4 (~119 ms, 77824).
    assert calibrate.recommend(table, target_ms=250) == KdfParams(2, 65_536, 1)
    assert calibrate.recommend(table, target_ms=500) == KdfParams(4, 65_536, 1)


def test_ties_go_to_more_memory():
    table = [(KdfParams(2, 65_536, 1), 200.0), (KdfParams(1, 131_072, 1), 200.0)]
    assert calibrate.recommend(table, target_ms=250) == KdfParams(1, 131_072, 1)


def test_recommend_returns_none_when_nothing_fits():
    table = calibrate.measure_grid(GRID, repeats=1, measure=fake_measure)
    assert calibrate.recommend(table, target_ms=10) is None


def test_cli_writes_a_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(calibrate, "measure_kdf", fake_measure)
    out = tmp_path / "report.json"
    assert calibrate.main(["--target-ms", "250", "500", "--repeats", "1", "--json", str(out)]) == 0
    report = json.loads(out.read_text())
    # Over the full grid, 46 MiB x 3 (~216 ms) is the most work within 250 ms.
    assert report["recommendations"]["250"] == {"time_cost": 3, "memory_kib": 47_104, "parallelism": 1}
    assert len(report["measurements"]) == len(calibrate.DEFAULT_GRID)
    assert "250 ms" in capsys.readouterr().out
