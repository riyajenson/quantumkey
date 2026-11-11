"""The benchmark harness runs and reports the measurements the docs cite."""

from quantumkey.bench import bench_variant


def test_bench_reports_login_with_and_without_a_session(tmp_path):
    result = bench_variant("ML-DSA-44", 2, tmp_path)
    protocol = result["protocol_ms"]
    assert {"login_end_to_end", "login_end_to_end_in_session"} <= set(protocol)
    # The session skips the Argon2id derivation, which dominates a cold login.
    assert protocol["login_end_to_end_in_session"]["median_ms"] < protocol["login_end_to_end"]["median_ms"]
