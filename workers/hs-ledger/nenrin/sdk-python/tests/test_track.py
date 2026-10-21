"""nenrin-track from the package: the vectors give the reports track.py wrote, byte for byte."""
from nenrin_verify import track_cli


def test_track_selftest_from_the_package(capsys):
    assert track_cli.selftest() == 0
    assert "=== 10 / 10 (nenrin-track-v0) ===" in capsys.readouterr().out
