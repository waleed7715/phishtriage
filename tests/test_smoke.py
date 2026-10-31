import pytest

from phishtriage import main


def test_main_prints_project_name(capsys: pytest.CaptureFixture[str]) -> None:
    main()
    assert "phishtriage" in capsys.readouterr().out
