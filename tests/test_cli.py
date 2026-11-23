"""Command-line interface."""

import io
import json

import pytest

from lupaxa.token_decoder.cli import main
from lupaxa.token_decoder.version import __version__


def test_argument_prints_json(capsys: object) -> None:
    assert main(['{"n":1}']) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.out) == {"type": "JSON", "data": {"n": 1}}
    assert captured.err == ""


def test_stdin_does_not_prompt(capsys: object) -> None:
    assert main([], stdin=io.StringIO("6869\n")) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    report = json.loads(captured.out)
    assert report["type"] == "Hexadecimal"
    assert report["decoded"] == "hi"
    assert captured.err == ""


def test_terminal_prompt_goes_to_stderr(capsys: object) -> None:
    class _TTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    assert main(["-"], stdin=_TTY('{"ok":true}\n')) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.out)["type"] == "JSON"
    assert captured.err == "Token: "


def test_version(capsys: object) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert captured.out.strip() == __version__
