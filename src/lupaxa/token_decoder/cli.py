"""Slim command-line interface for token-decoder."""

from __future__ import annotations

import argparse
import json
import sys
from typing import TextIO

from lupaxa.token_decoder.decode import decode_token
from lupaxa.token_decoder.version import __version__


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="token-decoder",
        description="Decode JWTs and other token formats. Signatures are not verified.",
    )
    parser.add_argument(
        "token",
        nargs="?",
        help="Token to decode. Omit to read stdin, or to prompt when stdin is a terminal. Use - for stdin.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _is_tty(stream: TextIO) -> bool:
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    return bool(isatty())


def read_token(argument: str | None, stdin: TextIO) -> str:
    """Return the token argument, or one line from stdin.

    The prompt is written to stderr so a piped JSON report stays clean.

    Parameters
    ----------
    argument:
        The positional argument, or ``None`` when it was omitted.
    stdin:
        Stream to read when the argument is missing or is ``-``.
    """
    if argument is not None and argument != "-":
        return argument
    if _is_tty(stdin):
        print("Token: ", end="", file=sys.stderr, flush=True)
    return stdin.readline()


def main(argv: list[str] | None = None, stdin: TextIO | None = None) -> int:
    """Decode one token and print a JSON report.

    Parameters
    ----------
    argv:
        Arguments to parse. Defaults to the process arguments.
    stdin:
        Token source when the argument is omitted. Defaults to ``sys.stdin``.
    """
    args = build_parser().parse_args(argv)
    source = sys.stdin if stdin is None else stdin
    report = decode_token(read_token(args.token, source))
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0
