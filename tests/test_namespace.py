"""The shared lupaxa namespace must stay a portion, not a regular package."""

import importlib.machinery
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"


def test_lupaxa_portion_has_no_init() -> None:
    assert not (_SRC / "lupaxa" / "__init__.py").exists()


def test_lupaxa_portion_is_a_namespace() -> None:
    spec = importlib.machinery.PathFinder.find_spec("lupaxa", [str(_SRC)])
    assert spec is not None
    assert spec.loader is None
    locations = spec.submodule_search_locations
    assert locations is not None
    assert list(locations) == [str(_SRC / "lupaxa")]
