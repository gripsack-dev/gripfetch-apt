"""The one rule: the sugar emits exactly the IR plugin_fetch produces."""

from __future__ import annotations

import importlib.util

import pytest

from gripfetch_apt import apt

HAS_GRIPSACK = importlib.util.find_spec("gripsack") is not None


def test_unpinned_omits_version():
    assert apt("hello").to_ir() == {
        "kind": "plugin",
        "name": "apt",
        "args": {"package": "hello"},
    }


def test_pinned_includes_version():
    assert apt("hello", "2.10-3").to_ir() == {
        "kind": "plugin",
        "name": "apt",
        "args": {"package": "hello", "version": "2.10-3"},
    }


def test_extra_kwargs_pass_through_without_none():
    spec = apt("hello", None, repos=["noble/main"], sha256=None).to_ir()
    assert spec == {
        "kind": "plugin",
        "name": "apt",
        "args": {"package": "hello", "repos": ["noble/main"]},
    }


def test_frozen_shape():
    spec = apt("ripgrep", "14.1.0-1")
    with pytest.raises(Exception):
        spec.kind = "tarball"  # type: ignore[misc]
    with pytest.raises(Exception):
        spec.args = {}  # type: ignore[misc]


@pytest.mark.skipif(not HAS_GRIPSACK, reason="gripsack not installed")
def test_identical_to_plugin_fetch():
    from gripsack.fetch import plugin_fetch

    assert apt("hello", "2.10-3") == plugin_fetch(
        "apt", package="hello", version="2.10-3"
    )
    assert apt("hello") == plugin_fetch("apt", package="hello")
    assert apt("hello").to_ir() == plugin_fetch("apt", package="hello").to_ir()
