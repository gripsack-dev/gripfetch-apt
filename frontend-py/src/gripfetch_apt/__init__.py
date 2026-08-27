"""gripfetch-apt — thin sugar for the apt fetcher plugin.

`apt(package, version=None, **kw)` returns exactly the IR that
`gripsack.fetch.plugin_fetch("apt", ...)` produces — no side channels,
no extra keys. With gripsack installed you get its real `Fetch`
object; without it, a mirror of the same frozen dataclass so the
package works standalone for authoring and type-checking.

    from gripfetch_apt import apt

    module(
        name="hello",
        fetch=apt("hello", "2.10-3"),
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = ["apt", "Fetch"]
__version__ = "0.1.0"

try:  # pragma: no cover - exercised only with gripsack installed
    from gripsack.fetch import Fetch as _GsFetch
    from gripsack.fetch import plugin_fetch as _gs_plugin_fetch

    def apt(
        package: str, version: Optional[str] = None, **kw: Any
    ) -> _GsFetch:
        """A Debian package fetched via the host's apt (`gripfetch-apt`).

        `version` omitted → latest available (resolved at fetch time).
        Extra kwargs pass through verbatim (e.g. `repos=[...]`).
        """
        return _gs_plugin_fetch("apt", **_args(package, version, kw))

except ImportError:
    from enum import Enum

    class FetchKind(str, Enum):
        """Mirrors gripsack.fetch.FetchKind for standalone use."""

        PLUGIN = "plugin"

    @dataclass(frozen=True)
    class Fetch:
        """A fetch spec — mirrors gripsack.fetch.Fetch exactly."""

        kind: FetchKind
        args: dict[str, Any] = field(default_factory=dict)

        def to_ir(self) -> dict[str, Any]:
            return {"kind": self.kind.value, **self.args}

    def apt(package: str, version: Optional[str] = None, **kw: Any) -> Fetch:
        """A Debian package fetched via the host's apt (`gripfetch-apt`).

        `version` omitted → latest available (resolved at fetch time).
        Extra kwargs pass through verbatim (e.g. `repos=[...]`).
        """
        return Fetch(
            FetchKind.PLUGIN,
            {"name": "apt", "args": _args(package, version, kw)},
        )


def _args(package: str, version: Optional[str], kw: dict[str, Any]) -> dict[str, Any]:
    """Build the plugin args: package always, version only when pinned."""
    args: dict[str, Any] = {"package": package}
    if version is not None:
        args["version"] = version
    for key, value in kw.items():
        if value is not None:
            args[key] = value
    return args
