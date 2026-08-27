# gripfetch-apt (python sugar)

Thin DSL helper for authoring gripsack modules that fetch Debian
packages through the [gripfetch-apt plugin](https://github.com/gripsack-dev/gripfetch-apt).

```python
from gripfetch_apt import apt

module(
    name="hello",
    fetch=apt("hello", "2.10-3"),   # version optional → latest available
    install={"bin/hello": symlink("~/.local/bin/hello")},
)
```

`apt(...)` returns exactly what `gripsack.fetch.plugin_fetch("apt", ...)`
returns — no side channels. The package works standalone (for authoring
and type-checking) even without gripsack installed: it then returns a
mirror of the same frozen `Fetch` dataclass.
