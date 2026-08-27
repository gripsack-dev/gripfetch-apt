# gripfetch-apt (typescript sugar)

Thin DSL helper for authoring gripsack modules that fetch Debian
packages through the [gripfetch-apt plugin](https://github.com/gripsack-dev/gripfetch-apt).

```ts
import { apt } from "gripfetch-apt";

module({
  name: "hello",
  fetch: apt("hello", "2.10-3"), // version optional → latest available
  install: { "bin/hello": symlink("~/.local/bin/hello") },
});
```

`apt(...)` returns exactly what gripsack's `pluginFetch("apt", ...)`
returns — no side channels.
