/**
 * gripfetch-apt — thin sugar for the apt fetcher plugin.
 *
 * `apt(...)` returns exactly the IR that gripsack's
 * `pluginFetch("apt", ...)` produces — no side channels.
 *
 *   import { apt } from "gripfetch-apt";
 *
 *   module({
 *     name: "hello",
 *     fetch: apt("hello", "2.10-3"),
 *   });
 */

/** The plugin fetch spec — mirrors gripsack's Fetch `plugin` member. */
export type Fetch = {
  kind: "plugin";
  name: string;
  args?: Record<string, unknown>;
};

/**
 * A Debian package fetched via the host's apt (`gripfetch-apt`).
 *
 * @param pkg      Debian package name, e.g. `"hello"`
 * @param version  optional pin; omitted → latest available
 * @param extra    pass-through args (e.g. `{ repos: ["noble/main"] }`)
 */
export function apt(
  pkg: string,
  version?: string,
  extra?: Record<string, unknown>,
): Fetch {
  const args: Record<string, unknown> = { package: pkg };
  if (version !== undefined) {
    args.version = version;
  }
  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      if (value !== undefined) {
        args[key] = value;
      }
    }
  }
  return { kind: "plugin", name: "apt", args };
}
