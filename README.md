# gripfetch-apt

A [gripsack](https://github.com/gripsack-dev/gripsack) fetcher plugin that
fetches **Debian packages through the host's apt** — it *wraps* apt
(`apt-cache`, `apt-get download`), never bundles one and never reimplements
one. If your machine's apt is pointed at internal enterprise mirrors
(`/etc/apt/sources.list.d`), the plugin inherits that configuration for
free: that is the entire point.

```
grip module fetch=apt("ripgrep", "14.1.0-1")   →   bin/rg in the store
```

- No root needed (`apt-get download` + pure-Rust `.deb` extraction).
- The `.deb` payload's `usr/bin/*` is staged as `bin/*`, so modules can
  write `install={"bin/rg": symlink(...)}`.
- Proxies and mirrors: `http_proxy`/`https_proxy`/`no_proxy` and all apt
  configuration are inherited verbatim from the environment.
- Never runs maintainer scripts (`postinst` & co) — gripsack is not a
  solver; config modules own system state.

## Wiring it up

`env.toml` (gripsack 0.14+ provisions plugins from GitHub releases):

```toml
[fetchers.apt]
package = "gripsack-dev/gripfetch-apt@0.1.0"
```

Then in a module (python):

```python
from gripsack.fetch import plugin_fetch

module(
    name="hello",
    fetch=plugin_fetch("apt", package="hello", version="2.10-3"),
    install={"bin/hello": symlink("~/.local/bin/hello")},
)
```

or with the sugar (below):

```python
from gripfetch_apt import apt

module(name="hello", fetch=apt("hello", "2.10-3"), ...)
```

Args: `package` (required), `version` (optional — omit to resolve the
newest available), `repos` (optional — restrict resolution to sources
matching any of the given substrings, e.g. `["internal.example.com"]`).

## Semantics

| phase | behavior |
| --- | --- |
| resolve (no lock / no version) | enumerate via `apt-cache madison <pkg>` (fallback `apt list -a <pkg>`), pick the newest by Debian version order, report it in provenance + a `W01` warning |
| fetch | `apt-get download <pkg>[=<version>]` (no root) → hash the `.deb` bytes → verify against the Packages-index `SHA256` → extract `data.tar.{gz,xz,zst}` into `dest_dir` with a path-traversal guard → map `usr/bin/*` → `bin/*` |
| locked (pin present) | reproduce *exactly*: fetch `locked.version`, stage it, recompute the canonical tree hash of the staged payload (mirroring the core's algorithm) and fail `A04` on mismatch against `locked.sha256`; if no configured mirror serves it anymore, fail `A03` with that as the message |
| capabilities | `{"throttle": {}}` — apt mirrors don't rate-limit like APIs; an empty map is the honest declaration |
| provenance | every fetch response carries `result.provenance = {apt_version, mirror, package, version, sha256 (of the .deb), filename}` |

Hashes, disambiguated: `locked.sha256` is the **core's canonical tree
hash of the previously staged payload** (not the .deb hash) — so the
locked check runs *after* staging, on the staged tree. The .deb's own
sha256 (verified against the Packages index on every fetch) is kept in
`provenance.sha256`, and the advisory `result.sha256` reports the
staged tree hash — the value the next pin will carry.

A failed fetch still stages a deterministic `gripfetch-apt-failure.txt`
note — an empty tree never masquerades as a successful fetch (the core
discards staging on error anyway).

## Diagnostic codes

The core renders these as `gripfetch-apt/<code>`. Warnings flow; errors
fail the fetch.

| code | severity | meaning |
| --- | --- | --- |
| `A01` | error | package not in any apt index this host knows |
| `A03` | error | locked version no longer served by any configured mirror |
| `A04` | error | sha256 mismatch: staged tree vs `locked.sha256`, or Packages index vs downloaded `.deb` bytes |
| `A05` | error | `apt-get download` failed (network/mirror/auth, tail attached) |
| `A06` | error | the downloaded `.deb` is malformed |
| `A07` | error | archive member would escape `dest_dir` — payload rejected |
| `A08` | error | `apt-get` not on PATH (install apt or use another fetcher) |
| `A09` | error | malformed request (missing `package`, unknown op, …) |
| `W01` | warning | no version pinned — resolved to latest |
| `W02` | warning | index carries no SHA256 — .deb verified by downloaded bytes only (the pin is always the tree hash) |

## Frontend sugar

Two thin packages in this repo (published separately by the owner):

- **`frontend-py`** → PyPI `gripfetch-apt` — `apt(package, version=None, **kw)`
  returning exactly `gripsack.fetch.plugin_fetch("apt", ...)`; works
  standalone (soft import) for authoring/type-checking.
- **`frontend-ts`** → npm `gripfetch-apt` — `apt(pkg, version?, extra?)`
  mirroring gripsack's `pluginFetch`.

One rule: the sugar emits exactly the same IR as
`plugin_fetch("apt", ...)` — no side channels.

## Developing

```sh
cargo test                                   # unit + stdio exchange tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# protocol conformance (the gate — every check must pass)
git clone --depth 1 https://github.com/gripsack-dev/gripfetch-conformance /tmp/c
(cd /tmp/c && uv run gripfetch-conformance "$OLDPWD/target/debug/gripfetch-apt")

# live smoke (needs apt + network): fetches hello, pinned + unpinned,
# asserts bin/hello staged, reproducible trees, tampered locks rejected
python3 scripts/smoke.py target/debug/gripfetch-apt hello
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push, plus
`pytest` for the py sugar and `node --test` for the ts sugar.

## Releases

Tags `v*` drive `.github/workflows/release.yml`: a 4-target matrix
(`x86_64`/`aarch64` × `unknown-linux-musl`/`apple-darwin`, musl via
`rust:alpine` docker) producing the assets the gripsack plugin lifecycle
expects — `gripfetch-apt-<version>-<triple>.tar.gz` plus a `.sha256`
sidecar, with the binary at the tarball root — then `cargo publish`
(skipped while `CARGO_REGISTRY_TOKEN` is unset) and the GitHub release.
The owner cuts tags; nothing here publishes by accident.

## License

MIT — see [LICENSE](LICENSE).
