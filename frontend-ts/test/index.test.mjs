// The one rule: the sugar emits exactly the IR pluginFetch produces.
import test from "node:test";
import assert from "node:assert/strict";

import { apt } from "../dist/src/index.js";

test("unpinned omits version", () => {
  assert.deepEqual(apt("hello"), {
    kind: "plugin",
    name: "apt",
    args: { package: "hello" },
  });
});

test("pinned includes version", () => {
  assert.deepEqual(apt("hello", "2.10-3"), {
    kind: "plugin",
    name: "apt",
    args: { package: "hello", version: "2.10-3" },
  });
});

test("extra args pass through, undefined dropped", () => {
  assert.deepEqual(apt("hello", undefined, { repos: ["noble/main"], sha256: undefined }), {
    kind: "plugin",
    name: "apt",
    args: { package: "hello", repos: ["noble/main"] },
  });
});

test("shape matches gripsack pluginFetch", () => {
  // gripsack's pluginFetch(name, args) → { kind: "plugin", name, args }
  const pluginFetch = (name, args) => ({ kind: "plugin", name, args });
  assert.deepEqual(apt("ripgrep", "14.1.0-1"), pluginFetch("apt", {
    package: "ripgrep",
    version: "14.1.0-1",
  }));
});
