"use strict";
const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { resolveBinary } = require("../lib/resolve.js");

test("linux x64 -> linux-x64 package, plain binary name", () => {
  const fakeResolve = (spec) => {
    assert.strictEqual(spec, "@tiagosilva07/zyrax-guard-linux-x64/package.json");
    return "/fake/node_modules/@tiagosilva07/zyrax-guard-linux-x64/package.json";
  };
  assert.strictEqual(
    resolveBinary("linux", "x64", fakeResolve),
    path.join("/fake/node_modules/@tiagosilva07/zyrax-guard-linux-x64", "zyrax-guard")
  );
});

test("win32 uses the .exe binary", () => {
  const fakeResolve = () => path.join("C:", "fake", "win32-x64", "package.json");
  assert.ok(resolveBinary("win32", "x64", fakeResolve).endsWith("zyrax-guard.exe"));
});

test("throws when the platform package is absent", () => {
  const fakeResolve = () => { throw new Error("Cannot find module"); };
  assert.throws(() => resolveBinary("sunos", "mips", fakeResolve));
});
