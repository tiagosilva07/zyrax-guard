"use strict";
const path = require("node:path");

// resolveBinary returns the absolute path to the platform binary for the given
// platform (process.platform) and arch (process.arch). `resolve` maps a package
// specifier to an absolute path (defaults to require.resolve); injectable for tests.
function resolveBinary(platform, arch, resolve = require.resolve) {
  const pkg = `zyrax-guard-${platform}-${arch}`;
  const exe = platform === "win32" ? "zyrax-guard.exe" : "zyrax-guard";
  const pkgJsonPath = resolve(`${pkg}/package.json`);
  return path.join(path.dirname(pkgJsonPath), exe);
}

module.exports = { resolveBinary };
