#!/usr/bin/env node
// Lay out the npm wrapper packages for publishing.
// Usage: node scripts/build-npm.mjs <version> <distDir>
//   <version>  npm version, e.g. 0.7.2 (no leading v)
//   <distDir>  dir containing release binaries (zyrax-guard-<os>-<arch>[.exe])
"use strict";
import { readFileSync, writeFileSync, copyFileSync, chmodSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const [, , version, distDir] = process.argv;
if (!version || !distDir) {
  console.error("usage: node scripts/build-npm.mjs <version> <distDir>");
  process.exit(2);
}
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const npmDir = join(root, "npm");

// npm platform -> release asset basename
const PLATFORMS = {
  "linux-x64": "zyrax-guard-linux-amd64",
  "linux-arm64": "zyrax-guard-linux-arm64",
  "darwin-x64": "zyrax-guard-darwin-amd64",
  "darwin-arm64": "zyrax-guard-darwin-arm64",
  "win32-x64": "zyrax-guard-windows-amd64.exe",
  "win32-arm64": "zyrax-guard-windows-arm64.exe",
};

function stampVersion(pkgPath, mutate) {
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  pkg.version = version;
  if (mutate) mutate(pkg);
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
}

// Main package: stamp version + pin each optionalDependency to the same version.
stampVersion(join(npmDir, "zyrax-guard", "package.json"), (pkg) => {
  for (const dep of Object.keys(pkg.optionalDependencies || {})) {
    pkg.optionalDependencies[dep] = version;
  }
});

// Platform packages: stamp version + copy the binary in.
for (const [plat, asset] of Object.entries(PLATFORMS)) {
  const platDir = join(npmDir, "platforms", plat);
  stampVersion(join(platDir, "package.json"));
  const src = join(distDir, asset);
  if (!existsSync(src)) {
    console.error(`missing release asset: ${src}`);
    process.exit(1);
  }
  const isWin = plat.startsWith("win32");
  const dst = join(platDir, isWin ? "zyrax-guard.exe" : "zyrax-guard");
  copyFileSync(src, dst);
  if (!isWin) chmodSync(dst, 0o755);
  console.log(`packaged ${plat}: ${asset}`);
}
console.log(`npm wrapper staged at version ${version}`);
