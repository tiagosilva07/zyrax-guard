#!/usr/bin/env node
"use strict";
const { spawnSync } = require("node:child_process");
const { resolveBinary } = require("../lib/resolve.js");

let bin;
try {
  bin = resolveBinary(process.platform, process.arch);
} catch {
  console.error(
    `zyrax-guard: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `Install a release binary from https://github.com/tiagosilva07/zyrax-guard/releases ` +
      `or run: go install github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest`
  );
  process.exit(1);
}

const res = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (res.error) {
  console.error(`zyrax-guard: failed to launch binary: ${res.error.message}`);
  process.exit(1);
}
if (res.signal) {
  process.kill(process.pid, res.signal);
} else {
  process.exit(res.status === null ? 1 : res.status);
}
