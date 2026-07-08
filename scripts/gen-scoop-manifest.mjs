#!/usr/bin/env node
// Generate the scoop manifest for zyrax-guard from a release checksums.txt.
// Usage: node scripts/gen-scoop-manifest.mjs <version> <checksums.txt> [outFile]
//   <version>  release version WITHOUT leading v, e.g. 0.11.0
//   <checksums.txt>  the release checksums file (sha256<sp><sp>asset per line)
//   [outFile]  write here; otherwise stdout
"use strict";
import { readFileSync, writeFileSync } from "node:fs";

const [, , version, checksumsPath, outFile] = process.argv;
if (!version || !checksumsPath) {
  console.error("usage: node scripts/gen-scoop-manifest.mjs <version> <checksums.txt> [outFile]");
  process.exit(2);
}

const checksums = readFileSync(checksumsPath, "utf8");
function sha(asset) {
  for (const line of checksums.split("\n")) {
    const m = line.trim().match(/^([0-9a-f]{64})\s+(.+)$/);
    if (m && m[2] === asset) return m[1];
  }
  console.error(`checksum not found for ${asset} in ${checksumsPath}`);
  process.exit(1);
}

const base = `https://github.com/tiagosilva07/zyrax-guard/releases/download/v${version}`;
// The `#/zyrax-guard.exe` URL fragment tells scoop to save the asset under
// that name, so `bin` stays stable across releases.
const manifest = {
  version,
  description:
    "Audit AI agent configs (prompt injection, rogue MCP servers) and vet packages — local, zero-dependency",
  homepage: "https://zyrax.io",
  license: "MIT",
  architecture: {
    "64bit": {
      url: `${base}/zyrax-guard-windows-amd64.exe#/zyrax-guard.exe`,
      hash: sha("zyrax-guard-windows-amd64.exe"),
    },
    arm64: {
      url: `${base}/zyrax-guard-windows-arm64.exe#/zyrax-guard.exe`,
      hash: sha("zyrax-guard-windows-arm64.exe"),
    },
  },
  bin: "zyrax-guard.exe",
  checkver: { github: "https://github.com/tiagosilva07/zyrax-guard" },
  // The scoop-bump workflow regenerates this file on every release, but the
  // autoupdate block keeps the manifest usable with scoop's own excavator too.
  autoupdate: {
    architecture: {
      "64bit": {
        url: "https://github.com/tiagosilva07/zyrax-guard/releases/download/v$version/zyrax-guard-windows-amd64.exe#/zyrax-guard.exe",
        hash: {
          url: "https://github.com/tiagosilva07/zyrax-guard/releases/download/v$version/checksums.txt",
          regex: "([a-fA-F0-9]{64})\\s+zyrax-guard-windows-amd64\\.exe",
        },
      },
      arm64: {
        url: "https://github.com/tiagosilva07/zyrax-guard/releases/download/v$version/zyrax-guard-windows-arm64.exe#/zyrax-guard.exe",
        hash: {
          url: "https://github.com/tiagosilva07/zyrax-guard/releases/download/v$version/checksums.txt",
          regex: "([a-fA-F0-9]{64})\\s+zyrax-guard-windows-arm64\\.exe",
        },
      },
    },
  },
};

const out = JSON.stringify(manifest, null, 2) + "\n";
if (outFile) writeFileSync(outFile, out);
else process.stdout.write(out);
