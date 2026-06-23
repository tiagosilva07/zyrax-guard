# Publishing: npm + MCP registry

Guard's CLI/MCP server is distributed on npm (`zyrax-guard` + `@zyrax-guard/*` platform
packages) and listed on the official MCP registry as `io.github.tiagosilva07/zyrax-guard`.
Publishing runs from `.github/workflows/publish-npm.yml` when a GitHub Release is published —
but only once the prerequisites below exist (the workflow no-ops otherwise).

## One-time setup
1. **npm org + token.** Create an npm org named `zyrax-guard` (gives the `@zyrax-guard`
   scope used by the platform packages). Create an **automation** token with publish rights
   to `zyrax-guard` and `@zyrax-guard/*`, and add it as the repo secret **`NPM_TOKEN`**.
2. **MCP registry.** No secret needed — the workflow authenticates with GitHub OIDC
   (`id-token: write`). The registry trusts the `io.github.tiagosilva07/*` namespace from this
   repo's OIDC identity. (First-time only, you may run `mcp-publisher login github` locally once
   to confirm the namespace is claimable by your GitHub account.)

## Per release (automated)
Cut a release tag `vX.Y.Z` (the existing release workflow builds + signs the binaries and
creates the GitHub Release). When the Release is *published*, `publish-npm.yml`:
1. downloads the release binaries,
2. runs `node scripts/build-npm.mjs <version> dist` to stamp versions and stage binaries,
3. `npm publish` the 6 platform packages then the main package (with `--provenance`),
4. stamps `server.json` to the version and runs `mcp-publisher publish`.

## Manual fallback
```bash
VERSION=0.7.2
mkdir -p dist
gh release download "v$VERSION" --repo tiagosilva07/zyrax-guard --dir dist --pattern 'zyrax-guard-*'
node scripts/build-npm.mjs "$VERSION" dist
for d in npm/platforms/*/; do npm publish "$d" --access public --provenance; done
npm publish npm/zyrax-guard --access public --provenance
# MCP registry:
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz mcp-publisher
node -e "const fs=require('fs');const s=JSON.parse(fs.readFileSync('server.json','utf8'));s.version='$VERSION';s.packages[0].version='$VERSION';fs.writeFileSync('server.json',JSON.stringify(s,null,2)+'\n')"
./mcp-publisher login github      # or: ./mcp-publisher login github-oidc (in CI)
./mcp-publisher publish
```

## Version sync
The npm package version, all `@zyrax-guard/*` versions, and both `server.json` versions must
equal the release version. `build-npm.mjs` and the workflow handle this automatically; for a
manual publish, keep them in sync.
