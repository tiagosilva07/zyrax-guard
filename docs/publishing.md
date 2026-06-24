# Publishing: npm + MCP registry

Guard's CLI/MCP server is distributed on npm (the `zyrax-guard` package plus six unscoped
`zyrax-guard-<platform>-<arch>` binary packages) and listed on the official MCP registry as
`io.github.tiagosilva07/zyrax-guard`. Publishing runs from `.github/workflows/publish-npm.yml`
when a GitHub Release is published — but only once the prerequisites below exist (the workflow
no-ops otherwise).

## One-time setup
1. **npm token.** A personal npm account is enough — the platform packages are unscoped, so
   **no npm org is required**. Create an **Automation** token (bypasses 2FA for CI) with
   publish rights, and add it as the repo secret **`NPM_TOKEN`**. The first publish claims
   `zyrax-guard` and the six `zyrax-guard-*` names.
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
# MCP registry — pin mcp-publisher to a version and verify its checksum (never use /releases/latest).
# Look up the checksum in registry_<ver>_checksums.txt on the release, then:
MCP_PUB=v1.7.9
curl -fsSL -o mcp-publisher.tar.gz "https://github.com/modelcontextprotocol/registry/releases/download/${MCP_PUB}/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz"
# verify: echo "<sha256>  mcp-publisher.tar.gz" | sha256sum -c -
tar xzf mcp-publisher.tar.gz mcp-publisher && rm -f mcp-publisher.tar.gz
node -e "const fs=require('fs');const s=JSON.parse(fs.readFileSync('server.json','utf8'));s.version='$VERSION';s.packages[0].version='$VERSION';fs.writeFileSync('server.json',JSON.stringify(s,null,2)+'\n')"
./mcp-publisher login github      # or: ./mcp-publisher login github-oidc (in CI)
./mcp-publisher publish
```

## Homebrew tap
The CLI is also distributed through a Homebrew tap, `tiagosilva07/homebrew-zyrax`
(`brew install tiagosilva07/zyrax/zyrax-guard`). The formula is a prebuilt-binary formula
pinned to a release with per-platform SHA-256 from `checksums.txt`.

- **One-time:** create a token with `contents:write` on `tiagosilva07/homebrew-zyrax` (a
  fine-grained PAT scoped to that repo) and add it as the repo secret **`HOMEBREW_TAP_TOKEN`**.
- **Per release (automated):** `.github/workflows/homebrew-bump.yml` regenerates the formula
  from the release checksums and pushes it to the tap. No-ops until the secret exists.
- **Manual bump:**
  ```bash
  VERSION=0.7.2
  mkdir -p dist
  gh release download "v$VERSION" --repo tiagosilva07/zyrax-guard --dir dist --pattern 'checksums.txt'
  node scripts/gen-homebrew-formula.mjs "$VERSION" dist/checksums.txt Formula/zyrax-guard.rb
  # commit Formula/zyrax-guard.rb to the tiagosilva07/homebrew-zyrax repo
  ```

## Version sync
The npm package version, all `zyrax-guard-*` platform-package versions, and both `server.json` versions must
equal the release version. `build-npm.mjs` and the workflow handle this automatically; for a
manual publish, keep them in sync.
