FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
# Debian snapshot indexes are signed; package hashes are checked by apt.
# Keep the timestamp immutable and refresh only in a reviewed dependency change.
RUN node -e "require('fs').writeFileSync('/tmp/peace-bootstrap-ca.pem',require('tls').rootCertificates.join('\n'))" \
 && rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261023T000000Z bookworm main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261023T000000Z bookworm-security main' > /etc/apt/sources.list \
 && apt-get -o Acquire::https::CaInfo=/tmp/peace-bootstrap-ca.pem -o APT::Update::Error-Mode=any update \
 && apt-get -o Acquire::https::CaInfo=/tmp/peace-bootstrap-ca.pem install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* /tmp/peace-bootstrap-ca.pem
# Relay-only repository: the build context is this repository root.
# Native source archives require a separate private full-source deployment.
WORKDIR /app/cozy-peace/Relay Server
COPY ["package.json", "package-lock.json", "./"]
# better-sqlite3 13 ships N-API prebuilds for linux-x64/arm64; no
# runtime compiler or install-time GitHub binary download is needed.
# Avoid npm auto-detecting binding.gyp on a clean lockfile install. All pinned
# runtime dependencies are script-free; the SQL smoke check loads the real addon.
RUN npm ci --omit=dev --ignore-scripts && node -e "const D=require('better-sqlite3');const d=new D(':memory:');d.prepare('SELECT 1').get();d.close();"
COPY ["./", "/app/cozy-peace/Relay Server/"]
RUN node tools/build/peace.verify-relay-source.js && node tests/runtime/peace.test-railway-process-lifecycle.js && node tests/diagnostics/peace.test-support-captures.js && node tests/diagnostics/peace.test-support-capture-context.js && node tests/diagnostics/peace.test-support-captures-http.js && node --test tests/cryptography/peace.test-crc-collision-vectors.js tests/security/peace.test-server-authority-bypass.js tests/bootstrap/peace.test-keyless-bootstrap.js tests/security/peace.test-server-policy-registry.js tests/runtime/peace.test-server-policy-worker.js tests/runtime/peace.test-worker-result-ownership.js tests/security/peace.test-server-policy-operations.js tests/integrity/peace.test-owned-pointer-graph.js tests/integrity/peace.test-authority-measurement-security.js tests/overlay/peace.test-cohort-retirement.js tests/bootstrap/peace.test-issued-a-signing.js tests/integrity/peace.test-pointer-graph-lifecycle.js tests/licensing/peace.test-desktop-members.js tests/protocol/peace.test-document-schema.js
ENV NODE_ENV=production
CMD ["node", "peace.relay-server.js"]
