FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
# better-sqlite3 13 ships N-API prebuilds for linux-x64/arm64; no
# runtime compiler or install-time GitHub binary download is needed.
# Avoid npm auto-detecting binding.gyp on a clean lockfile install. All pinned
# runtime dependencies are script-free; the SQL smoke check loads the real addon.
RUN npm ci --omit=dev --ignore-scripts && node -e "const D=require('better-sqlite3');const d=new D(':memory:');d.prepare('SELECT 1').get();d.close();"
COPY . .
ENV NODE_ENV=production PORT=8080 WEB_ADMIN_PORT=8080 CONNECT_TCP_PORT=3000 DATA_DIR=/data HA_ENABLED=0
EXPOSE 8080 3000
CMD ["node", "server.js"]
