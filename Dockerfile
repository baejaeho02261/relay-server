FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production PORT=8080 WEB_ADMIN_PORT=8080 CONNECT_TCP_PORT=3000 DATA_DIR=/data HA_ENABLED=0
EXPOSE 8080 3000
CMD ["node", "server.js"]
