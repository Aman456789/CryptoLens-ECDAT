# backend/Dockerfile
#
# Production image for the ECDAT Express API gateway. This is the only
# service in the stack that publishes a port at all (see
# docker-compose.yml) — everything else is reached via ecdat-net only.

FROM node:18-alpine

WORKDIR /app

# Copy manifest files first so `npm ci` is cached separately from the
# rest of the source — source-only changes won't force a full reinstall.
COPY package.json package-lock.json* ./

RUN apk add --no-cache python3 py3-pip nmap && \
    pip3 install semgrep --break-system-packages

# Production-only install: no devDependencies (nodemon, etc.) in the
# shipped image.
RUN npm install --omit=dev

COPY src/ ./src/

ENV NODE_ENV=production

# Matches the port backend listens on and the `expose: ["5000"]` entry
# in docker-compose.yml — not published to the host directly, only
# reachable from other containers on ecdat-net (Caddy proxies to it).
EXPOSE 5000

CMD ["node", "src/server.js"]
