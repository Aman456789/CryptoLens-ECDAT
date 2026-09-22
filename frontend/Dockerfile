# Stage 1 — build the CRA static bundle
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY public/ ./public/
COPY src/ ./src/
# REACT_APP_* vars are baked into the JS bundle at BUILD time by CRA (they
# have no effect if set as a runtime `environment:` on the container) — so
# this must be passed as a docker-compose build ARG, not an env var. Default
# is empty: with Caddy routing /api/* to the backend and everything else to
# this container on the SAME origin (see ../Caddyfile), api.js's axios
# client should make relative requests like `/api/assets`, not prefix them
# with a second base path (that would produce `/api/api/assets`).
ARG REACT_APP_API_BASE_URL=""
ENV REACT_APP_API_BASE_URL=$REACT_APP_API_BASE_URL
RUN npm run build

# Stage 2 — serve the static bundle
FROM nginx:1.27-alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
