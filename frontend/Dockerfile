# NeuroBots dashboard. Multi-stage: Node builds the bundle, nginx serves it.
# The runtime image carries no Node, no npm and no source - just static files
# behind a web server, which is a far smaller attack surface for the one
# container in this stack that is meant to be reachable from a browser.
#
# Build context is the REPO ROOT - see docker-compose.yml.

# ---------------------------------------------------------------- build stage
FROM node:20-alpine AS build

WORKDIR /app

# IMPORTANT: Vite inlines VITE_* variables into the bundle at BUILD time. They
# are not read at runtime, so passing them as compose `environment:` entries
# does nothing - they have to arrive as build args. This is the single most
# common way this image gets misconfigured.
ARG VITE_GATEWAY_URL=http://127.0.0.1:8080
ARG VITE_ADMIN_KEY=changeme-admin-key
ARG VITE_POLL_INTERVAL=2000
ENV VITE_GATEWAY_URL=$VITE_GATEWAY_URL \
    VITE_ADMIN_KEY=$VITE_ADMIN_KEY \
    VITE_POLL_INTERVAL=$VITE_POLL_INTERVAL

# package-lock.json is committed, so `npm ci` gives a reproducible install and
# fails loudly if the lockfile and package.json have drifted apart.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build

# -------------------------------------------------------------- runtime stage
FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# nginx:alpine ships an unprivileged `nginx` user but runs its master as root to
# bind :80. Serving on 8080 instead lets the whole process tree drop to that
# user, since ports above 1024 need no capability.
RUN touch /var/run/nginx.pid \
    && chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx /usr/share/nginx/html
USER nginx

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider -q http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
