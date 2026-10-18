# Runtime baseline: Node 24 (xtrape-docs reference/10-runtime-baseline.md §1).
# This must stay in lockstep with package.json `engines.node` and the CI job
# container image — the three declarations are one decision, not three.
FROM node:24-bookworm AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.28.2 --activate
COPY package.json pnpm-lock.yaml .npmrc ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
RUN pnpm build && pnpm prune --prod

FROM node:24-bookworm-slim
ENV NODE_ENV=production \
    LINUX_OPS_WIDGET_CONF_DIR=/app/conf \
    LINUX_OPS_WIDGET_LOG_DIR=/app/logs \
    LINUX_OPS_WIDGET_DATA_DIR=/app/data
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN useradd --system --home /app --shell /usr/sbin/nologin linux-ops \
    && mkdir -p /app/conf /app/logs /app/data \
    && chown -R linux-ops:linux-ops /app/conf /app/logs /app/data
USER linux-ops
ENTRYPOINT ["node", "dist/index.js"]
