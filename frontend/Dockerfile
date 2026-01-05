# frontend/Dockerfile
# Stage 1 — build
FROM node:18-alpine AS build
WORKDIR /usr/src/app

# Prevent node_modules from being copied if present on host
COPY package.json package-lock.json ./
RUN npm ci --production=false

# Copy source, build
COPY . .
ARG REACT_APP_API_URL
ENV REACT_APP_API_URL=${REACT_APP_API_URL:-http://backend:5000}
RUN npm run build

# Stage 2 — nginx
FROM nginx:stable-alpine AS runtime
LABEL org.opencontainers.image.source="AgroConnect-Frontend"

# Remove default nginx static files
RUN rm -rf /usr/share/nginx/html/*

# Copy built files
COPY --from=build /usr/src/app/build /usr/share/nginx/html

# Copy custom nginx config (optional). If you don't have one, default will work.
# COPY nginx.conf /etc/nginx/conf.d/default.conf

# Healthcheck for Compose
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- --timeout=2 http://localhost/ || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
