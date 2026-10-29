# frontend image -- Vite/React static build, served by nginx.
#
# Build context is the WHOLE repo root, not frontend/. Every COPY below is
# written relative to that root, not to this directory.
FROM node:22-bookworm-slim AS build
WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .

# Addresses baked into the build (the browser calls the backend directly). docker-compose.yml
# passes these; the defaults suit a backend published on this machine at port 4000.
ARG VITE_API_BASE_URL=http://localhost:4000
ARG VITE_WINDOWS_AGENT_INSTALLER_URL=
ARG VITE_LINUX_AGENT_INSTALLER_URL=
ARG VITE_DEPLOYMENT_MODE=on_prem
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_WINDOWS_AGENT_INSTALLER_URL=$VITE_WINDOWS_AGENT_INSTALLER_URL \
    VITE_LINUX_AGENT_INSTALLER_URL=$VITE_LINUX_AGENT_INSTALLER_URL \
    VITE_DEPLOYMENT_MODE=$VITE_DEPLOYMENT_MODE
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
