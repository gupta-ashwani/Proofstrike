# syntax=docker/dockerfile:1
#
# ProofStrike frontend — build the React/Vite app, serve the static bundle with Nginx,
# and proxy /api to the backend service (so the browser sees one same-origin host).

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build          # -> /app/dist

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
