# vault-web-client: compila con Vite y sirve el resultado con nginx.
# Requiere que exista el proyecto Vite (package.json) — ver client/README.md
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
