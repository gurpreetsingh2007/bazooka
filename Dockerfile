FROM node:22-alpine AS frontend
WORKDIR /ui
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM golang:1.23-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY backend ./backend
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/bazooka ./backend

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /
COPY --from=backend /out/bazooka /bazooka
COPY --from=frontend /ui/dist /web
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/bazooka"]
