# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/pathlab ./cmd/pathlab

# Runtime (distroless-like)
FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/pathlab /app/pathlab
EXPOSE 10443 8080
ENV PATHLAB_LISTEN=:10443
ENV PATHLAB_ADMIN=:8080
CMD ["/app/pathlab"]
