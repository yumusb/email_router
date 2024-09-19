FROM golang:1.23.1 AS build-stage
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/main

FROM alpine:latest AS build-release-stage
WORKDIR /app
COPY --from=build-stage /app/main /app/main
ENTRYPOINT ["/app/main"]