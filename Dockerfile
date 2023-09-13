FROM alpine:latest as builder

RUN apk update && apk add --no-cache build-base curl-dev cmake openssl-dev
COPY . .
RUN cmake -S . -B ./build
RUN cmake --build ./build -j $(nproc)

FROM alpine:latest
COPY --from=builder /build/tenebrastakenode .
RUN apk update && apk add --no-cache libcurl ca-certificates libstdc++ libgcc
ENTRYPOINT ["/tenebrastakenode"]