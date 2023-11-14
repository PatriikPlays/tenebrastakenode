FROM alpine:latest as builder

RUN apk update && apk add --no-cache build-base cmake openssl-dev zlib-dev
COPY . .
RUN cmake -DCMAKE_BUILD_TYPE=RELEASE -S . -B ./build
RUN cmake --build ./build -j $(nproc)

FROM alpine:latest
COPY --from=builder /build/tenebrastakenode .
RUN apk update && apk add --no-cache ca-certificates libstdc++ libgcc

RUN adduser --uid 1000 --disabled-password --gecos "" nonroot
USER nonroot

ENTRYPOINT ["/tenebrastakenode"]