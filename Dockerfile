FROM alpine:3.6 as scanner_builder

ENV VERSION 1.4.0

RUN apk add --no-cache \
      curl \
      musl-dev \
      && :

RUN apk add --no-cache -X http://dl-4.alpinelinux.org/alpine/edge/community \
      'go>=1.8.4-r0' \
      && :

RUN apk add --no-cache -X http://dl-4.alpinelinux.org/alpine/edge/main \
      'ca-certificates>=20170801-r0' \
      && :


# https://github.com/golang/go/issues/9344#issuecomment-69944514
RUN cd /tmp && \
    curl -sSLO https://github.com/ssllabs/ssllabs-scan/archive/v${VERSION}.tar.gz && \
    tar xvzf v${VERSION}.tar.gz && \
    cd ssllabs-scan-${VERSION} && \
    GOPATH=~ \
    CGO_ENABLED=0 \
    GOOS=linux \
    LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LIBRARY_PATH \
    go build \
      -a \
      -tags netgo \
      -ldflags '-extldflags "-static" -s' \
      -buildmode exe \
      ssllabs-scan.go

#
# Build the runtime image.
#
FROM visheyra/angler-base-image:latest

ADD requirements.txt /tmp

RUN apk add --no-cache python3 && python3 -m ensurepip && pip3 install -r /tmp/requirements.txt

WORKDIR "/app"
RUN apk add --no-cache ca-certificates
ENV VERSION 1.4.0
COPY --from=scanner_builder /tmp/ssllabs-scan-${VERSION}/ssllabs-scan /app
ADD app/main.py /app
ENV PLUGIN_COMMAND "python3 main.py"