FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    clang llvm iproute2 iputils-ping libelf-dev gcc make curl git && \
    curl -LO https://go.dev/dl/go1.22.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz && \
    rm go1.22.2.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app
COPY . .

RUN go mod download && \
    go generate && \
    go build -o demo

CMD ["./demo"]