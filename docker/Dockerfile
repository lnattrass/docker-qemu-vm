FROM alpine:latest

RUN apk add --update --no-cache \
  jq \
  bash \
  wget \
  curl \
  socat \
  cdrkit \
  procps \
  python3 \
  py3-pip \
  iproute2 \
  qemu-img \
  moreutils \
  util-linux \
  ca-certificates \
  qemu-system-x86_64

RUN curl -fsSo /usr/local/bin/mc https://dl.min.io/client/mc/release/linux-amd64/mc \
  && chmod +x /usr/local/bin/mc \
  && pip3 install click pyyaml humanfriendly logbook pyroute2

ADD tree/ /
WORKDIR /vm

ENTRYPOINT ["/vm/entrypoint.py"]
