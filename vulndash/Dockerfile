FROM ghcr.io/home-assistant/base:latest

ARG BUILD_VERSION=0.1.0
ARG BUILD_ARCH=amd64

LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache python3 py3-sqlite3

WORKDIR /app
COPY server.py index.html /app/
COPY assets/ /app/assets/
COPY run.sh /run.sh
RUN chmod a+x /run.sh && mkdir -p /data

EXPOSE 8099
CMD ["/run.sh"]
