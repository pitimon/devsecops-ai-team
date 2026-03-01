FROM alpine:3.19

# DevSecOps AI Team — Sidecar Runner
# Orchestrates security tool containers via Docker CLI

# Install Docker CLI + dependencies
RUN apk add --no-cache \
    docker-cli \
    docker-cli-compose \
    bash \
    curl \
    jq \
    tini \
    python3 \
    && addgroup -S runner \
    && adduser -S runner -G runner

# Create directory structure
RUN mkdir -p /workspace /results /config /cache \
    && chown -R runner:runner /results /cache

# Copy scripts
COPY --chown=runner:runner entrypoint.sh /usr/local/bin/
COPY --chown=runner:runner job-dispatcher.sh /usr/local/bin/
COPY --chown=runner:runner result-collector.sh /usr/local/bin/
COPY --chown=runner:runner healthcheck.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/*.sh

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Non-root user
USER runner

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/entrypoint.sh"]
