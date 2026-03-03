# Demo Vulnerable Dockerfile — DevSecOps AI Team
# Contains INTENTIONAL security issues for container scanning demos.
# DO NOT use in production.
#
# Expected findings:
#   - Outdated base image (node:14 is EOL)
#   - No USER directive (runs as root)
#   - No HEALTHCHECK defined
#   - COPY . . without .dockerignore (may leak secrets)
#   - Using latest tag implicitly for pip packages

# VULNERABLE: node:14 is end-of-life, has known CVEs
FROM node:14

# VULNERABLE: no explicit non-root user — container runs as root
WORKDIR /app

# VULNERABLE: copies everything including potential .env files
COPY . .

# Install Node dependencies
RUN npm install --production

# Install Python dependencies without pinned versions
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip3 install flask requests && \
    rm -rf /var/lib/apt/lists/*

# VULNERABLE: exposes port but no HEALTHCHECK defined
EXPOSE 5000

# VULNERABLE: debug mode in production, runs as root
CMD ["python3", "app.py"]
