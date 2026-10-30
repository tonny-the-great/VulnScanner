FROM python:3.11-slim

# Prevent Python from writing .pyc files & buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:${PATH}"

# Install OS utilities, scanning tools dependencies, Nmap, and Testssl prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    nmap \
    dnsutils \
    bsdmainutils \
    openssl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libjpeg62-turbo \
    libopenjp2-7 \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery Nuclei binary
ARG NUCLEI_VERSION=3.3.7
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then N_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then N_ARCH="arm64"; \
    else echo "Unsupported architecture: $ARCH" >&2; exit 1; fi && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${N_ARCH}.zip" -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Install testssl.sh from a release tag (the default branch is a development line)
ARG TESTSSL_VERSION=3.2.4
RUN git clone --depth 1 --branch "v${TESTSSL_VERSION}" https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl && \
    chmod +x /usr/local/bin/testssl.sh

WORKDIR /app

# Install dependencies in their own layer so source edits do not reinstall them.
# Hatch needs the README and a package directory to build, so a stub stands in.
COPY pyproject.toml README.md ./
RUN mkdir app && touch app/__init__.py && \
    pip install --no-cache-dir ".[postgres,reporting,llm]"
# Runtime integrations only; no developer or test dependencies.
COPY app ./app
RUN pip install --no-cache-dir --no-deps .

# Create uploads directory with appropriate permissions
RUN mkdir -p /app/uploads && chmod 750 /app/uploads

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
