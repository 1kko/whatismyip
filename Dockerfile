# Use an official Python runtime as a parent image.
# Pinned to the multi-arch manifest digest for supply-chain reproducibility;
# Dependabot keeps this up to date.
FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286

# Set the working directory in the container
WORKDIR /app

# python:3.12-slim already has pip. we just need to install uv
RUN pip3 install uv poetry

# Needs to install poetry plugin: export
RUN poetry self add poetry-plugin-export

# copy only the dependencies that are needed for our application and the source files
COPY poetry.lock .
COPY pyproject.toml .

RUN poetry export > ./requirements.txt

# install requirements using uv --system with hash verification
RUN uv pip install --system --require-hashes -r requirements.txt

RUN useradd -m -r appuser

COPY *.py /app/
COPY templates /app/templates
COPY static /app/static

RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser

# The commit being built, for /healthz "version" and OTel service.version.
# Coolify also sets SOURCE_COMMIT in the runtime environment on every deploy,
# which takes precedence over this; the build arg only arrives with Coolify's
# "Include Source Commit in Build" on, or from a manual
# `docker build --build-arg SOURCE_COMMIT=$(git rev-parse HEAD)`. Declared
# after the dependency layers: its value changes on every commit and would
# otherwise invalidate their cache.
ARG SOURCE_COMMIT=""
ENV SOURCE_COMMIT=${SOURCE_COMMIT}

# Expose port 8000 for the FastAPI app to run on
EXPOSE 8000

# Liveness probe using only the Python stdlib (no extra install).
# Succeeds when uvicorn is bound to 8000; start-period covers the
# first-boot GeoLite2 download.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 8000))"

# Command to run the FastAPI app using uvicorn, wrapped with OpenTelemetry.
# The SDK builds its Resource inside opentelemetry-instrument, before main.py is
# imported, so service.version can only arrive through OTEL_RESOURCE_ATTRIBUTES.
# The commit is appended to whatever the operator set there rather than
# replacing it: the SDK lets the last duplicate key win, so it overrides a
# static service.version and keeps every other attribute
# (deployment.environment, ...). The shell then execs the command after "sh"
# ($0), which leaves uvicorn as PID 1 to receive SIGTERM.
ENTRYPOINT ["/bin/sh", "-c", "if [ -n \"$SOURCE_COMMIT\" ]; then export OTEL_RESOURCE_ATTRIBUTES=\"${OTEL_RESOURCE_ATTRIBUTES:+$OTEL_RESOURCE_ATTRIBUTES,}service.version=$SOURCE_COMMIT\"; fi; exec \"$@\"", \
            "sh", \
            "opentelemetry-instrument", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
