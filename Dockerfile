# Use an official Python runtime as a parent image.
# Pinned to the multi-arch manifest digest for supply-chain reproducibility;
# Dependabot keeps this up to date.
FROM python:3.14-slim@sha256:bc389f7dfcb21413e72a28f491985326994795e34d2b86c8ae2f417b4e7818aa

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

# Expose port 8000 for the FastAPI app to run on
EXPOSE 8000

# Liveness probe using only the Python stdlib (no extra install).
# Succeeds when uvicorn is bound to 8000; start-period covers the
# geoip2fast DB download at boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 8000))"

# Command to run the FastAPI app using uvicorn, wrapped with OpenTelemetry
ENTRYPOINT ["opentelemetry-instrument", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
