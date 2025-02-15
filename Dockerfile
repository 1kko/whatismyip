# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# python:3.10-slim already has pip. we just need to install uv
RUN pip3 install uv poetry

# Needs to install poetry plugin: export
RUN poetry self add poetry-plugin-export

# copy only the dependencies that are needed for our application and the source files
COPY poetry.lock .
COPY pyproject.toml .

RUN poetry export --without-hashes > ./requirements.txt

# install requirements using uv --system (hence no virtualenv is required)
RUN uv pip install --system -r requirements.txt

COPY *.py /app/
COPY templates /app/templates
COPY static /app/static

# Expose port 8000 for the FastAPI app to run on
EXPOSE 8000

# Command to run the FastAPI app using uvicorn
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
