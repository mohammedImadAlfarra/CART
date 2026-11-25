# CART — ML-based malicious-request detection + security scanner
# OPTIONAL packaging. The project also runs with plain `python run.py`;
# deleting this file (and docker-compose.yml) changes nothing about that.
#
# Inside the container CART needs no GPU and no API keys. It trains the ML
# models, starts the 4 vulnerable lab targets (on localhost inside the
# container) and runs the scan.

FROM python:3.12-slim

# keep Python output unbuffered and skip .pyc files
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy the project
COPY . .

# the run writes its HTML/JSON report here; mount it to read results on the host
VOLUME ["/app/reports"]

# default: the full run (ML + scan + report)
CMD ["python", "run.py"]
