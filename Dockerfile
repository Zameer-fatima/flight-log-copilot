# Public showcase image. Build:  docker build -t flight-log-copilot .
# Run:                           docker run --rm -p 8000:8000 flight-log-copilot
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 FLC_DEMO=1 PORT=8000
WORKDIR /srv/app

COPY requirements-demo.txt .
RUN pip install --no-cache-dir -r requirements-demo.txt

COPY app ./app
COPY sample_data ./sample_data

# run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "python -m app.web --demo --host 0.0.0.0 --port ${PORT}"]
