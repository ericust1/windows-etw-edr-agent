FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulate_events.py .
COPY ../../src ./src

CMD ["python", "simulate_events.py"]
