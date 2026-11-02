FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY kuberhound.py k8s_client.py bloodhound_client.py redact.py query_bloodhound.py \
     CustomNodes.json kuberhound_queries.json ./
COPY collectors/ collectors/
COPY edges/ edges/

USER 10001:10001

ENTRYPOINT ["python3", "kuberhound.py"]
