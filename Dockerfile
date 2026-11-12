FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishgraph/ phishgraph/
COPY api/ api/
COPY models/ models/

ENV PORT=8000
EXPOSE 8000
# Render / Hugging Face Spaces / Railway set $PORT; locally it defaults to 8000
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]
