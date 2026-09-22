FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake model weights in at BUILD time, while the CI/build environment still
# has internet access — the running container never needs network access
# to Hugging Face again (required for an air-gapped NTRO deployment; see
# whitepaper Section 13, "Air-Gapped Deployment Consideration").
# NOTE: this must match predictor.py's default MODEL_DIR ("/models/distilroberta")
# and use AutoModelForSequenceClassification, not AutoModel — predictor.py
# calls .from_pretrained() for classification, and the two classes save/load
# different config shapes.
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
    AutoTokenizer.from_pretrained('distilroberta-base').save_pretrained('/models/distilroberta'); \
    AutoModelForSequenceClassification.from_pretrained('distilroberta-base', num_labels=2).save_pretrained('/models/distilroberta')"

ENV TRANSFORMERS_OFFLINE=1
ENV MODEL_DIR=/models/distilroberta

COPY app/ ./app/

# Intentionally NO "ports:" mapping in docker-compose.yml for this service —
# it must stay unreachable from the host or the public internet, reachable
# only via Docker's internal DNS from the backend container (Patch 3).
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
