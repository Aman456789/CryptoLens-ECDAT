"""
predictor.py

Runs the DistilRoBERTa binary classifier that filters Semgrep's
rule-based findings down to genuine cryptographic vulnerabilities,
discarding benign pattern matches (e.g. an image checksum that happens
to look like a hash call).

Loaded strictly from a local, offline directory — never from the
Hugging Face Hub at runtime. The weights are baked into the container
image at build time (see Dockerfile), and TRANSFORMERS_OFFLINE=1 is set
so any accidental network call the library might attempt fails loudly
and immediately instead of hanging, which matters for an air-gapped
NTRO deployment.
"""

import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = os.environ.get("MODEL_DIR", "/models/distilroberta")

# Class index convention for this fine-tuned checkpoint:
#   0 -> False Alarm (benign pattern, not a real cryptographic weakness)
#   1 -> True Threat  (confirmed vulnerable pattern)
LABELS = {0: "False Alarm", 1: "True Threat"}


class CryptoThreatPredictor:
    """
    Thin, CPU-only inference wrapper. Instantiated once at process
    startup (see main.py) and reused across requests — reloading the
    model per-request would defeat the point of running this as a
    long-lived microservice.
    """

    def __init__(self, model_dir: str = MODEL_DIR):
        # torch.set_num_threads is left to PyTorch's default here; tune
        # explicitly if this container is pinned to a specific CPU quota.
        self.device = torch.device("cpu")

        self.tokenizer = AutoTokenizer.from_pretrained(
            model_dir, local_files_only=True
        )
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_dir, local_files_only=True
        )
        self.model.to(self.device)
        self.model.eval()  # inference mode — disables dropout etc.

    @torch.no_grad()
    def predict(self, snippet: str) -> dict:
        """
        Args:
            snippet: the windowed code context produced by chunking.py.

        Returns:
            {
              "verdict": 0 | 1,
              "label": "False Alarm" | "True Threat",
              "confidence": float,   # softmax probability of the chosen class
            }
        """
        if not snippet or not snippet.strip():
            return {"verdict": 0, "label": LABELS[0], "confidence": 0.0}

        inputs = self.tokenizer(
            snippet,
            return_tensors="pt",
            truncation=True,
            max_length=512,  # hard ceiling — chunking.py should already
                              # keep windows well under this, but this is
                              # the final safety net against a tokenizer crash
            padding=True,
        ).to(self.device)

        logits = self.model(**inputs).logits
        probs = torch.softmax(logits, dim=-1).squeeze(0)

        verdict = int(torch.argmax(probs).item())
        confidence = float(probs[verdict].item())

        return {
            "verdict": verdict,
            "label": LABELS.get(verdict, "Unknown"),
            "confidence": round(confidence, 4),
        }


# Module-level singleton — main.py imports and reuses this instance
# rather than constructing a new predictor per request.
predictor = CryptoThreatPredictor()
