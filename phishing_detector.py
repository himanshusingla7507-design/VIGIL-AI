"""Compatibility facade; all prediction decisions live in service.py."""
from service import load_model_bundle, scan

def predict_url(url): return scan(url)
def check_phishing(url):
    try: return scan(url)
    except Exception as exc: return {"url": url or "", "label": "ERROR", "error": str(exc)}

__all__ = ["scan", "predict_url", "check_phishing", "load_model_bundle"]
