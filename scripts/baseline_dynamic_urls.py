"""Run a fixed, offline baseline for legitimate dynamic URLs."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from service import scan


URLS = [
    "https://www.google.com/search?q=phishing+prevention",
    "https://www.bing.com/search?q=phishing+prevention",
    "https://www.youtube.com/results?search_query=phishing+prevention",
    "https://github.com/microsoft/vscode",
    "https://github.com/search?q=python+url+parser&type=repositories",
    "https://www.amazon.com/s?k=usb+c+hub",
    "https://learn.microsoft.com/en-us/python/",
    "https://stackoverflow.com/questions/tagged/python",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://www.reddit.com/r/cybersecurity/",
    "https://accounts.google.com/signin/v2/identifier",
    "https://www.google.com/search?q=security+news&utm_source=baseline&utm_medium=organic",
    "https://www.bing.com/search?q=python&count=20&form=QBLH&sp=-1",
    "https://en.wikipedia.org/wiki/URL#Components",
    "https://www.google.com/search?q=URL%20encoding%20examples",
    "https://www.google.com/search?q=legitimate+dynamic+url+baseline+with+a+deliberately+long+query+containing+several+ordinary+words+for+testing+how+the+production+model+responds+to+long+search+queries",
]


def main() -> None:
    results = []
    for url in URLS:
        result = scan(url)
        results.append(
            {
                "url": url,
                "probability": result["probability"],
                "label": result["label"],
                "model_version": result["model_version"],
            }
        )

    total = len(results)
    summary = {
        "total": total,
        "SAFE": sum(row["label"] == "SAFE" for row in results),
        "SUSPICIOUS": sum(row["label"] == "SUSPICIOUS" for row in results),
        "PHISHING": sum(row["label"] == "PHISHING" for row in results),
        "average_probability": round(
            sum(row["probability"] for row in results) / total, 6
        ),
        "maximum_probability": max(row["probability"] for row in results),
    }

    report_path = ROOT / "reports" / "baseline_dynamic_legitimate.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump({"summary": summary, "results": results}, report_file, indent=2)
        report_file.write("\n")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()