import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import scan

ROOT = Path(__file__).resolve().parents[1]
rows = []
with (ROOT / "validation_urls.csv").open(newline="", encoding="utf-8") as f:
    for item in csv.DictReader(f):
        result = scan(item["url"])
        expected = item["expected_label"]
        rows.append({"URL": item["url"], "normalized URL": result["normalized_url"], "label": result["label"], "probability": result["probability"], "risk score": result["risk_score"], "expected category": expected, "pass/fail": result["label"] == expected})
with (ROOT / "validation_report.csv").open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0]); writer.writeheader(); writer.writerows(rows)
passed = sum(r["pass/fail"] for r in rows)
lines = ["# VIGIL validation report", "", "These synthetic examples do not represent real-world phishing prevalence and are not a substitute for dataset-level evaluation. Bare homepages of popular domains can still be misclassified by a URL-only model.", "", f"Passed: {passed}/{len(rows)}", "", "| URL | Label | Probability | Risk | Expected | Pass |", "|---|---:|---:|---:|---|---|"]
lines += [f"| {r['URL']} | {r['label']} | {r['probability']:.6f} | {r['risk score']} | {r['expected category']} | {r['pass/fail']} |" for r in rows]
(ROOT / "validation_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(json.dumps({"passed": passed, "total": len(rows), "failed": len(rows)-passed}, indent=2))
