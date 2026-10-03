# 🛡️ Vigil Is Online  
## Project Report – Phishing Detection & Browser Protection System

> This overview contains historical project framing. Its prior accuracy claims and multi-source collection statements are not current verified results; see [the current ML/backend evaluation](ml-evaluation.md).

---

## 1. 📌 Abstract

Phishing attacks remain one of the most prevalent cybersecurity threats, exploiting human trust through deceptive URLs and fake websites. These attacks often lead to credential theft, financial loss, and data breaches.

**Vigil Is Online** is an intelligent, machine learning–based phishing detection system designed to provide real-time protection against such threats. The system integrates a trained classification model with a browser extension to analyze URLs dynamically and prevent users from accessing malicious websites.

Unlike traditional blacklist-based systems, the prototype evaluates lexical URL features. Its ability to generalize is limited by the available dataset and the current holdout results; zero-day detection is not guaranteed or independently established.

---

## 2. 🎯 Problem Statement

With the exponential growth of digital platforms, phishing attacks have evolved in both volume and sophistication. Attackers now use techniques such as:

- URL obfuscation  
- Homograph attacks (lookalike domains)  
- Short-lived malicious domains  
- Social engineering combined with technical deception  

Existing solutions suffer from several limitations:

- Blacklist Dependency — cannot detect newly generated phishing URLs  
- Delayed Response Time — detection often happens after damage is done  
- User Awareness Gap — users may not recognize suspicious URLs  
- Limited Scalability — manual reporting systems cannot keep up  

### Objective

To design and implement a system that:
- Detects phishing URLs in real time  
- Works on unseen data using ML  
- Integrates directly into the browsing experience  
- Provides instant feedback and protection  

---

## 3. 💡 Proposed Solution

**Vigil Is Online** introduces a multi-layered detection system combining:

### 🧠 Machine Learning Layer
A supervised classification model trained on phishing and legitimate URLs that learns patterns and behaviors of malicious links.

### 🔍 Feature Extraction Layer
Extracts structural and lexical features such as URL length, symbols, domain patterns, and suspicious keywords.

### 🌐 Browser Extension Layer
Monitors user browsing activity and sends URLs for real-time analysis.

### 🚫 Protection Layer
The extension delegates scanning to `/scan` and presents a badge or popup result. Automatic blocking behavior was not exercised in this evaluation.

### Key Innovation
The current implementation centralizes deterministic URL-string analysis and reports a calibrated score, separate risk score, classification, and evidence. It does not inspect page behavior or claim zero-day coverage.

---

## 4. ⚙️ System Architecture

```mermaid
flowchart LR
A[Browser Extension or Client] --> B[Flask API]
B --> C[service.scan]
C --> D[URL Validation and Features]
D --> E[Calibrated Model]
E --> F[Risk, Label, Evidence]
F --> G[Client Result]
```

---

## 5. 🧠 Methodology

### 5.1 Data Collection
- Current model training uses `final_dataset_v2.csv`; its upstream source is not documented in the file.
- No external dataset was integrated in the current evaluated run.

### 5.2 Data Preprocessing
- Canonicalized URL strings, removed feature-equivalent duplicates, and excluded conflicting-label rows  
- Retained source and source-row provenance; upstream provenance is currently missing from the input CSV  
- No class rebalancing was performed  

### 5.3 Feature Engineering

Key features:
- URL length  
- Number of dots and subdomains  
- Presence of IP address  
- Special characters (@, -, etc.)  
- HTTP/HTTPS is exposed as neutral evidence and is excluded from model scoring  
- Suspicious keywords  

### 5.4 Model Training
- Used Scikit-learn classifiers  
- Evaluated using Accuracy, Precision, Recall, F1-score  
- Saved trained model using `.pkl`  

### 5.5 Deployment
- Hosted backend on Render  
- Integrated with browser extension  

---

## 6. 🧪 Implementation Details

### Backend
Python-based system handling feature extraction and predictions.

### Machine Learning Pipeline
Transforms raw URLs into feature vectors and processes them through the trained model.

### Browser Extension
JavaScript-based extension that monitors browsing and interacts with backend.

### Integration
Real-time communication between extension and ML backend ensures instant decisions.

---

## 7. 🌍 Live Demo

The deployment URL was not tested in this backend evaluation. The local API startup command is documented in [ml-evaluation.md](ml-evaluation.md).

---

## 8. 📊 Results & Evaluation

The system demonstrates:
- High accuracy in phishing detection  
- Fast response suitable for real-time use  
- Effective identification of suspicious patterns  

### Current Fresh Metrics

| Metric    | Value |
|----------|------|
| Random holdout accuracy | 0.8609 |
| Random holdout PR-AUC | 0.9006 |
| Random holdout FPR | 0.0240 |
| Random holdout FNR | 0.2949 |

These are dataset holdout results, not estimates of real-world accuracy. The independent external and temporal evaluations have not been run; see [ml-evaluation.md](ml-evaluation.md) for full metrics and limitations.

---

## 9. 🚧 Limitations

- May not detect highly sophisticated obfuscated attacks  
- Depends on dataset quality  
- Requires backend connectivity  
- Seven of eight named legitimate reference URLs were SUSPICIOUS in the current run; the threshold was not relaxed to force them SAFE.  
- No temporal or independent external validation has been performed.  

---

## 10. 📈 Future Scope

- Integration with live threat intelligence APIs  
- Deep learning-based models  
- Mobile and multi-browser support  
- Continuous model updates  
- Enhanced UI/UX  

---

## 11. 🔐 Security Considerations

- History omits userinfo, query strings, and fragments; other URL components such as paths are retained.  
- Only URL strings are analyzed; page content and submitted URLs are not fetched.  
- Privacy-friendly lightweight design  

---

## 12. 🤝 Conclusion

**Vigil Is Online** demonstrates the power of machine learning in cybersecurity by providing a proactive, real-time phishing detection system.

It moves beyond traditional reactive approaches and offers a scalable solution to protect users from evolving online threats.

---

## 13. 📚 References

- Scikit-learn Documentation  
- Public phishing datasets  
- Cybersecurity research papers  
- Chrome Extension Documentation  

---


