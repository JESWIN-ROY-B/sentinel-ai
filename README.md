# 🛡️ CipherMind AI '26 — AI-Powered Security Operations Assistant

An end-to-end intelligent Security Operations Center (SOC) assistant built to automate threat detection, eliminate alert fatigue, explain high-risk decisions, and generate instant response playbooks.

---

## 📌 Overview

Modern enterprise SOCs face thousands of daily alerts from firewalls, endpoint detection systems, and email gateways. Most alerts are false positives or low-priority noise, leading to alert fatigue and delayed incident response.

**CipherMind AI** assists human analysts by:
* Detecting and classifying network intrusions into 9 threat families using the **UNSW-NB15** dataset.
* Providing model transparency via **SHAP (Explainable AI)** to show *why* an alert was flagged.
* Scoring and identifying **phishing emails** with natural language processing.
* Discovering unknown malware relationships using **unsupervised behavioral clustering**.
* Generating **automated mitigation playbooks** to reduce Mean Time to Respond (MTTR).

---

## 🏗️ System Architecture

```text
                                [ Security Telemetry Ingestion ]
                                               │
                ┌──────────────────────────────┼──────────────────────────────┐
                ▼                              ▼                              ▼
     Network Flow Logs (UNSW-NB15)      Suspicious Email Body       Sandbox Execution Metrics
                │                              │                              │
                ▼                              ▼                              ▼
     XGBoost Threat Classifier         TF-IDF + Naive Bayes       PCA + K-Means Clustering
                │                              │                              │
        ┌───────┴───────┐                      │                              │
        ▼               ▼                      │                              │
   Threat Class     SHAP (XAI)                 │                              │
        │               │                      │                              │
        └───────┬───────┘                      │                              │
                └──────────────────────────────┼──────────────────────────────┘
                                               ▼
                              [ Unified SOC Assistant Engine ]
                                               │
                                 ├── Dynamic Risk Scoring (Low ➔ Critical)
                                 ├── Actionable Response Playbooks
                                 └── Interactive Web Console (Gradio)
