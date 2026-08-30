# Sentinel AI - Autonomous Security Operations Assistant

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://sentinel-soc.streamlit.app/)

Live Prototype: https://sentinel-soc.streamlit.app/

## Overview
Sentinel AI is an AI-powered Security Operations Assistant built for the **CipherMind AI '26** challenge. It tackles SOC alert fatigue by ingesting raw network security events, filtering noise, and correlating related threats into clear, actionable incidents.

## Problem Addressed
Modern Security Operations Centers (SOCs) are overwhelmed by thousands of fragmented alerts daily across firewalls, endpoint security tools, and IDSs. Manual triage leads to slow response times, allowing malicious actors to exfiltrate sensitive data before detection.

## Key Features
* **AI Alert Correlation Engine:** Groups isolated security events chronologically using weighted similarity scoring (Source IP, Destination IP, Protocol, Service, Attack Category).
* **UNSW-NB15 Dataset Integration:** Trained and evaluated using the modern UNSW-NB15 network intrusion dataset covering attack categories like DoS, Exploits, Reconnaissance, Fuzzers, and Analysis.
* **Explainable Insights (XAI):** Automatically generates clear incident titles, metrics, and risk scores so analysts understand why alerts were correlated.
* **Noise & Fatigue Reduction:** Provides high-level reduction metrics to show time and alert volume savings.

## Tech Stack
* **Frontend/UI:** Streamlit
* **Data Processing & ML:** Python, Pandas, NumPy, Scikit-Learn
* **Deployment:** Streamlit Cloud

## Quick Start (Local Run)
1. Clone the repository:
   ```bash
   git clone [https://github.com/JESWIN-ROY-B/sentinel-ai.git](https://github.com/JESWIN-ROY-B/sentinel-ai.git)
   cd sentinel-ai
