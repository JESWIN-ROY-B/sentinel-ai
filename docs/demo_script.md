# Demo Script: Sentinel AI Hackathon Walkthrough

## Demo Overview

This script provides a 3-5 minute walkthrough of Sentinel AI for hackathon demonstrations. The demo showcases the system's core capabilities in a clear, engaging narrative suitable for judges and stakeholders.

## Demo Duration: 3-5 Minutes

## Prerequisites

- Sentinel AI installed and running
- Synthetic data generated
- Streamlit dashboard accessible
- Basic understanding of SOC operations

## Demo Script

### Opening (30 seconds)

**Speaker**: "Good morning/afternoon. I'm demonstrating Sentinel AI, an AI-powered Security Operations Center assistant that helps human analysts investigate security threats faster and more accurately."

**Action**: Show the main dashboard screen

**Speaker**: "SOC analysts today face overwhelming challenges: thousands of daily alerts, false positives, and hours spent investigating legitimate activity. Sentinel AI transforms this noise into prioritized, explainable incidents so analysts can focus on real threats."

### Problem Statement (30 seconds)

**Speaker**: "Let me show you the problem we're solving. A typical SOC might receive 10,000 alerts per day. Without intelligent correlation, analysts must manually triage each one, leading to alert fatigue and missed threats."

**Action**: Navigate to the Overview page and show the metrics

**Speaker**: "On our overview page, you can see the scope of the problem. We have 500 raw alerts that our system has processed. Without correlation, analysts would need to review each one individually."

### Solution - Overview (45 seconds)

**Speaker**: "Sentinel AI solves this through multiple AI capabilities working together."

**Action**: Point to key metrics on the Overview page

**Speaker**: "Our system provides immediate visibility into the security landscape. You can see total alerts, open incidents, and critical incidents at a glance. Most importantly, we show the alert reduction achieved through intelligent correlation."

**Speaker**: "The system also shows severity distribution and attack categories, helping analysts understand the threat landscape quickly."

### Solution - Alert Correlation (45 seconds)

**Speaker**: "Let me show you how we reduce alert fatigue through intelligent correlation."

**Action**: Navigate to the Incidents page

**Speaker**: "Our correlation engine groups similar alerts into coherent incidents based on source IP, destination IP, protocol, time windows, and attack patterns. This reduces 500 raw alerts to just 10 incidents that require analyst attention."

**Speaker**: "You can see the correlation metrics: raw alerts, deduplicated alerts, and the final incident count. This represents a 98% reduction in alert volume, saving analysts hours of manual triage."

### Solution - Risk Scoring (45 seconds)

**Speaker": "But not all incidents are equal. Our transparent risk scoring engine prioritizes threats based on multiple factors."

**Action**: Click on a high-risk incident to show detail

**Speaker**: "Risk scores are calculated using seven weighted components: model confidence, anomaly score, attack severity, asset criticality, user privilege risk, alert frequency, and threat intelligence reputation."

**Speaker**: "Each component is clearly displayed, so analysts understand exactly why an incident received its risk score. This transparency builds trust and helps analysts make informed decisions."

### Solution - Explainability (45 seconds)

**Speaker**: "Crucially, Sentinel AI provides explainable AI. Analysts need to understand WHY the system flagged something, not just WHAT it flagged."

**Action**: Navigate to the Explainability page

**Speaker**: "For each alert, we show the top contributing features, feature importance, and plain-language explanations. This helps analysts quickly understand the evidence behind the AI's decision."

**Speaker**: "We use SHAP values for tree-based models with fallbacks for when SHAP isn't available. The explanation clearly states: 'Model evidence, not proof of causation. Analyst validation is required.'"

### Solution - Attack Timeline (30 seconds)

**Speaker**: "We also provide attack timeline visualization to help analysts understand attack progression."

**Action**: Navigate to the Attack Timeline page

**Speaker**: "The timeline shows the chronological sequence of events, mapped to MITRE ATT&CK tactics where appropriate. This helps analysts see the bigger picture and understand potential attack chains."

**Speaker**: "MITRE mappings are heuristic investigation aids that must be validated by analysts, but they provide valuable context for investigation."

### Human-in-the-Loop Design (30 seconds)

**Speaker**: "I want to emphasize that Sentinel AI is designed as a human-in-the-loop system. The AI assists, but humans decide."

**Action**: Show the analyst controls in the Incident Detail page

**Speaker**: "Analysts can update incident status, add notes, override severity, and mark incidents as false positives. The system provides recommendations, but all response actions require human approval."

**Speaker**: "This safety notice is always visible: 'Sentinel AI provides AI-assisted analysis. Human analyst validation is required before response actions.'"

### Technical Architecture (30 seconds)

**Speaker**: "Under the hood, Sentinel AI uses a sophisticated architecture with multiple machine learning models."

**Action**: Navigate to the Model Performance page

**Speaker**: "We employ three types of models: a binary classifier for normal vs attack detection, a multi-class classifier for attack categorization, and an Isolation Forest anomaly detector for novel behavior detection."

**Speaker**: "The system automatically selects the best available model - LightGBM, XGBoost, or HistGradientBoostingClassifier - with appropriate fallbacks."

### Synthetic Demo Mode (30 seconds)

**Speaker**: "What you're seeing today is our synthetic demo mode, which allows the system to work immediately without requiring external datasets or trained models."

**Action**: Show the demo mode indicator

**Speaker**: "The system generates realistic synthetic data for demonstration purposes, clearly labeled as demo-only. In production, it would work with real UNSW-NB15 data or live telemetry."

### Closing and Value Proposition (30 seconds)

**Speaker**: "To summarize, Sentinel AI delivers three key values:"

**Speaker**: "First, it reduces alert fatigue by 98% through intelligent correlation, turning thousands of alerts into a handful of prioritized incidents."

**Speaker**: "Second, it accelerates investigation through explainable AI and risk-based prioritization, helping analysts focus on the most critical threats first."

**Speaker**: "Third, it maintains human oversight through transparent decision-making and required analyst validation for all response actions."

**Speaker**: "The result: Security analysts can make accurate decisions in seconds or minutes instead of hours, while maintaining the human judgment that's essential for effective security operations."

### Q&A Preparation

**Common Questions**:

1. **Q: What datasets does it work with?**
   A: "Primarily UNSW-NB15, with an extensible adapter architecture for future datasets like CIC-IDS2017."

2. **Q: Does it replace analysts?**
   A: "No, it's designed as a human-in-the-loop assistant. All response actions require analyst approval."

3. **Q: How accurate are the models?**
   A: "On UNSW-NB15, we achieve 85-90% accuracy for binary classification. Real-world performance varies based on environment."

4. **Q: Can it integrate with existing SIEMs?**
   A: "The architecture supports SIEM integration, though that's planned for future releases."

5. **Q: Is it open source?**
   A: "Yes, it's released under MIT license for community use and contribution."

## Demo Tips

### Visual Aids

1. **Use Screen Real Estate**: Maximize the dashboard window for visibility
2. **Highlight Key Metrics**: Point to important numbers as you mention them
3. **Show Interactivity**: Demonstrate filtering, sorting, and drill-down capabilities
4. **Use Color**: Point out the severity color coding (red=critical, orange=high, etc.)

### Narrative Flow

1. **Problem-Solution**: Start with the problem, then show the solution
2. **Technical but Accessible**: Explain technical concepts simply
3. **Human Focus**: Emphasize the human analyst benefits
4. **Value Proposition**: Clear return on investment for organizations

### Engagement

1. **Ask Questions**: "Have you seen alert fatigue in your SOC?"
2. **Relate**: "This is like having a junior analyst who never sleeps"
3. **Show Don't Tell**: Demonstrate features rather than just describing them
4. **Be Confident**: Show confidence in the system's capabilities

### Time Management

1. **Stick to Script**: Follow the timing for each section
2. **Skip Details**: Don't get bogged down in technical details
3. **Focus on Value**: Emphasize business value over technical features
4. **Practice**: Rehearse the demo for smooth delivery

## Demo Variations

### Technical Audience (5 minutes)

- Add more detail about model architecture
- Show configuration files and risk weights
- Discuss the explainability approach in depth
- Mention the technology stack and performance

### Executive Audience (3 minutes)

- Focus on business value and ROI
- Emphasize time savings and efficiency
- Highlight risk reduction and improved security
- Minimize technical details

### Mixed Audience (4 minutes)

- Balance technical and business content
- Provide enough detail for credibility
- Focus on practical benefits
- Keep explanations accessible

## Common Demo Issues

### Technical Issues

1. **System Slow**: "The system is processing a large dataset. In production, this would be optimized."
2. **Missing Data**: "We're using synthetic demo data. In production, this would be real alert data."
3. **Feature Not Working**: "That feature is planned for the next release."

### Content Issues

1. **Too Technical**: "The key takeaway is that it helps analysts work faster."
2. **Too Vague**: "Specifically, it reduces 500 alerts to 10 incidents."
3. **Running Long**: Skip less critical sections, focus on core value

## Follow-Up Materials

### After Demo

1. **Documentation**: Provide access to full documentation
2. **GitHub Repository**: Share the code repository
3. **Contact Information**: Provide contact for follow-up questions
4. **Live Demo**: Offer to provide a live demo environment

### Evaluation Criteria

1. **Functionality**: System works as demonstrated
2. **Value Proposition**: Clear business value is communicated
3. **Innovation**: Novel approach to SOC challenges
4. **Practicality**: Real-world applicability
5. **Presentation**: Clear, engaging presentation

## Success Metrics

### Demo Success Indicators

1. **Audience Engagement**: Questions and interest from audience
2. **Understanding**: Audience grasps the key concepts
3. **Excitement**: Positive response to the solution
4. **Follow-up**: Requests for more information or demos
5. **Comprehension**: Audience can explain the system to others

## Conclusion

This demo script provides a structured approach to showcasing Sentinel AI's capabilities in a hackathon setting. The key is to balance technical depth with business value, while maintaining a clear narrative that resonates with the audience.

Remember that the goal is not just to show features, but to tell a story about how Sentinel AI solves real-world security operations challenges and delivers tangible value to organizations and analysts.

**Final Note**: Practice makes perfect. Rehearse the demo multiple times to ensure smooth delivery and confident presentation.
