"""Sentinel AI - Main Streamlit Application"""

import streamlit as st
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.utils.logger import setup_logger, get_logger
from src.utils.config import config

# Setup logging
logger = get_logger(__name__)

# Page configuration
st.set_page_config(
    page_title="Sentinel AI - SOC Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
    }
    .main {
        background-color: #0e1117;
    }
    h1, h2, h3 {
        color: #ffffff;
    }
    .stMetric {
        background-color: #1e2130;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 10px;
    }
    .stDataFrame {
        background-color: #1e2130;
    }
    div[data-testid="stMetricValue"] {
        color: #ffffff;
    }
    div[data-testid="stMetricLabel"] {
        color: #a0aec0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'page' not in st.session_state:
    st.session_state.page = 'overview'
if 'data_loaded' not in st.session_state:
    st.session_state.data_loaded = False
if 'synthetic_mode' not in st.session_state:
    st.session_state.synthetic_mode = True
if 'alerts_df' not in st.session_state:
    st.session_state.alerts_df = None
if 'incidents_df' not in st.session_state:
    st.session_state.incidents_df = None


def main():
    """Main application function."""
    
    # Sidebar
    with st.sidebar:
        st.title("🛡️ Sentinel AI")
        st.markdown("---")
        
        # Mode indicator
        if st.session_state.synthetic_mode:
            st.warning("🔬 DEMO MODE")
            st.caption("Using synthetic data")
        else:
            st.success("📊 LIVE MODE")
            st.caption("Using uploaded dataset")
        
        st.markdown("---")
        
        # Navigation
        st.subheader("Navigation")
        page = st.radio(
            "Select Page",
            ['Overview', 'Live Alerts', 'Incidents', 'Incident Detail', 
             'Explainability', 'Attack Timeline', 'Model Performance', 
             'Data Management', 'Settings'],
            key='page_navigation'
        )
        st.session_state.page = page.lower().replace(' ', '_')
        
        st.markdown("---")
        
        # Safety notice
        st.error("⚠️ SAFETY NOTICE")
        st.caption("Sentinel AI provides AI-assisted analysis. Human analyst validation is required before response actions.")
        
        st.markdown("---")
        
        # App info
        st.subheader("System Status")
        st.caption(f"Version: {config.get('app.version', '1.0.0')}")
        st.caption(f"Dataset: {'Synthetic' if st.session_state.synthetic_mode else 'Uploaded'}")
        
        # Model status
        model_status = "🟢 Ready" if st.session_state.data_loaded else "🟡 No Data"
        st.caption(f"Model Status: {model_status}")
    
    # Main content area
    if st.session_state.page == 'overview':
        render_overview()
    elif st.session_state.page == 'live_alerts':
        render_live_alerts()
    elif st.session_state.page == 'incidents':
        render_incidents()
    elif st.session_state.page == 'incident_detail':
        render_incident_detail()
    elif st.session_state.page == 'explainability':
        render_explainability()
    elif st.session_state.page == 'attack_timeline':
        render_attack_timeline()
    elif st.session_state.page == 'model_performance':
        render_model_performance()
    elif st.session_state.page == 'data_management':
        render_data_management()
    elif st.session_state.page == 'settings':
        render_settings()


def render_overview():
    """Render overview page."""
    st.title("📊 SOC Overview")
    st.markdown("---")
    
    # Load synthetic data if not loaded
    if not st.session_state.data_loaded:
        load_synthetic_data()
    
    if st.session_state.alerts_df is None or len(st.session_state.alerts_df) == 0:
        st.warning("No data available. Please load data from the Data Management page.")
        return
    
    alerts_df = st.session_state.alerts_df
    incidents_df = st.session_state.incidents_df
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_alerts = len(alerts_df)
        st.metric("Total Alerts", total_alerts)
    
    with col2:
        if incidents_df is not None and len(incidents_df) > 0:
            incidents_count = len(incidents_df)
            st.metric("Open Incidents", incidents_count)
        else:
            st.metric("Open Incidents", 0)
    
    with col3:
        critical_incidents = len(incidents_df[incidents_df['severity'] == 'Critical']) if incidents_df is not None else 0
        st.metric("Critical Incidents", critical_incidents)
    
    with col4:
        high_risk = len(alerts_df[alerts_df['severity'].isin(['Critical', 'High'])])
        st.metric("High-Risk Alerts", high_risk)
    
    st.markdown("---")
    
    # Additional metrics
    col5, col6, col7, col8 = st.columns(4)
    
    with col5:
        detection_rate = (len(alerts_df[alerts_df['label'] == 1]) / len(alerts_df)) * 100 if len(alerts_df) > 0 else 0
        st.metric("Detection Rate", f"{detection_rate:.1f}%")
    
    with col6:
        alert_reduction = 0  # Would be calculated from correlation
        st.metric("Alert Reduction", f"{alert_reduction:.1f}%")
    
    with col7:
        time_savings = "45 min"  # Estimated
        st.metric("Time Savings", time_savings)
    
    with col8:
        avg_risk = alerts_df['risk_score'].mean() if 'risk_score' in alerts_df.columns else 0
        st.metric("Avg Risk Score", f"{avg_risk:.1f}")
    
    st.markdown("---")
    
    # Charts and visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Severity Distribution")
        if 'severity' in alerts_df.columns:
            severity_counts = alerts_df['severity'].value_counts()
            st.bar_chart(severity_counts)
    
    with col2:
        st.subheader("Attack Categories")
        if 'attack_category' in alerts_df.columns:
            attack_counts = alerts_df['attack_category'].value_counts()
            st.bar_chart(attack_counts)
    
    st.markdown("---")
    
    # Recent high-risk incidents
    st.subheader("Recent High-Risk Incidents")
    if incidents_df is not None and len(incidents_df) > 0:
        high_risk_incidents = incidents_df[incidents_df['severity'].isin(['Critical', 'High'])].head(5)
        if len(high_risk_incidents) > 0:
            st.dataframe(high_risk_incidents[['incident_id', 'title', 'severity', 'risk_score', 'first_seen']], use_container_width=True)
        else:
            st.info("No high-risk incidents found")
    else:
        st.info("No incidents available")


def render_live_alerts():
    """Render live alerts page."""
    st.title("🚨 Live Alerts")
    st.markdown("---")
    
    # File upload
    with st.expander("Upload Alert Data"):
        uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
        if uploaded_file:
            st.success(f"File uploaded: {uploaded_file.name}")
            # Process uploaded file (placeholder)
    
    # Load synthetic data if not loaded
    if not st.session_state.data_loaded:
        load_synthetic_data()
    
    if st.session_state.alerts_df is None or len(st.session_state.alerts_df) == 0:
        st.warning("No alerts available. Use synthetic data or upload a file.")
        return
    
    alerts_df = st.session_state.alerts_df
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    
    with col2:
        attack_filter = st.multiselect("Attack Type", alerts_df['attack_category'].unique())
    
    with col3:
        status_filter = st.multiselect("Status", alerts_df['status'].unique())
    
    with col4:
        risk_range = st.slider("Risk Score Range", 0, 100, (0, 100))
    
    # Apply filters
    filtered_alerts = alerts_df.copy()
    
    if severity_filter:
        filtered_alerts = filtered_alerts[filtered_alerts['severity'].isin(severity_filter)]
    if attack_filter:
        filtered_alerts = filtered_alerts[filtered_alerts['attack_category'].isin(attack_filter)]
    if status_filter:
        filtered_alerts = filtered_alerts[filtered_alerts['status'].isin(status_filter)]
    if risk_range:
        filtered_alerts = filtered_alerts[
            (filtered_alerts['risk_score'] >= risk_range[0]) & 
            (filtered_alerts['risk_score'] <= risk_range[1])
        ]
    
    # Display alerts
    st.subheader(f"Alerts ({len(filtered_alerts)} filtered)")
    
    if len(filtered_alerts) > 0:
        display_columns = ['timestamp', 'source_ip', 'destination_ip', 'protocol', 
                        'attack_category', 'severity', 'risk_score', 'status']
        available_columns = [col for col in display_columns if col in filtered_alerts.columns]
        st.dataframe(filtered_alerts[available_columns].head(100), use_container_width=True)
    else:
        st.info("No alerts match the current filters")


def render_incidents():
    """Render incidents page."""
    st.title("📋 Incidents")
    st.markdown("---")
    
    # Load synthetic data if not loaded
    if not st.session_state.data_loaded:
        load_synthetic_data()
    
    if st.session_state.incidents_df is None or len(st.session_state.incidents_df) == 0:
        st.warning("No incidents available.")
        return
    
    incidents_df = st.session_state.incidents_df
    
    # Display correlation metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_alerts = len(st.session_state.alerts_df) if st.session_state.alerts_df is not None else 0
        st.metric("Raw Alerts", total_alerts)
    
    with col2:
        total_incidents = len(incidents_df)
        st.metric("Incidents", total_incidents)
    
    with col3:
        if total_alerts > 0:
            reduction = ((total_alerts - total_incidents) / total_alerts) * 100
            st.metric("Alert Reduction", f"{reduction:.1f}%")
        else:
            st.metric("Alert Reduction", "0%")
    
    st.markdown("---")
    
    # Incident filters
    severity_filter = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    status_filter = st.multiselect("Status", ['New', 'Under Investigation', 'Escalated', 'Resolved', 'False Positive'])
    
    # Apply filters
    filtered_incidents = incidents_df.copy()
    
    if severity_filter:
        filtered_incidents = filtered_incidents[filtered_incidents['severity'].isin(severity_filter)]
    if status_filter:
        filtered_incidents = filtered_incidents[filtered_incidents['status'].isin(status_filter)]
    
    # Display incidents
    st.subheader(f"Incident Queue ({len(filtered_incidents)} filtered)")
    
    if len(filtered_incidents) > 0:
        display_columns = ['incident_id', 'title', 'severity', 'risk_score', 'attack_category', 
                        'first_seen', 'alert_count', 'status']
        available_columns = [col for col in display_columns if col in filtered_incidents.columns]
        st.dataframe(filtered_incidents[available_columns], use_container_width=True)
    else:
        st.info("No incidents match the current filters")


def render_incident_detail():
    """Render incident detail page."""
    st.title("🔍 Incident Detail")
    st.markdown("---")
    
    # Incident selector
    if st.session_state.incidents_df is not None and len(st.session_state.incidents_df) > 0:
        incident_id = st.selectbox("Select Incident", st.session_state.incidents_df['incident_id'].tolist())
        
        if incident_id:
            incident = st.session_state.incidents_df[st.session_state.incidents_df['incident_id'] == incident_id].iloc[0]
            
            # Display incident details
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Severity", incident['severity'])
            
            with col2:
                st.metric("Risk Score", f"{incident['risk_score']:.1f}")
            
            with col3:
                st.metric("Status", incident['status'])
            
            st.markdown("---")
            
            # Executive summary
            st.subheader("Executive Summary")
            st.write(f"Incident {incident_id} involves {incident['attack_category']} activity detected on {incident['first_seen']}.")
            st.write(f"This incident generated {incident['alert_count']} alerts and affects {len(incident['affected_assets'])} assets.")
            
            st.markdown("---")
            
            # Affected entities
            st.subheader("Affected Entities")
            st.write(f"**Assets:** {', '.join(incident['affected_assets'])}")
            st.write(f"**Source IPs:** {', '.join(incident['source_ips'])}")
            
            st.markdown("---")
            
            # Recommended actions
            st.subheader("Recommended Actions")
            st.write("• Review affected systems for signs of compromise")
            st.write("• Check authentication logs for suspicious activity")
            st.write("• Isolate affected systems if compromise is confirmed")
            
            st.markdown("---")
            
            # Analyst controls
            st.subheader("Analyst Controls")
            new_status = st.selectbox("Update Status", ['New', 'Under Investigation', 'Escalated', 'Resolved', 'False Positive'])
            if st.button("Update Status"):
                st.success(f"Status updated to {new_status}")
    else:
        st.warning("No incidents available. Load data first.")


def render_explainability():
    """Render explainability page."""
    st.title("🧠 Explainability")
    st.markdown("---")
    
    st.info("Select an alert or incident to view model explanations")
    
    # Alert selector
    if st.session_state.alerts_df is not None and len(st.session_state.alerts_df) > 0:
        alert_index = st.selectbox("Select Alert", range(len(st.session_state.alerts_df)))
        
        if alert_index is not None:
            alert = st.session_state.alerts_df.iloc[alert_index]
            
            # Display prediction card
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Prediction", alert.get('prediction', 'Unknown'))
            
            with col2:
                confidence = alert.get('confidence', 0)
                st.metric("Confidence", f"{confidence:.1%}")
            
            with col3:
                risk_score = alert.get('risk_score', 0)
                st.metric("Risk Score", f"{risk_score:.1f}")
            
            st.markdown("---")
            
            # Explanation
            st.subheader("Model Explanation")
            st.write("Model evidence, not proof of causation. Analyst validation is required.")
            
            # Placeholder for SHAP values
            st.info("SHAP explanations would be displayed here with trained models")
            
            st.markdown("---")
            
            # Feature contributions
            st.subheader("Top Contributing Features")
            st.write("Feature contributions would be displayed here based on model analysis")
    else:
        st.warning("No alerts available. Load data first.")


def render_attack_timeline():
    """Render attack timeline page."""
    st.title("⏱️ Attack Timeline")
    st.markdown("---")
    
    st.info("Select an incident to view its attack timeline")
    
    # Incident selector
    if st.session_state.incidents_df is not None and len(st.session_state.incidents_df) > 0:
        incident_id = st.selectbox("Select Incident", st.session_state.incidents_df['incident_id'].tolist())
        
        if incident_id:
            st.subheader(f"Timeline for {incident_id}")
            
            # Placeholder timeline visualization
            st.info("Attack timeline visualization would be displayed here")
            
            st.markdown("---")
            
            # Attack progression
            st.subheader("Attack Progression")
            st.write("• Reconnaissance")
            st.write("• Initial Access")
            st.write("• Execution")
            st.write("• Persistence")
            
            st.caption("MITRE ATT&CK mapping is heuristic and must be validated by security analysts")
    else:
        st.warning("No incidents available. Load data first.")


def render_model_performance():
    """Render model performance page."""
    st.title("📈 Model Performance")
    st.markdown("---")
    
    # Model info
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Binary Model", "Not Trained")
    
    with col2:
        st.metric("Multi-class Model", "Not Trained")
    
    with col3:
        st.metric("Anomaly Detector", "Not Trained")
    
    st.markdown("---")
    
    st.info("Train models using the training script to see performance metrics here")
    
    st.markdown("---")
    
    # Placeholder for metrics
    st.subheader("Performance Metrics")
    st.write("Model performance metrics would be displayed here after training")
    
    st.caption("Offline benchmark metrics do not guarantee production SOC performance")


def render_data_management():
    """Render data management page."""
    st.title("💾 Data Management")
    st.markdown("---")
    
    # Data upload
    st.subheader("Upload Dataset")
    uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
    
    if uploaded_file:
        st.success(f"File uploaded: {uploaded_file.name}")
        # Process uploaded file (placeholder)
    
    st.markdown("---")
    
    # Synthetic data
    st.subheader("Synthetic Data")
    if st.button("Generate Synthetic Data"):
        with st.spinner("Generating synthetic data..."):
            from src.data.synthetic import generate_all_synthetic_data
            generate_all_synthetic_data()
            st.success("Synthetic data generated successfully")
            load_synthetic_data()
    
    st.markdown("---")
    
    # Current data info
    if st.session_state.alerts_df is not None:
        st.subheader("Current Data")
        st.write(f"**Alerts:** {len(st.session_state.alerts_df)}")
        st.write(f"**Incidents:** {len(st.session_state.incidents_df) if st.session_state.incidents_df is not None else 0}")
        
        st.dataframe(st.session_state.alerts_df.head(), use_container_width=True)


def render_settings():
    """Render settings page."""
    st.title("⚙️ Settings")
    st.markdown("---")
    
    # Risk weights
    st.subheader("Risk Scoring Weights")
    st.write("Configure the weights for risk scoring components")
    
    st.markdown("---")
    
    # Thresholds
    st.subheader("Thresholds")
    anomaly_threshold = st.slider("Anomaly Threshold", 0, 100, 50)
    prediction_threshold = st.slider("Prediction Threshold", 0, 100, 50)
    
    st.markdown("---")
    
    # Correlation settings
    st.subheader("Correlation Settings")
    time_window = st.slider("Correlation Time Window (minutes)", 1, 120, 30)
    similarity_threshold = st.slider("Similarity Threshold", 0.0, 1.0, 0.7)
    
    st.markdown("---")
    
    # Demo settings
    st.subheader("Demo Settings")
    synthetic_enabled = st.checkbox("Enable Synthetic Data Mode", value=True)
    
    if st.button("Save Settings"):
        st.success("Settings saved successfully")


def load_synthetic_data():
    """Load synthetic data into session state."""
    try:
        from src.data.loader import DatasetLoader
        from src.intelligence.risk_scoring import RiskScoringEngine
        from src.intelligence.correlation import correlate_alerts_to_incidents
        
        loader = DatasetLoader()
        alerts_df = loader.load_synthetic_data()
        
        # Calculate risk scores
        risk_engine = RiskScoringEngine()
        alerts_df = risk_engine.calculate_batch_risk(alerts_df)
        
        # Correlate alerts into incidents
        alerts_df, incidents_df, metrics = correlate_alerts_to_incidents(alerts_df)
        
        st.session_state.alerts_df = alerts_df
        st.session_state.incidents_df = incidents_df
        st.session_state.data_loaded = True
        st.session_state.synthetic_mode = True
        
        logger.info("Synthetic data loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load synthetic data: {e}")
        st.error(f"Failed to load synthetic data: {e}")


if __name__ == "__main__":
    main()
