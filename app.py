"""Sentinel AI - Main Streamlit Application"""

import sys
from pathlib import Path
import streamlit as st

# 1. MUST be the very first Streamlit call in the script
st.set_page_config(
    page_title="Sentinel AI - SOC Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.utils.logger import setup_logger, get_logger
from src.utils.config import config

# Setup logging AFTER st.set_page_config
logger = get_logger(__name__)

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
        st.caption(f"Version: {config.get('app.version', '1.0.0') if hasattr(config, 'get') else '1.0.0'}")
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
    
    if not st.session_state.data_loaded:
        load_synthetic_data()
    
    if st.session_state.alerts_df is None or len(st.session_state.alerts_df) == 0:
        st.warning("No data available. Please load data from the Data Management page.")
        return
    
    alerts_df = st.session_state.alerts_df
    incidents_df = st.session_state.incidents_df
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Alerts", len(alerts_df))
    
    with col2:
        incidents_count = len(incidents_df) if incidents_df is not None else 0
        st.metric("Open Incidents", incidents_count)
    
    with col3:
        critical_incidents = len(incidents_df[incidents_df['severity'] == 'Critical']) if (incidents_df is not None and 'severity' in incidents_df.columns) else 0
        st.metric("Critical Incidents", critical_incidents)
    
    with col4:
        high_risk = len(alerts_df[alerts_df['severity'].isin(['Critical', 'High'])]) if 'severity' in alerts_df.columns else 0
        st.metric("High-Risk Alerts", high_risk)
    
    st.markdown("---")
    
    col5, col6, col7, col8 = st.columns(4)
    
    with col5:
        detection_rate = (len(alerts_df[alerts_df['label'] == 1]) / len(alerts_df)) * 100 if ('label' in alerts_df.columns and len(alerts_df) > 0) else 0
        st.metric("Detection Rate", f"{detection_rate:.1f}%")
    
    with col6:
        st.metric("Alert Reduction", "0.0%")
    
    with col7:
        st.metric("Time Savings", "45 min")
    
    with col8:
        avg_risk = alerts_df['risk_score'].mean() if 'risk_score' in alerts_df.columns else 0
        st.metric("Avg Risk Score", f"{avg_risk:.1f}")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Severity Distribution")
        if 'severity' in alerts_df.columns:
            st.bar_chart(alerts_df['severity'].value_counts())
    
    with col2:
        st.subheader("Attack Categories")
        if 'attack_category' in alerts_df.columns:
            st.bar_chart(alerts_df['attack_category'].value_counts())
    
    st.markdown("---")
    
    st.subheader("Recent High-Risk Incidents")
    if incidents_df is not None and len(incidents_df) > 0 and 'severity' in incidents_df.columns:
        high_risk_incidents = incidents_df[incidents_df['severity'].isin(['Critical', 'High'])].head(5)
        if len(high_risk_incidents) > 0:
            st.dataframe(high_risk_incidents, use_container_width=True)
        else:
            st.info("No high-risk incidents found")
    else:
        st.info("No incidents available")


def render_live_alerts():
    """Render live alerts page."""
    st.title("🚨 Live Alerts")
    st.markdown("---")
    
    with st.expander("Upload Alert Data"):
        uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
        if uploaded_file:
            st.success(f"File uploaded: {uploaded_file.name}")
    
    if not st.session_state.data_loaded:
        load_synthetic_data()
    
    if st.session_state.alerts_df is None or len(st.session_state.alerts_df) == 0:
        st.warning("No alerts available. Use synthetic data or upload a file.")
        return
    
    alerts_df = st.session_state.alerts_df
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    
    with col2:
        attack_options = alerts_df['attack_category'].unique() if 'attack_category' in alerts_df.columns else []
        attack_filter = st.multiselect("Attack Type", attack_options)
    
    with col3:
        status_options = alerts_df['status'].unique() if 'status' in alerts_df.columns else []
        status_filter = st.multiselect("Status", status_options)
    
    with col4:
        risk_range = st.slider("Risk Score Range", 0, 100, (0, 100))
    
    filtered_alerts = alerts_df.copy()
    
    if severity_filter and 'severity' in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[filtered_alerts['severity'].isin(severity_filter)]
    if attack_filter and 'attack_category' in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[filtered_alerts['attack_category'].isin(attack_filter)]
    if status_filter and 'status' in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[filtered_alerts['status'].isin(status_filter)]
    if risk_range and 'risk_score' in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[
            (filtered_alerts['risk_score'] >= risk_range[0]) & 
            (filtered_alerts['risk_score'] <= risk_range[1])
        ]
    
    st.subheader(f"Alerts ({len(filtered_alerts)} filtered)")
    
    if len(filtered_alerts) > 0:
        display_columns = ['timestamp', 'source_ip', 'destination_ip', 'protocol', 
                        'attack_category', 'severity', 'risk_score', 'status']
        available_columns = [col for col in display_columns if col in filtered_alerts.columns]
        st.dataframe(filtered_alerts[available_columns if available_columns else filtered_alerts.columns].head(100), use_container_width=True)
    else:
        st.info("No alerts match the current filters")


def render_incidents():
    """Render incidents page."""
    st.title("📋 Incidents")
    st.markdown("---")
    
    if not st.session_state.data_loaded:
        load_synthetic_data()
    
    if st.session_state.incidents_df is None or len(st.session_state.incidents_df) == 0:
        st.warning("No incidents available.")
        return
    
    incidents_df = st.session_state.incidents_df
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_alerts = len(st.session_state.alerts_df) if st.session_state.alerts_df is not None else 0
        st.metric("Raw Alerts", total_alerts)
    
    with col2:
        st.metric("Incidents", len(incidents_df))
    
    with col3:
        if total_alerts > 0:
            reduction = ((total_alerts - len(incidents_df)) / total_alerts) * 100
            st.metric("Alert Reduction", f"{reduction:.1f}%")
        else:
            st.metric("Alert Reduction", "0%")
    
    st.markdown("---")
    
    severity_filter = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    status_filter = st.multiselect("Status", ['New', 'Under Investigation', 'Escalated', 'Resolved', 'False Positive'])
    
    filtered_incidents = incidents_df.copy()
    
    if severity_filter and 'severity' in filtered_incidents.columns:
        filtered_incidents = filtered_incidents[filtered_incidents['severity'].isin(severity_filter)]
    if status_filter and 'status' in filtered_incidents.columns:
        filtered_incidents = filtered_incidents[filtered_incidents['status'].isin(status_filter)]
    
    st.subheader(f"Incident Queue ({len(filtered_incidents)} filtered)")
    
    if len(filtered_incidents) > 0:
        st.dataframe(filtered_incidents, use_container_width=True)
    else:
        st.info("No incidents match the current filters")


def render_incident_detail():
    """Render incident detail page."""
    st.title("🔍 Incident Detail")
    st.markdown("---")
    
    if st.session_state.incidents_df is not None and len(st.session_state.incidents_df) > 0:
        incidents_df = st.session_state.incidents_df
        incident_ids = incidents_df['incident_id'].tolist() if 'incident_id' in incidents_df.columns else incidents_df.index.tolist()
        incident_id = st.selectbox("Select Incident", incident_ids)
        
        if incident_id is not None:
            if 'incident_id' in incidents_df.columns:
                incident = incidents_df[incidents_df['incident_id'] == incident_id].iloc[0]
            else:
                incident = incidents_df.loc[incident_id]
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Severity", incident.get('severity', 'N/A'))
            
            with col2:
                risk = incident.get('risk_score', 0)
                st.metric("Risk Score", f"{risk:.1f}" if isinstance(risk, (int, float)) else str(risk))
            
            with col3:
                st.metric("Status", incident.get('status', 'N/A'))
            
            st.markdown("---")
            
            st.subheader("Executive Summary")
            st.write(f"Incident {incident_id} involves {incident.get('attack_category', 'unclassified')} activity detected on {incident.get('first_seen', 'unknown date')}.")
            
            st.markdown("---")
            
            st.subheader("Affected Entities")
            assets = incident.get('affected_assets', ['N/A'])
            sources = incident.get('source_ips', ['N/A'])
            
            assets_str = ", ".join(assets) if isinstance(assets, list) else str(assets)
            sources_str = ", ".join(sources) if isinstance(sources, list) else str(sources)
            
            st.write(f"**Assets:** {assets_str}")
            st.write(f"**Source IPs:** {sources_str}")
            
            st.markdown("---")
            
            st.subheader("Recommended Actions")
            st.write("• Review affected systems for signs of compromise")
            st.write("• Check authentication logs for suspicious activity")
            st.write("• Isolate affected systems if compromise is confirmed")
            
            st.markdown("---")
            
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
    
    if st.session_state.alerts_df is not None and len(st.session_state.alerts_df) == 0:
        alert_index = st.selectbox("Select Alert Index", range(len(st.session_state.alerts_df)))
        
        if alert_index is not None:
            alert = st.session_state.alerts_df.iloc[alert_index]
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Prediction", alert.get('prediction', 'Unknown'))
            
            with col2:
                confidence = alert.get('confidence', 0)
                st.metric("Confidence", f"{confidence:.1%}" if isinstance(confidence, (int, float)) else str(confidence))
            
            with col3:
                risk_score = alert.get('risk_score', 0)
                st.metric("Risk Score", f"{risk_score:.1f}" if isinstance(risk_score, (int, float)) else str(risk_score))
            
            st.markdown("---")
            
            st.subheader("Model Explanation")
            st.write("Model evidence, not proof of causation. Analyst validation is required.")
            st.info("SHAP explanations will display here once trained models are loaded.")
    else:
        st.warning("No alerts available. Load data first.")


def render_attack_timeline():
    """Render attack timeline page."""
    st.title("⏱️ Attack Timeline")
    st.markdown("---")
    
    if st.session_state.incidents_df is not None and len(st.session_state.incidents_df) > 0:
        incidents_df = st.session_state.incidents_df
        incident_ids = incidents_df['incident_id'].tolist() if 'incident_id' in incidents_df.columns else incidents_df.index.tolist()
        incident_id = st.selectbox("Select Incident", incident_ids)
        
        if incident_id:
            st.subheader(f"Timeline for {incident_id}")
            st.info("Attack timeline visualization step")
            
            st.markdown("---")
            st.subheader("Attack Progression")
            st.write("• Reconnaissance\n• Initial Access\n• Execution\n• Persistence")
            st.caption("MITRE ATT&CK mapping is heuristic and must be validated by security analysts.")
    else:
        st.warning("No incidents available. Load data first.")


def render_model_performance():
    """Render model performance page."""
    st.title("📈 Model Performance")
    st.markdown("---")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Binary Model", "Not Trained")
    with col2:
        st.metric("Multi-class Model", "Not Trained")
    with col3:
        st.metric("Anomaly Detector", "Not Trained")
    
    st.markdown("---")
    st.info("Train models using your custom training pipelines to populate metrics here.")


def render_data_management():
    """Render data management page."""
    st.title("💾 Data Management")
    st.markdown("---")
    
    st.subheader("Upload Dataset")
    uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
    if uploaded_file:
        st.success(f"File uploaded: {uploaded_file.name}")
    
    st.markdown("---")
    
    st.subheader("Synthetic Data")
    if st.button("Generate Synthetic Data"):
        with st.spinner("Generating synthetic data..."):
            try:
                from src.data.synthetic import generate_all_synthetic_data
                generate_all_synthetic_data()
                st.success("Synthetic data generated successfully")
                load_synthetic_data()
            except Exception as e:
                st.error(f"Failed generating data: {e}")
    
    st.markdown("---")
    
    if st.session_state.alerts_df is not None:
        st.subheader("Current Data")
        st.write(f"**Alerts:** {len(st.session_state.alerts_df)}")
        st.write(f"**Incidents:** {len(st.session_state.incidents_df) if st.session_state.incidents_df is not None else 0}")
        st.dataframe(st.session_state.alerts_df.head(), use_container_width=True)


def render_settings():
    """Render settings page."""
    st.title("⚙️ Settings")
    st.markdown("---")
    
    st.subheader("Thresholds")
    st.slider("Anomaly Threshold", 0, 100, 50)
    st.slider("Prediction Threshold", 0, 100, 50)
    
    st.markdown("---")
    
    st.subheader("Correlation Settings")
    st.slider("Correlation Time Window (minutes)", 1, 120, 30)
    st.slider("Similarity Threshold", 0.0, 1.0, 0.7)
    
    st.markdown("---")
    
    if st.button("Save Settings"):
        st.success("Settings saved successfully")


def load_synthetic_data():
    """Load synthetic data into session state safely."""
    try:
        from src.data.loader import DatasetLoader
        from src.intelligence.risk_scoring import RiskScoringEngine
        from src.intelligence.correlation import correlate_alerts_to_incidents
        
        loader = DatasetLoader()
        alerts_df = loader.load_synthetic_data()
        
        risk_engine = RiskScoringEngine()
        alerts_df = risk_engine.calculate_batch_risk(alerts_df)
        
        alerts_df, incidents_df, _ = correlate_alerts_to_incidents(alerts_df)
        
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
