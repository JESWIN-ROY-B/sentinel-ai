"""Synthetic data generator for Sentinel AI demo mode."""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any
import random
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.constants import AttackCategory, Severity
from ..utils.helpers import (
    generate_incident_id, mask_ip, timestamp_to_datetime, 
    safe_float, safe_int, safe_str
)

logger = get_logger(__name__)


class SyntheticDataGenerator:
    """Generate realistic synthetic cybersecurity data for demo mode."""
    
    def __init__(self, random_seed: int = 42):
        """Initialize the synthetic data generator."""
        self.random_seed = random_seed
        np.random.seed(random_seed)
        random.seed(random_seed)
        
        # Sample IP addresses
        self.source_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25",
            "10.0.0.5", "10.0.0.10", "10.0.0.15", "172.16.0.5",
            "203.0.113.10", "198.51.100.20", "192.0.2.30", "203.0.113.40"
        ]
        
        # Sample destination IPs (internal assets)
        self.dest_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",
            "10.0.0.100", "10.0.0.101", "10.0.0.102", "172.16.0.100"
        ]
        
        # Protocols
        self.protocols = ["tcp", "udp", "icmp", "arp"]
        
        # Services
        self.services = ["http", "https", "ftp", "ssh", "dns", "smtp", "icmp", "none"]
        
        # Attack categories with probabilities
        self.attack_categories = [
            "Normal", "Normal", "Normal",  # 60% normal traffic
            "Reconnaissance", "Reconnaissance",
            "Exploits", "Backdoors", "DoS",
            "Fuzzers", "Analysis", "Shellcode", "Worms", "Generic"
        ]
        
        # Asset criticality mapping
        self.asset_criticality = {
            "192.168.1.100": "critical",
            "192.168.1.101": "high",
            "192.168.1.102": "medium",
            "192.168.1.103": "low",
            "10.0.0.100": "critical",
            "10.0.0.101": "high",
            "10.0.0.102": "medium",
            "172.16.0.100": "high"
        }
        
        # User privilege levels
        self.user_privileges = {
            "admin": "admin",
            "user1": "standard",
            "user2": "standard",
            "user3": "privileged",
            "service": "service",
            "guest": "guest"
        }
    
    def generate_alerts(self, num_alerts: int = 500) -> pd.DataFrame:
        """Generate synthetic network alerts."""
        logger.info(f"Generating {num_alerts} synthetic alerts")
        
        alerts = []
        base_time = datetime.now() - timedelta(hours=24)
        
        for i in range(num_alerts):
            alert = self._generate_single_alert(base_time, i)
            alerts.append(alert)
        
        df = pd.DataFrame(alerts)
        logger.info(f"Generated {len(df)} synthetic alerts")
        return df
    
    def _generate_single_alert(self, base_time: datetime, index: int) -> Dict[str, Any]:
        """Generate a single synthetic alert."""
        # Random timestamp within last 24 hours
        timestamp = base_time + timedelta(
            minutes=random.randint(0, 1440),
            seconds=random.randint(0, 59)
        )
        
        # Select attack category
        attack_cat = random.choice(self.attack_categories)
        
        # Select IPs (attackers target critical assets more often)
        if attack_cat != "Normal":
            dest_ip = random.choice([ip for ip, crit in self.asset_criticality.items() 
                                    if crit in ["critical", "high"]])
        else:
            dest_ip = random.choice(self.dest_ips)
        
        source_ip = random.choice(self.source_ips)
        
        # Protocol and service
        protocol = random.choice(self.protocols)
        service = random.choice(self.services)
        
        # Generate network features with attack-specific patterns
        if attack_cat == "Normal":
            duration = random.uniform(0.1, 5.0)
            sbytes = random.randint(100, 5000)
            dbytes = random.randint(100, 5000)
            spkts = random.randint(1, 20)
            dpkts = random.randint(1, 20)
        else:
            # Attack traffic patterns
            duration = random.uniform(0.01, 60.0)
            sbytes = random.randint(50, 10000)
            dbytes = random.randint(50, 10000)
            spkts = random.randint(1, 100)
            dpkts = random.randint(1, 100)
        
        # Port numbers
        sport = random.randint(1024, 65535)
        dport = self._get_destination_port(service)
        
        # Additional features
        sttl = random.randint(32, 128)
        dttl = random.randint(32, 128)
        sload = sbytes / (duration + 0.001)
        dload = dbytes / (duration + 0.001)
        sloss = random.randint(0, spkts // 4)
        dloss = random.randint(0, dpkts // 4)
        
        alert = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": sport,
            "destination_port": dport,
            "protocol": protocol,
            "service": service,
            "duration": duration,
            "source_bytes": sbytes,
            "destination_bytes": dbytes,
            "source_packets": spkts,
            "destination_packets": dpkts,
            "source_ttl": sttl,
            "destination_ttl": dttl,
            "source_load": sload,
            "destination_load": dload,
            "source_loss": sloss,
            "destination_loss": dloss,
            "attack_category": attack_cat,
            "label": 0 if attack_cat == "Normal" else 1,
            "prediction": attack_cat,
            "confidence": random.uniform(0.6, 0.95) if attack_cat != "Normal" else random.uniform(0.7, 0.99),
            "anomaly_score": random.uniform(10, 30) if attack_cat == "Normal" else random.uniform(50, 95),
            "incident_id": "",
            "status": "New"
        }
        
        return alert
    
    def _get_destination_port(self, service: str) -> int:
        """Get typical destination port for a service."""
        port_mapping = {
            "http": 80,
            "https": 443,
            "ftp": 21,
            "ssh": 22,
            "dns": 53,
            "smtp": 25,
            "icmp": 0,
            "none": 0
        }
        return port_mapping.get(service, random.randint(1, 65535))
    
    def generate_assets(self, num_assets: int = 50) -> pd.DataFrame:
        """Generate synthetic asset data."""
        logger.info(f"Generating {num_assets} synthetic assets")
        
        assets = []
        criticality_levels = ["critical", "high", "medium", "low"]
        
        for i in range(num_assets):
            asset = {
                "asset_id": f"AST-{i:04d}",
                "asset_name": f"Server-{i+1}",
                "asset_type": random.choice(["Server", "Workstation", "Router", "Firewall", "Database"]),
                "ip_address": random.choice(self.dest_ips),
                "criticality": random.choice(criticality_levels),
                "owner": random.choice(list(self.user_privileges.keys())),
                "department": random.choice(["IT", "Finance", "HR", "Engineering", "Sales"]),
                "os": random.choice(["Windows", "Linux", "macOS"]),
                "last_updated": datetime.now() - timedelta(days=random.randint(0, 30))
            }
            assets.append(asset)
        
        df = pd.DataFrame(assets)
        logger.info(f"Generated {len(df)} synthetic assets")
        return df
    
    def generate_users(self, num_users: int = 30) -> pd.DataFrame:
        """Generate synthetic user data."""
        logger.info(f"Generating {num_users} synthetic users")
        
        users = []
        privilege_levels = ["admin", "privileged", "standard", "guest", "service"]
        
        for i in range(num_users):
            user = {
                "user_id": f"USR-{i:04d}",
                "username": f"user{i+1}",
                "full_name": f"User {i+1}",
                "email": f"user{i+1}@company.com",
                "privilege_level": random.choice(privilege_levels),
                "department": random.choice(["IT", "Finance", "HR", "Engineering", "Sales"]),
                "last_login": datetime.now() - timedelta(days=random.randint(0, 7)),
                "account_status": random.choice(["active", "active", "active", "suspended"])
            }
            users.append(user)
        
        df = pd.DataFrame(users)
        logger.info(f"Generated {len(df)} synthetic users")
        return df
    
    def generate_incidents(self, num_incidents: int = 20) -> pd.DataFrame:
        """Generate synthetic incident data."""
        logger.info(f"Generating {num_incidents} synthetic incidents")
        
        incidents = []
        base_time = datetime.now() - timedelta(hours=24)
        
        # Generate some attack chains
        attack_chains = self._generate_attack_chains(base_time)
        
        for i in range(num_incidents):
            if i < len(attack_chains):
                incident = attack_chains[i]
            else:
                incident = self._generate_single_incident(base_time, i)
            incidents.append(incident)
        
        df = pd.DataFrame(incidents)
        logger.info(f"Generated {len(df)} synthetic incidents")
        return df
    
    def _generate_single_incident(self, base_time: datetime, index: int) -> Dict[str, Any]:
        """Generate a single synthetic incident."""
        attack_cat = random.choice([cat for cat in self.attack_categories if cat != "Normal"])
        
        first_seen = base_time + timedelta(
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        last_seen = first_seen + timedelta(
            minutes=random.randint(5, 120)
        )
        
        risk_score = random.uniform(50, 95)
        severity = self._calculate_severity(risk_score)
        
        incident = {
            "incident_id": generate_incident_id(),
            "title": f"{attack_cat} Activity Detected",
            "description": f"Suspicious {attack_cat.lower()} activity detected from internal network.",
            "severity": severity,
            "risk_score": risk_score,
            "attack_category": attack_cat,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "affected_assets": random.sample(self.dest_ips, random.randint(1, 3)),
            "source_ips": random.sample(self.source_ips, random.randint(1, 2)),
            "alert_count": random.randint(5, 50),
            "status": random.choice(["New", "Under Investigation", "Escalated", "Resolved", "False Positive"]),
            "confidence": random.uniform(0.6, 0.95),
            "mitre_tactic": self._get_mitre_tactic(attack_cat),
            "analyst_notes": ""
        }
        
        return incident
    
    def _generate_attack_chains(self, base_time: datetime) -> List[Dict[str, Any]]:
        """Generate multi-stage attack chains for realistic scenarios."""
        chains = []
        
        # Reconnaissance -> Exploitation chain
        chain1 = {
            "incident_id": generate_incident_id(),
            "title": "Multi-stage Attack: Reconnaissance to Exploitation",
            "description": "Attack chain showing reconnaissance followed by exploitation attempts",
            "severity": "Critical",
            "risk_score": 92.0,
            "attack_category": "Exploits",
            "first_seen": base_time + timedelta(hours=2),
            "last_seen": base_time + timedelta(hours=5),
            "affected_assets": ["192.168.1.100", "192.168.1.101"],
            "source_ips": ["203.0.113.10", "198.51.100.20"],
            "alert_count": 45,
            "status": "Under Investigation",
            "confidence": 0.88,
            "mitre_tactic": "Reconnaissance, Initial Access, Execution",
            "analyst_notes": "Possible coordinated attack requiring immediate investigation"
        }
        chains.append(chain1)
        
        # Backdoor persistence chain
        chain2 = {
            "incident_id": generate_incident_id(),
            "title": "Backdoor Communication Detected",
            "description": "Suspicious backdoor communication patterns detected",
            "severity": "High",
            "risk_score": 78.0,
            "attack_category": "Backdoors",
            "first_seen": base_time + timedelta(hours=8),
            "last_seen": base_time + timedelta(hours=12),
            "affected_assets": ["10.0.0.100"],
            "source_ips": ["203.0.113.40"],
            "alert_count": 28,
            "status": "Escalated",
            "confidence": 0.82,
            "mitre_tactic": "Command and Control, Persistence",
            "analyst_notes": "Potential C2 communication detected"
        }
        chains.append(chain2)
        
        # DoS attack chain
        chain3 = {
            "incident_id": generate_incident_id(),
            "title": "Denial of Service Attack",
            "description": "High-volume traffic consistent with DoS attack",
            "severity": "Critical",
            "risk_score": 89.0,
            "attack_category": "DoS",
            "first_seen": base_time + timedelta(hours=15),
            "last_seen": base_time + timedelta(hours=17),
            "affected_assets": ["192.168.1.102", "192.168.1.103"],
            "source_ips": ["198.51.100.20", "192.0.2.30"],
            "alert_count": 156,
            "status": "New",
            "confidence": 0.91,
            "mitre_tactic": "Impact",
            "analyst_notes": "High-volume traffic targeting critical infrastructure"
        }
        chains.append(chain3)
        
        return chains
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Calculate severity from risk score."""
        if risk_score >= 85:
            return "Critical"
        elif risk_score >= 70:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _get_mitre_tactic(self, attack_cat: str) -> str:
        """Get MITRE ATT&CK tactic for attack category."""
        mitre_mapping = {
            "Reconnaissance": "Reconnaissance",
            "Exploits": "Initial Access, Execution",
            "Backdoors": "Command and Control, Persistence",
            "DoS": "Impact",
            "Fuzzers": "Reconnaissance",
            "Analysis": "Reconnaissance",
            "Shellcode": "Execution",
            "Worms": "Lateral Movement",
            "Generic": "Unknown"
        }
        return mitre_mapping.get(attack_cat, "Unknown")
    
    def save_synthetic_data(self, output_dir: Path):
        """Save all synthetic data to CSV files."""
        logger.info(f"Saving synthetic data to {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate and save alerts
        alerts_df = self.generate_alerts(500)
        alerts_df.to_csv(output_dir / "synthetic_alerts.csv", index=False)
        
        # Generate and save assets
        assets_df = self.generate_assets(50)
        assets_df.to_csv(output_dir / "synthetic_assets.csv", index=False)
        
        # Generate and save users
        users_df = self.generate_users(30)
        users_df.to_csv(output_dir / "synthetic_users.csv", index=False)
        
        # Generate and save incidents
        incidents_df = self.generate_incidents(20)
        incidents_df.to_csv(output_dir / "synthetic_incidents.csv", index=False)
        
        logger.info("Synthetic data saved successfully")


def generate_all_synthetic_data(output_dir: Path = None, random_seed: int = 42):
    """Generate all synthetic data files."""
    if output_dir is None:
        from ..utils.paths import get_sample_data_dir
        output_dir = get_sample_data_dir()
    
    generator = SyntheticDataGenerator(random_seed=random_seed)
    generator.save_synthetic_data(output_dir)
    
    return output_dir


if __name__ == "__main__":
    # Generate synthetic data when run directly
    generate_all_synthetic_data()
    print("Synthetic data generation complete!")
