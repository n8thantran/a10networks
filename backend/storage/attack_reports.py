"""
Attack Report Storage and Management
"""
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import uuid

class AttackReportStorage:
    """Store and manage DDoS attack reports"""
    
    def __init__(self, storage_path: str = "./storage/attack_reports"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.reports_file = self.storage_path / "attack_reports.json"
        self.active_attacks_file = self.storage_path / "active_attacks.json"
        
        self.reports = self._load_reports()
        self.active_attacks = self._load_active_attacks()
    
    def _load_reports(self) -> List[Dict[str, Any]]:
        """Load existing attack reports"""
        if self.reports_file.exists():
            try:
                with open(self.reports_file, 'r') as f:
                    content = f.read()
                    if content.strip():  # Check if file has content
                        return json.loads(content)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load reports file: {e}")
        return []
    
    def _load_active_attacks(self) -> Dict[str, Any]:
        """Load active attack tracking"""
        if self.active_attacks_file.exists():
            try:
                with open(self.active_attacks_file, 'r') as f:
                    content = f.read()
                    if content.strip():  # Check if file has content
                        return json.loads(content)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load active attacks file: {e}")
        return {}
    
    def save_report(self, report: Dict[str, Any]) -> str:
        """Save a new attack report"""
        # Generate unique ID
        report_id = f"REPORT-{uuid.uuid4().hex[:8]}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Add metadata
        report["id"] = report_id
        report["created_at"] = datetime.now().isoformat()
        
        # Add to reports list
        self.reports.append(report)
        
        # Keep only last 100 reports
        if len(self.reports) > 100:
            self.reports = self.reports[-100:]
        
        # Save to file
        with open(self.reports_file, 'w') as f:
            json.dump(self.reports, f, indent=2)
        
        # Also save individual report file
        individual_file = self.storage_path / f"{report_id}.json"
        with open(individual_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_id
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific report by ID"""
        for report in self.reports:
            if report.get("id") == report_id:
                return report
        
        # Try loading from individual file
        individual_file = self.storage_path / f"{report_id}.json"
        if individual_file.exists():
            with open(individual_file, 'r') as f:
                return json.load(f)
        
        return None
    
    def get_recent_reports(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get reports from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent = []
        for report in self.reports:
            try:
                report_time = datetime.fromisoformat(report.get("created_at", ""))
                if report_time > cutoff_time:
                    recent.append(report)
            except:
                pass
        
        return recent
    
    def get_all_reports(self) -> List[Dict[str, Any]]:
        """Get all attack reports"""
        return self.reports
    
    def generate_attack_report(self, 
                              attack_data: Dict[str, Any],
                              mitigation_data: Dict[str, Any],
                              detection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive attack report"""
        
        # Calculate duration
        start_time = attack_data.get("start_time")
        end_time = attack_data.get("end_time", datetime.now().isoformat())
        
        if start_time:
            try:
                duration = (datetime.fromisoformat(end_time) - 
                          datetime.fromisoformat(start_time)).total_seconds()
            except:
                duration = 0
        else:
            duration = 0
        
        # Calculate effectiveness
        total_requests = attack_data.get("total_requests", 0)
        blocked_requests = mitigation_data.get("blocked_requests", 0)
        effectiveness = (blocked_requests / total_requests * 100) if total_requests > 0 else 0
        
        report = {
            "attack_summary": {
                "type": attack_data.get("attack_type", "Unknown"),
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": duration,
                "status": attack_data.get("status", "mitigated"),
                "severity": self._calculate_severity(attack_data, mitigation_data)
            },
            
            "traffic_statistics": {
                "total_requests": total_requests,
                "successful_requests": attack_data.get("successful_requests", 0),
                "failed_requests": attack_data.get("failed_requests", 0),
                "blocked_requests": blocked_requests,
                "bytes_sent": attack_data.get("bytes_sent", 0),
                "peak_rps": attack_data.get("peak_rps", 0),
                "average_rps": attack_data.get("average_rps", 0)
            },
            
            "detection_details": {
                "detection_time": detection_data.get("detection_time"),
                "detection_method": detection_data.get("method", "AI Agent"),
                "confidence_score": detection_data.get("confidence", 0),
                "threat_indicators": detection_data.get("indicators", []),
                "anomalies_detected": detection_data.get("anomalies", [])
            },
            
            "mitigation_actions": {
                "actions_taken": mitigation_data.get("actions", []),
                "ips_blocked": mitigation_data.get("blocked_ips", []),
                "rules_applied": mitigation_data.get("rules", []),
                "effectiveness_percentage": effectiveness,
                "response_time_seconds": mitigation_data.get("response_time", 0)
            },
            
            "attack_sources": {
                "unique_ips": len(set(attack_data.get("source_ips", []))),
                "top_attackers": self._get_top_attackers(attack_data),
                "geographic_distribution": attack_data.get("geo_distribution", {}),
                "user_agents": attack_data.get("user_agents", [])
            },
            
            "impact_assessment": {
                "service_availability": mitigation_data.get("service_availability", "maintained"),
                "performance_impact": mitigation_data.get("performance_impact", "minimal"),
                "data_compromised": False,
                "estimated_damage": self._estimate_damage(attack_data, mitigation_data)
            },
            
            "recommendations": self._generate_recommendations(attack_data, mitigation_data),
            
            "visualizations": {
                "attack_flow": detection_data.get("attack_flow_diagram"),
                "mitigation_flow": detection_data.get("mitigation_diagram"),
                "statistics": detection_data.get("statistics_diagram")
            }
        }
        
        return report
    
    def _calculate_severity(self, attack_data: Dict, mitigation_data: Dict) -> str:
        """Calculate attack severity"""
        total_requests = attack_data.get("total_requests", 0)
        peak_rps = attack_data.get("peak_rps", 0)
        
        if total_requests > 100000 or peak_rps > 1000:
            return "critical"
        elif total_requests > 10000 or peak_rps > 100:
            return "high"
        elif total_requests > 1000 or peak_rps > 50:
            return "medium"
        else:
            return "low"
    
    def _get_top_attackers(self, attack_data: Dict) -> List[Dict]:
        """Get top attacking IPs"""
        ip_counts = {}
        for ip in attack_data.get("source_ips", []):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"ip": ip, "requests": count}
            for ip, count in sorted_ips[:10]
        ]
    
    def _estimate_damage(self, attack_data: Dict, mitigation_data: Dict) -> Dict:
        """Estimate potential damage from attack"""
        duration = attack_data.get("duration", 0)
        total_requests = attack_data.get("total_requests", 0)
        blocked = mitigation_data.get("blocked_requests", 0)
        
        # Simple damage estimation
        potential_downtime = duration if blocked == 0 else duration * (1 - blocked/total_requests)
        
        return {
            "potential_downtime_seconds": potential_downtime,
            "requests_that_got_through": total_requests - blocked,
            "estimated_cost": f"${potential_downtime * 0.1:.2f}",  # $0.1 per second of downtime
            "risk_level": "high" if blocked < total_requests * 0.8 else "low"
        }
    
    def _generate_recommendations(self, attack_data: Dict, mitigation_data: Dict) -> List[str]:
        """Generate recommendations based on attack"""
        recommendations = []
        
        attack_type = attack_data.get("attack_type", "").lower()
        effectiveness = mitigation_data.get("effectiveness_percentage", 0)
        
        if effectiveness < 80:
            recommendations.append("Improve detection algorithms for faster response")
        
        if "volumetric" in attack_type:
            recommendations.append("Implement rate limiting at network edge")
            recommendations.append("Consider CDN with DDoS protection")
        
        if "slowloris" in attack_type:
            recommendations.append("Configure connection timeout limits")
            recommendations.append("Implement connection pooling limits")
        
        if "application" in attack_type:
            recommendations.append("Add CAPTCHA challenges for suspicious requests")
            recommendations.append("Implement Web Application Firewall (WAF)")
        
        recommendations.extend([
            "Enable permanent DDoS protection monitoring",
            "Set up automated alerting for traffic anomalies",
            "Create incident response playbook",
            "Regular security audits and penetration testing"
        ])
        
        return recommendations[:5]  # Top 5 recommendations
    
    def mark_attack_active(self, attack_id: str, attack_data: Dict):
        """Mark an attack as currently active"""
        self.active_attacks[attack_id] = {
            "start_time": datetime.now().isoformat(),
            "attack_type": attack_data.get("type"),
            "data": attack_data
        }
        
        with open(self.active_attacks_file, 'w') as f:
            json.dump(self.active_attacks, f, indent=2)
    
    def mark_attack_stopped(self, attack_id: str) -> Dict[str, Any]:
        """Mark an attack as stopped and return data"""
        if attack_id in self.active_attacks:
            attack_data = self.active_attacks[attack_id]
            attack_data["end_time"] = datetime.now().isoformat()
            
            # Remove from active attacks
            del self.active_attacks[attack_id]
            
            with open(self.active_attacks_file, 'w') as f:
                json.dump(self.active_attacks, f, indent=2)
            
            return attack_data
        
        return {}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall attack statistics"""
        total_attacks = len(self.reports)
        
        if total_attacks == 0:
            return {
                "total_attacks": 0,
                "attacks_today": 0,
                "most_common_type": "None",
                "average_duration": 0,
                "total_blocked_requests": 0
            }
        
        # Calculate statistics
        attacks_today = len(self.get_recent_reports(24))
        
        attack_types = {}
        total_duration = 0
        total_blocked = 0
        
        for report in self.reports:
            # Count attack types
            attack_type = report.get("attack_summary", {}).get("type", "Unknown")
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Sum durations
            total_duration += report.get("attack_summary", {}).get("duration_seconds", 0)
            
            # Sum blocked requests
            total_blocked += report.get("mitigation_actions", {}).get("blocked_requests", 0)
        
        most_common_type = max(attack_types.items(), key=lambda x: x[1])[0] if attack_types else "None"
        
        return {
            "total_attacks": total_attacks,
            "attacks_today": attacks_today,
            "attacks_this_week": len(self.get_recent_reports(168)),
            "most_common_type": most_common_type,
            "average_duration": total_duration / total_attacks if total_attacks > 0 else 0,
            "total_blocked_requests": total_blocked,
            "attack_type_distribution": attack_types
        }