"""
Create a test attack report for debugging
"""
from storage.attack_reports import AttackReportStorage
from datetime import datetime
import uuid

def create_test_report():
    """Create a test attack report"""
    storage = AttackReportStorage()
    
    # Create a test report
    test_report = {
        "attack_summary": {
            "type": "Multi-Vector DDoS",
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": 45.2,
            "status": "mitigated",
            "severity": "high"
        },
        "traffic_statistics": {
            "total_requests": 15234,
            "successful_requests": 523,
            "failed_requests": 245,
            "blocked_requests": 14466,
            "bytes_sent": 5242880,
            "peak_rps": 342.5,
            "average_rps": 224.3
        },
        "detection_details": {
            "detection_time": datetime.now().isoformat(),
            "detection_method": "AI Agent Auto-Detection",
            "confidence_score": 0.95,
            "threat_indicators": [
                "RPS spike: 342.5",
                "Blocked IPs: 47",
                "Attack type: Multi-Vector"
            ],
            "anomalies_detected": [
                "Volumetric flood detected",
                "Application layer attacks",
                "Slowloris connections"
            ]
        },
        "mitigation_actions": {
            "actions_taken": [
                "Blocked 47 malicious IPs",
                "Applied 12 firewall rules",
                "Activated rate limiting",
                "AI agent analyzing traffic patterns"
            ],
            "ips_blocked": [f"192.168.1.{i}" for i in range(100, 110)],
            "rules_applied": [],
            "effectiveness_percentage": 94.9,
            "response_time_seconds": 3.2
        },
        "attack_sources": {
            "unique_ips": 47,
            "top_attackers": [
                {"ip": "192.168.1.100", "requests": 1523},
                {"ip": "192.168.1.101", "requests": 1234},
                {"ip": "192.168.1.102", "requests": 1122}
            ],
            "geographic_distribution": {},
            "user_agents": []
        },
        "impact_assessment": {
            "service_availability": "maintained",
            "performance_impact": "minimal",
            "data_compromised": False,
            "estimated_damage": {
                "potential_downtime_seconds": 2.3,
                "requests_that_got_through": 768,
                "estimated_cost": "$0.23",
                "risk_level": "low"
            }
        },
        "recommendations": [
            "Enable permanent DDoS protection monitoring",
            "Configure rate limiting rules",
            "Set up traffic monitoring alerts",
            "Implement CAPTCHA for suspicious requests",
            "Use CDN for traffic distribution"
        ],
        "visualizations": {}
    }
    
    # Save the report
    report_id = storage.save_report(test_report)
    print(f"✅ Created test report: {report_id}")
    
    # Verify it was saved
    saved_report = storage.get_report(report_id)
    if saved_report:
        print(f"✅ Report verified in storage")
    else:
        print(f"❌ Failed to verify report")
    
    # Check statistics
    stats = storage.get_statistics()
    print(f"📊 Total reports in storage: {stats['total_attacks']}")
    
    return report_id

if __name__ == "__main__":
    create_test_report()