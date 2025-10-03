"""
Network data storage and management system
"""
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
from collections import defaultdict

class NetworkDataStore:
    """Store and manage network topology and packet data"""
    
    def __init__(self, storage_path: str = "./storage/network_data"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.data_file = self.storage_path / "network_topology.json"
        self.sessions_file = self.storage_path / "sessions.json"
        self.flows_file = self.storage_path / "flows.json"
        
        self.network_data = self._load_or_create()
        
    def _load_or_create(self) -> Dict[str, Any]:
        """Load existing network data or create new structure"""
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                return json.load(f)
        
        return {
            "nodes": {},
            "connections": [],
            "services": {},
            "protocols": {},
            "anomalies": [],
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "total_packets": 0,
                "total_bytes": 0
            }
        }
    
    def add_node(self, ip: str, **kwargs) -> str:
        """Add or update a network node"""
        node_id = hashlib.md5(ip.encode()).hexdigest()[:8]
        
        if node_id not in self.network_data["nodes"]:
            self.network_data["nodes"][node_id] = {
                "ip": ip,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "ports": [],
                "services": [],
                "os": kwargs.get("os"),
                "hostname": kwargs.get("hostname"),
                "mac": kwargs.get("mac"),
                "vendor": kwargs.get("vendor"),
                "type": kwargs.get("type", "host"),
                "risk_score": 0,
                "packet_count": 0,
                "bytes_transferred": 0
            }
        else:
            node = self.network_data["nodes"][node_id]
            node["last_seen"] = datetime.now().isoformat()
            node["packet_count"] += kwargs.get("packet_count", 1)
            node["bytes_transferred"] += kwargs.get("bytes", 0)
            
            if kwargs.get("port") and kwargs.get("port") not in node["ports"]:
                node["ports"].append(kwargs.get("port"))
        
        return node_id
    
    def add_connection(self, src_ip: str, dst_ip: str, protocol: str, port: int, **kwargs) -> Dict:
        """Add a network connection between nodes"""
        src_node_id = self.add_node(src_ip)
        dst_node_id = self.add_node(dst_ip, port=port)
        
        connection_id = f"{src_node_id}_{dst_node_id}_{protocol}_{port}"
        
        connection = {
            "id": connection_id,
            "source": src_node_id,
            "target": dst_node_id,
            "protocol": protocol,
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "packet_count": kwargs.get("packet_count", 1),
            "bytes": kwargs.get("bytes", 0),
            "flags": kwargs.get("flags"),
            "service": kwargs.get("service"),
            "threat_level": kwargs.get("threat_level", "none")
        }
        
        # Update or add connection
        existing = next((c for c in self.network_data["connections"] 
                        if c["id"] == connection_id), None)
        
        if existing:
            existing["packet_count"] += connection["packet_count"]
            existing["bytes"] += connection["bytes"]
            existing["timestamp"] = connection["timestamp"]
        else:
            self.network_data["connections"].append(connection)
        
        # Update protocol statistics
        if protocol not in self.network_data["protocols"]:
            self.network_data["protocols"][protocol] = {
                "count": 0,
                "bytes": 0,
                "ports": []
            }
        
        proto_stats = self.network_data["protocols"][protocol]
        proto_stats["count"] += 1
        proto_stats["bytes"] += kwargs.get("bytes", 0)
        if port not in proto_stats["ports"]:
            proto_stats["ports"].append(port)
        
        return connection
    
    def add_service(self, ip: str, port: int, service: str, **kwargs):
        """Add discovered service information"""
        service_key = f"{ip}:{port}"
        
        self.network_data["services"][service_key] = {
            "ip": ip,
            "port": port,
            "service": service,
            "version": kwargs.get("version"),
            "product": kwargs.get("product"),
            "discovered_at": datetime.now().isoformat(),
            "vulnerabilities": kwargs.get("vulnerabilities", []),
            "banner": kwargs.get("banner")
        }
    
    def add_anomaly(self, anomaly_type: str, description: str, **kwargs):
        """Add detected anomaly"""
        anomaly = {
            "type": anomaly_type,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "severity": kwargs.get("severity", "medium"),
            "source": kwargs.get("source"),
            "target": kwargs.get("target"),
            "details": kwargs.get("details", {})
        }
        
        self.network_data["anomalies"].append(anomaly)
        
        # Keep only last 1000 anomalies
        if len(self.network_data["anomalies"]) > 1000:
            self.network_data["anomalies"] = self.network_data["anomalies"][-1000:]
    
    def update_from_packet(self, packet_data: Dict[str, Any]):
        """Update network data from captured packet"""
        # Extract IP information
        ip_layer = None
        transport_layer = None
        
        for layer in packet_data.get("layers", []):
            if layer["name"] == "IP":
                ip_layer = layer["fields"]
            elif layer["name"] in ["TCP", "UDP"]:
                transport_layer = layer
        
        if ip_layer and transport_layer:
            protocol = transport_layer["name"].lower()
            src_port = transport_layer["fields"].get("sport", 0)
            dst_port = transport_layer["fields"].get("dport", 0)
            
            self.add_connection(
                src_ip=ip_layer["src"],
                dst_ip=ip_layer["dst"],
                protocol=protocol,
                port=dst_port,
                bytes=packet_data.get("size", 0),
                flags=transport_layer["fields"].get("flags")
            )
        
        # Update metadata
        self.network_data["metadata"]["total_packets"] += 1
        self.network_data["metadata"]["total_bytes"] += packet_data.get("size", 0)
        self.network_data["metadata"]["last_updated"] = datetime.now().isoformat()
    
    def save(self):
        """Save network data to disk"""
        with open(self.data_file, 'w') as f:
            json.dump(self.network_data, f, indent=2)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get network summary statistics"""
        return {
            "total_nodes": len(self.network_data["nodes"]),
            "total_connections": len(self.network_data["connections"]),
            "total_services": len(self.network_data["services"]),
            "protocols_used": list(self.network_data["protocols"].keys()),
            "recent_anomalies": len(self.network_data["anomalies"]),
            "metadata": self.network_data["metadata"]
        }
    
    def query_nodes(self, **filters) -> List[Dict]:
        """Query nodes with filters"""
        results = []
        
        for node_id, node in self.network_data["nodes"].items():
            match = True
            
            for key, value in filters.items():
                if key in node:
                    if isinstance(value, list):
                        if node[key] not in value:
                            match = False
                            break
                    elif node[key] != value:
                        match = False
                        break
            
            if match:
                results.append({"id": node_id, **node})
        
        return results
    
    def get_node_connections(self, node_ip: str) -> Dict[str, List]:
        """Get all connections for a specific node"""
        node_id = hashlib.md5(node_ip.encode()).hexdigest()[:8]
        
        incoming = []
        outgoing = []
        
        for conn in self.network_data["connections"]:
            if conn["source"] == node_id:
                outgoing.append(conn)
            elif conn["target"] == node_id:
                incoming.append(conn)
        
        return {
            "incoming": incoming,
            "outgoing": outgoing
        }
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get nodes with most traffic"""
        nodes_with_traffic = [
            {"id": nid, **node} 
            for nid, node in self.network_data["nodes"].items()
        ]
        
        return sorted(
            nodes_with_traffic, 
            key=lambda x: x.get("bytes_transferred", 0),
            reverse=True
        )[:limit]
    
    def get_protocol_distribution(self) -> Dict[str, Dict]:
        """Get protocol usage distribution"""
        return self.network_data["protocols"]
    
    def get_recent_anomalies(self, hours: int = 24) -> List[Dict]:
        """Get anomalies from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        return [
            anomaly for anomaly in self.network_data["anomalies"]
            if datetime.fromisoformat(anomaly["timestamp"]) > cutoff_time
        ]
    
    def clear_old_data(self, days: int = 7):
        """Clear data older than specified days"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        # Clear old anomalies
        self.network_data["anomalies"] = [
            a for a in self.network_data["anomalies"]
            if datetime.fromisoformat(a["timestamp"]) > cutoff_time
        ]
        
        # Clear old connections
        self.network_data["connections"] = [
            c for c in self.network_data["connections"]
            if datetime.fromisoformat(c["timestamp"]) > cutoff_time
        ]
        
        self.save()