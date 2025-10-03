"""
Natural language query agent for network data
"""
import re
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from storage.network_store import NetworkDataStore
from storage.attack_reports import AttackReportStorage

class NetworkQueryAgent:
    """Process natural language queries about network data"""
    
    def __init__(self, store: NetworkDataStore, report_storage: AttackReportStorage = None):
        self.store = store
        self.report_storage = report_storage or AttackReportStorage()
        
        # Define query patterns and their handlers
        self.query_patterns = [
            # Node queries
            (r"show all (nodes|hosts|devices)", self._query_all_nodes),
            (r"(find|show|get) (?:node|host|device)s? (?:with|having) ip (\S+)", self._query_node_by_ip),
            (r"(find|show|get) (?:node|host|device)s? on port (\d+)", self._query_nodes_by_port),
            (r"what services are running", self._query_all_services),
            (r"show services on (\S+)", self._query_services_by_host),
            
            # Connection queries
            (r"show connections (?:from|to) (\S+)", self._query_connections),
            (r"who is talking to (\S+)", self._query_who_talks_to),
            (r"show all connections", self._query_all_connections),
            (r"show (tcp|udp|icmp) connections", self._query_connections_by_protocol),
            
            # Traffic analysis
            (r"(?:show|get) top (\d+)? ?talkers", self._query_top_talkers),
            (r"(?:show|get) protocol (distribution|usage)", self._query_protocol_distribution),
            (r"what protocols are being used", self._query_protocol_distribution),
            
            # Anomaly queries
            (r"show (?:recent )?anomalies", self._query_recent_anomalies),
            (r"show anomalies (?:in the )?(?:last|past) (\d+) hours?", self._query_anomalies_by_time),
            (r"(?:are there any|show) threats", self._query_threats),
            
            # Summary queries
            (r"(?:show|get) (?:network )?summary", self._query_summary),
            (r"how many (nodes|connections|services)", self._query_count),
            (r"what is the network topology", self._query_topology),
            
            # Port queries
            (r"what is running on port (\d+)", self._query_port_services),
            (r"show (?:all )?open ports", self._query_open_ports),
            (r"which ports are open on (\S+)", self._query_host_ports),
            
            # Attack report queries
            (r"show (?:recent )?(?:attack )?reports?", self._query_attack_reports),
            (r"show (?:attack )?report (\S+)", self._query_specific_report),
            (r"(?:what|show) attacks? (?:happened|occurred) today", self._query_today_attacks),
            (r"(?:show|get) attack statistics", self._query_attack_statistics),
            (r"(?:show|get) (?:the )?latest attack", self._query_latest_attack),
            (r"how many attacks? (?:were there|happened)", self._query_attack_count),
        ]
    
    def query(self, natural_query: str) -> Dict[str, Any]:
        """Process a natural language query"""
        query_lower = natural_query.lower().strip()
        
        # Try to match query patterns
        for pattern, handler in self.query_patterns:
            match = re.search(pattern, query_lower)
            if match:
                try:
                    result = handler(match)
                    return {
                        "success": True,
                        "query": natural_query,
                        "type": handler.__name__.replace("_query_", ""),
                        "data": result,
                        "visualization": self._suggest_visualization(result, handler.__name__)
                    }
                except Exception as e:
                    return {
                        "success": False,
                        "query": natural_query,
                        "error": str(e)
                    }
        
        # Fallback to keyword search
        return self._keyword_search(query_lower)
    
    def _query_all_nodes(self, match) -> Dict:
        """Get all network nodes"""
        nodes = self.store.query_nodes()
        return {
            "nodes": nodes,
            "count": len(nodes),
            "message": f"Found {len(nodes)} network nodes"
        }
    
    def _query_node_by_ip(self, match) -> Dict:
        """Query node by IP address"""
        ip = match.group(2) if match.lastindex >= 2 else match.group(1)
        nodes = self.store.query_nodes(ip=ip)
        
        if nodes:
            connections = self.store.get_node_connections(ip)
            return {
                "node": nodes[0],
                "connections": connections,
                "message": f"Found node {ip}"
            }
        
        return {
            "node": None,
            "message": f"No node found with IP {ip}"
        }
    
    def _query_nodes_by_port(self, match) -> Dict:
        """Find nodes using specific port"""
        port = int(match.group(2) if match.lastindex >= 2 else match.group(1))
        
        nodes_with_port = []
        for node_id, node in self.store.network_data["nodes"].items():
            if port in node.get("ports", []):
                nodes_with_port.append({"id": node_id, **node})
        
        return {
            "nodes": nodes_with_port,
            "port": port,
            "count": len(nodes_with_port),
            "message": f"Found {len(nodes_with_port)} nodes using port {port}"
        }
    
    def _query_all_services(self, match) -> Dict:
        """Get all discovered services"""
        services = self.store.network_data["services"]
        return {
            "services": services,
            "count": len(services),
            "message": f"Found {len(services)} services"
        }
    
    def _query_services_by_host(self, match) -> Dict:
        """Get services running on specific host"""
        host = match.group(1)
        
        host_services = {
            key: service for key, service in self.store.network_data["services"].items()
            if service["ip"] == host
        }
        
        return {
            "host": host,
            "services": host_services,
            "count": len(host_services),
            "message": f"Found {len(host_services)} services on {host}"
        }
    
    def _query_connections(self, match) -> Dict:
        """Get connections for a host"""
        host = match.group(1)
        connections = self.store.get_node_connections(host)
        
        total = len(connections["incoming"]) + len(connections["outgoing"])
        return {
            "host": host,
            "connections": connections,
            "total": total,
            "message": f"Found {total} connections for {host}"
        }
    
    def _query_who_talks_to(self, match) -> Dict:
        """Find who communicates with a host"""
        host = match.group(1)
        connections = self.store.get_node_connections(host)
        
        talkers = set()
        for conn in connections["incoming"]:
            source_node = self.store.network_data["nodes"].get(conn["source"])
            if source_node:
                talkers.add(source_node["ip"])
        
        return {
            "target": host,
            "talkers": list(talkers),
            "count": len(talkers),
            "message": f"{len(talkers)} hosts are talking to {host}"
        }
    
    def _query_all_connections(self, match) -> Dict:
        """Get all network connections"""
        connections = self.store.network_data["connections"]
        return {
            "connections": connections,
            "count": len(connections),
            "message": f"Found {len(connections)} connections"
        }
    
    def _query_connections_by_protocol(self, match) -> Dict:
        """Get connections by protocol"""
        protocol = match.group(1).lower()
        
        filtered = [
            conn for conn in self.store.network_data["connections"]
            if conn["protocol"] == protocol
        ]
        
        return {
            "protocol": protocol,
            "connections": filtered,
            "count": len(filtered),
            "message": f"Found {len(filtered)} {protocol.upper()} connections"
        }
    
    def _query_top_talkers(self, match) -> Dict:
        """Get top talking nodes"""
        limit = int(match.group(1)) if match.lastindex >= 1 and match.group(1) else 10
        top_talkers = self.store.get_top_talkers(limit)
        
        return {
            "top_talkers": top_talkers,
            "limit": limit,
            "message": f"Top {limit} network talkers by bytes transferred"
        }
    
    def _query_protocol_distribution(self, match) -> Dict:
        """Get protocol distribution"""
        distribution = self.store.get_protocol_distribution()
        
        return {
            "protocols": distribution,
            "total_protocols": len(distribution),
            "message": f"Protocol distribution across {len(distribution)} protocols"
        }
    
    def _query_recent_anomalies(self, match) -> Dict:
        """Get recent anomalies"""
        anomalies = self.store.get_recent_anomalies(24)
        
        return {
            "anomalies": anomalies,
            "time_range": "24 hours",
            "count": len(anomalies),
            "message": f"Found {len(anomalies)} anomalies in the last 24 hours"
        }
    
    def _query_anomalies_by_time(self, match) -> Dict:
        """Get anomalies by time range"""
        hours = int(match.group(1))
        anomalies = self.store.get_recent_anomalies(hours)
        
        return {
            "anomalies": anomalies,
            "time_range": f"{hours} hours",
            "count": len(anomalies),
            "message": f"Found {len(anomalies)} anomalies in the last {hours} hours"
        }
    
    def _query_threats(self, match) -> Dict:
        """Get threat information"""
        # Filter anomalies with high severity
        threats = [
            a for a in self.store.network_data["anomalies"]
            if a.get("severity") in ["high", "critical"]
        ]
        
        # Filter connections with threat level
        threat_connections = [
            c for c in self.store.network_data["connections"]
            if c.get("threat_level") not in ["none", None]
        ]
        
        return {
            "anomalies": threats,
            "connections": threat_connections,
            "total_threats": len(threats) + len(threat_connections),
            "message": f"Found {len(threats)} high severity anomalies and {len(threat_connections)} suspicious connections"
        }
    
    def _query_summary(self, match) -> Dict:
        """Get network summary"""
        summary = self.store.get_summary()
        
        return {
            "summary": summary,
            "message": "Network summary statistics"
        }
    
    def _query_count(self, match) -> Dict:
        """Count specific entities"""
        entity = match.group(1).lower()
        
        counts = {
            "nodes": len(self.store.network_data["nodes"]),
            "connections": len(self.store.network_data["connections"]),
            "services": len(self.store.network_data["services"])
        }
        
        count = counts.get(entity, 0)
        return {
            "entity": entity,
            "count": count,
            "message": f"There are {count} {entity} in the network"
        }
    
    def _query_topology(self, match) -> Dict:
        """Get network topology overview"""
        # Include node IDs with the nodes for connection mapping
        nodes_with_ids = []
        node_id_to_ip = {}
        
        for node_id, node_data in self.store.network_data["nodes"].items():
            node_with_id = {**node_data, "id": node_id}
            nodes_with_ids.append(node_with_id)
            node_id_to_ip[node_id] = node_data["ip"]
        
        # Map connections to use IPs instead of node IDs
        connections_with_ips = []
        for conn in self.store.network_data["connections"]:
            conn_copy = conn.copy()
            # Replace node IDs with IPs if they exist
            if conn["source"] in node_id_to_ip:
                conn_copy["source"] = node_id_to_ip[conn["source"]]
            if conn["target"] in node_id_to_ip:
                conn_copy["target"] = node_id_to_ip[conn["target"]]
            connections_with_ips.append(conn_copy)
        
        return {
            "nodes": nodes_with_ids,
            "connections": connections_with_ips,
            "message": "Complete network topology"
        }
    
    def _query_port_services(self, match) -> Dict:
        """Find what services run on a port"""
        port = int(match.group(1))
        
        services = {
            key: service for key, service in self.store.network_data["services"].items()
            if service["port"] == port
        }
        
        return {
            "port": port,
            "services": services,
            "count": len(services),
            "message": f"Found {len(services)} services on port {port}"
        }
    
    def _query_open_ports(self, match) -> Dict:
        """Get all open ports"""
        all_ports = set()
        
        for node in self.store.network_data["nodes"].values():
            all_ports.update(node.get("ports", []))
        
        for service in self.store.network_data["services"].values():
            all_ports.add(service["port"])
        
        return {
            "ports": sorted(list(all_ports)),
            "count": len(all_ports),
            "message": f"Found {len(all_ports)} open ports"
        }
    
    def _query_host_ports(self, match) -> Dict:
        """Get open ports on a host"""
        host = match.group(1)
        
        # Find node by IP
        node = None
        for n in self.store.network_data["nodes"].values():
            if n["ip"] == host:
                node = n
                break
        
        if node:
            return {
                "host": host,
                "ports": node.get("ports", []),
                "count": len(node.get("ports", [])),
                "message": f"Host {host} has {len(node.get('ports', []))} open ports"
            }
        
        return {
            "host": host,
            "ports": [],
            "message": f"Host {host} not found"
        }
    
    def _keyword_search(self, query: str) -> Dict:
        """Fallback keyword-based search"""
        keywords = query.split()
        results = {
            "nodes": [],
            "services": [],
            "connections": []
        }
        
        # Search in nodes
        for node in self.store.network_data["nodes"].values():
            if any(kw in str(node).lower() for kw in keywords):
                results["nodes"].append(node)
        
        # Search in services
        for service in self.store.network_data["services"].values():
            if any(kw in str(service).lower() for kw in keywords):
                results["services"].append(service)
        
        # Limit connections search for performance
        for conn in self.store.network_data["connections"][:100]:
            if any(kw in str(conn).lower() for kw in keywords):
                results["connections"].append(conn)
        
        total = len(results["nodes"]) + len(results["services"]) + len(results["connections"])
        
        return {
            "success": True,
            "query": query,
            "type": "keyword_search",
            "data": {
                "results": results,
                "total": total,
                "message": f"Found {total} results for '{query}'"
            }
        }
    
    def _query_attack_reports(self, match) -> Dict:
        """Get recent attack reports"""
        reports = self.report_storage.get_recent_reports(24)
        
        return {
            "reports": reports,
            "count": len(reports),
            "message": f"Found {len(reports)} attack reports in the last 24 hours"
        }
    
    def _query_specific_report(self, match) -> Dict:
        """Get a specific attack report"""
        report_id = match.group(1)
        report = self.report_storage.get_report(report_id)
        
        if report:
            return {
                "report": report,
                "message": f"Found report {report_id}"
            }
        
        return {
            "report": None,
            "message": f"No report found with ID {report_id}"
        }
    
    def _query_today_attacks(self, match) -> Dict:
        """Get attacks from today"""
        reports = self.report_storage.get_recent_reports(24)
        
        today_reports = []
        today = datetime.now().date()
        
        for report in reports:
            try:
                report_date = datetime.fromisoformat(report.get("created_at", "")).date()
                if report_date == today:
                    today_reports.append(report)
            except:
                pass
        
        return {
            "reports": today_reports,
            "count": len(today_reports),
            "message": f"Found {len(today_reports)} attacks today"
        }
    
    def _query_attack_statistics(self, match) -> Dict:
        """Get attack statistics"""
        stats = self.report_storage.get_statistics()
        
        return {
            "statistics": stats,
            "message": f"Attack statistics: {stats.get('total_attacks', 0)} total attacks"
        }
    
    def _query_latest_attack(self, match) -> Dict:
        """Get the latest attack report"""
        reports = self.report_storage.get_all_reports()
        
        if reports:
            latest = reports[-1]
            return {
                "report": latest,
                "message": f"Latest attack: {latest.get('attack_summary', {}).get('type', 'Unknown')} at {latest.get('created_at', 'Unknown time')}"
            }
        
        return {
            "report": None,
            "message": "No attack reports available"
        }
    
    def _query_attack_count(self, match) -> Dict:
        """Get total attack count"""
        stats = self.report_storage.get_statistics()
        total = stats.get("total_attacks", 0)
        today = stats.get("attacks_today", 0)
        week = stats.get("attacks_this_week", 0)
        
        return {
            "total": total,
            "today": today,
            "this_week": week,
            "message": f"Total attacks: {total} (Today: {today}, This week: {week})"
        }
    
    def _suggest_visualization(self, data: Dict, query_type: str) -> Optional[str]:
        """Suggest appropriate visualization type"""
        visualizations = {
            "_query_topology": "network_graph",
            "_query_all_connections": "network_graph",
            "_query_connections": "directed_graph",
            "_query_who_talks_to": "star_graph",
            "_query_top_talkers": "bar_chart",
            "_query_protocol_distribution": "pie_chart",
            "_query_recent_anomalies": "timeline",
            "_query_all_nodes": "node_list",
            "_query_connections_by_protocol": "filtered_graph"
        }
        
        return visualizations.get(query_type, "table")