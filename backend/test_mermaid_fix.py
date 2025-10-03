"""
Test the fixed Mermaid syntax
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.mermaid_generator import MermaidGenerator

def test_mermaid():
    gen = MermaidGenerator()
    
    # Test data
    nodes = [
        {"id": "n1", "ip": "192.168.1.1", "hostname": "router", "type": "router"},
        {"id": "n2", "ip": "192.168.1.100", "hostname": "workstation", "type": "host"},
        {"id": "n3", "ip": "192.168.1.200", "hostname": "webserver", "type": "server"},
        {"id": "n4", "ip": "10.0.0.1", "hostname": "firewall", "type": "firewall"}
    ]
    
    connections = [
        {"source": "n2", "target": "n3", "protocol": "tcp", "port": 443},
        {"source": "n2", "target": "n1", "protocol": "udp", "port": 53},
        {"source": "n3", "target": "n4", "protocol": "tcp", "port": 80}
    ]
    
    # Generate diagram
    diagram = gen.generate_network_graph(nodes, connections, "Test Network")
    
    print("Generated Mermaid Diagram:")
    print("=" * 50)
    print(diagram)
    print("=" * 50)
    
    # Test pie chart
    proto_data = {"TCP": 5, "UDP": 3, "ICMP": 1}
    pie = gen.generate_pie_chart(proto_data, "Protocol Distribution")
    
    print("\nGenerated Pie Chart:")
    print("=" * 50)
    print(pie)
    print("=" * 50)

if __name__ == "__main__":
    test_mermaid()