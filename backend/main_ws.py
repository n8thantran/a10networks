"""
WebSocket-based packet monitor with proper CORS handling
"""
import asyncio
import json
import logging
from typing import Dict, Any, List, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel
from starlette.websockets import WebSocketState

# Import new components
from storage.network_store import NetworkDataStore
from storage.attack_reports import AttackReportStorage
from agents.network_query_agent import NetworkQueryAgent
from agents.mermaid_generator import MermaidGenerator
from agents.ddos_protection_agent import DDoSProtectionAgent
from agents.attack_visualizer import AttackVisualizer
from ddos_simulator import DDoSSimulator
from api_endpoints import router as api_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NetSentinel WebSocket Monitor")

# Configure CORS to allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Initialize storage
network_store = NetworkDataStore()
attack_report_storage = AttackReportStorage()

# Initialize agents with proper dependencies
query_agent = NetworkQueryAgent(network_store, attack_report_storage)  # Pass report storage!
mermaid_gen = MermaidGenerator()

# Initialize API components with the same instances
from api_endpoints import init_components
init_components(network_store, attack_report_storage, query_agent, mermaid_gen)

# Include API router
app.include_router(api_router)

# Initialize DDoS protection
ddos_agent = DDoSProtectionAgent()
attack_visualizer = AttackVisualizer()
ddos_simulator = None  # Will be initialized when attack starts

# Attack detection state
current_attack_id = None
attack_auto_stopped = False
attack_detection_start = None

# Store packets and connections
packet_storage: List[Dict[str, Any]] = []
active_connections: Set[WebSocket] = set()

class ThreatDetector:
    def __init__(self):
        self.xss_patterns = [
            "<script", "javascript:", "onerror=", "onclick=", 
            "alert(", "document.cookie", "<iframe", "onload=",
            "eval(", "expression(", "<img src", "<svg"
        ]
        self.sql_patterns = [
            "' or '", "1=1", "union select", "drop table",
            "; delete", "exec(", "xp_cmdshell", "' or 1=1",
            "admin'--", "' or 'a'='a", "1' or '1' = '1",
            "select * from", "insert into", "update set"
        ]
    
    def analyze(self, content: str) -> Dict[str, Any]:
        threats = []
        content_lower = content.lower()
        
        # Check XSS
        for pattern in self.xss_patterns:
            if pattern.lower() in content_lower:
                threats.append({
                    "type": "XSS",
                    "pattern": pattern,
                    "severity": "high"
                })
                break  # Only report first match to avoid duplicates
        
        # Check SQL Injection
        for pattern in self.sql_patterns:
            if pattern.lower() in content_lower:
                threats.append({
                    "type": "SQL Injection",
                    "pattern": pattern,
                    "severity": "critical"
                })
                break
        
        threat_level = "safe"
        if threats:
            if any(t["severity"] == "critical" for t in threats):
                threat_level = "critical"
            elif any(t["severity"] == "high" for t in threats):
                threat_level = "high"
            else:
                threat_level = "medium"
        
        return {
            "threats": threats,
            "threat_level": threat_level
        }

detector = ThreatDetector()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                if connection.application_state == WebSocketState.CONNECTED:
                    await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

async def monitor_and_auto_stop_attack():
    """Monitor attack and auto-stop when detected"""
    global ddos_simulator, attack_auto_stopped, current_attack_id
    
    logger.info(f"🔍 Starting aggressive attack monitoring for {current_attack_id}")
    
    # More aggressive detection settings
    detection_checks = 0
    packets_analyzed = 0
    start_time = datetime.now()
    
    # Give it 3 seconds for traffic to start flowing
    await asyncio.sleep(3)
    
    while ddos_simulator and ddos_simulator.attack_active:
        # Check every second for faster response
        await asyncio.sleep(1)
        detection_checks += 1
        
        # Get current protection status
        protection_status = ddos_agent.get_mitigation_status()
        
        # Log current state for debugging
        current_rps = protection_status.get("current_rps", 0)
        baseline_rps = protection_status.get("baseline_rps", 10)
        attack_detected = protection_status.get("attack_detected", False)
        blocked_count = protection_status.get("blocked_count", 0)
        
        logger.info(f"Check #{detection_checks}: RPS={current_rps:.1f}, Baseline={baseline_rps}, Detected={attack_detected}, Blocked={blocked_count}")
        
        # Multiple detection criteria - ANY of these triggers auto-stop
        should_stop = False
        stop_reason = ""
        
        # Criteria 1: High RPS (lowered threshold)
        if current_rps > baseline_rps * 1.5 and current_rps > 15:  # Much lower threshold
            should_stop = True
            stop_reason = f"High RPS detected: {current_rps:.1f} (threshold: {baseline_rps * 1.5:.1f})"
        
        # Criteria 2: Attack flag is set
        elif attack_detected:
            should_stop = True
            stop_reason = f"Attack flag detected by AI agent"
        
        # Criteria 3: IPs are being blocked
        elif blocked_count > 2:  # If more than 2 IPs blocked
            should_stop = True
            stop_reason = f"Multiple IPs blocked: {blocked_count}"
        
        # Criteria 4: Mitigation is active
        elif protection_status.get("mitigation_active"):
            should_stop = True
            stop_reason = "Mitigation system activated"
        
        # Criteria 5: Time-based - if attack runs for more than 10 seconds
        elif (datetime.now() - start_time).total_seconds() > 10 and current_rps > baseline_rps:
            should_stop = True
            stop_reason = f"Sustained elevated traffic for 10+ seconds"
        
        if should_stop:
            logger.warning(f"🚨 DDoS ATTACK DETECTED! Reason: {stop_reason}")
            logger.warning(f"📊 Stats: RPS={current_rps}, Blocked IPs={blocked_count}")
            
            # FORCE STOP the attack
            if ddos_simulator:
                try:
                    # Get stats before stopping
                    attack_stats = ddos_simulator.get_stats()
                    
                    # Force stop
                    ddos_simulator.attack_active = False  # Force the flag
                    stop_result = ddos_simulator.stop_attack()
                    
                    # Merge stats
                    if stop_result and "stats" in stop_result:
                        attack_stats.update(stop_result["stats"])
                    
                    attack_auto_stopped = True
                    
                    # Generate and save report
                    report_id = await generate_and_save_report(attack_stats, protection_status, "auto_stopped")
                    
                    logger.info(f"✅ Attack FORCE STOPPED! Report: {report_id}")
                    
                    # Broadcast alert to all connected clients
                    await manager.broadcast({
                        "type": "attack_alert",
                        "message": f"🛡️ DDoS Attack Detected and Auto-Stopped!",
                        "attack_id": current_attack_id,
                        "report_id": report_id,
                        "severity": "high",
                        "action": "auto_stopped",
                        "reason": stop_reason,
                        "stats": {
                            "rps": current_rps,
                            "blocked_ips": blocked_count,
                            "total_requests": attack_stats.get("total_requests", 0)
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    
                    # Clear the simulator
                    ddos_simulator = None
                    
                except Exception as e:
                    logger.error(f"Error stopping attack: {e}")
                
            break
        
        # Timeout after 30 seconds
        if (datetime.now() - start_time).total_seconds() > 30:
            logger.info("Monitoring timeout reached (30s)")
            break
    
    logger.info(f"Attack monitoring ended for {current_attack_id}")

async def generate_and_save_report(attack_stats: Dict, protection_status: Dict, stop_reason: str):
    """Generate and save attack report"""
    global current_attack_id
    
    # Get attack data
    attack_data = attack_report_storage.mark_attack_stopped(current_attack_id)
    attack_data.update(attack_stats)
    attack_data["stop_reason"] = stop_reason
    
    # Get detection data
    detection_data = {
        "detection_time": datetime.now(timezone.utc).isoformat(),
        "method": "AI Agent Real-time Analysis",
        "confidence": 0.95,
        "indicators": [
            f"RPS spike: {protection_status.get('current_rps', 0)}",
            f"Blocked IPs: {protection_status.get('blocked_count', 0)}",
            f"Attack type: {attack_stats.get('attack_type', 'Unknown')}"
        ],
        "anomalies": protection_status.get("mitigation_rules", [])
    }
    
    # Generate visualizations
    detection_data["attack_flow_diagram"] = attack_visualizer.generate_attack_flow_diagram({
        "attack_type": attack_stats.get("attack_type"),
        "stats": attack_stats
    })
    detection_data["mitigation_diagram"] = attack_visualizer.generate_mitigation_diagram(protection_status)
    detection_data["statistics_diagram"] = attack_visualizer.generate_statistics_diagram({
        **attack_stats,
        **protection_status.get("metrics", {})
    })
    
    # Generate report
    report = attack_report_storage.generate_attack_report(
        attack_data,
        protection_status,
        detection_data
    )
    
    # Save report
    report_id = attack_report_storage.save_report(report)
    logger.info(f"Attack report saved: {report_id}")
    
    return report_id

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint with improved error handling"""
    await manager.connect(websocket)
    
    try:
        # Send initial packets
        for packet in packet_storage[-20:]:
            await websocket.send_json(packet)
        
        # Generate some initial test packets
        if len(packet_storage) == 0:
            test_packet = generate_test_packet("Connection established")
            packet_storage.append(test_packet)
            await websocket.send_json(test_packet)
        
        # Keep connection alive and handle messages
        while True:
            try:
                # Wait for any message from client (ping/pong)
                data = await websocket.receive_text()
                
                # If client sends data, analyze it
                if data and data != "ping":
                    analysis = detector.analyze(data)
                    packet = generate_packet_from_analysis(data, analysis)
                    
                    # Run through DDoS protection
                    ddos_analysis = await ddos_agent.analyze_traffic(packet)
                    
                    # Only broadcast if not blocked
                    if ddos_analysis["action"] != "block":
                        packet_storage.append(packet)
                        packet["ddos_analysis"] = ddos_analysis
                        await manager.broadcast(packet)
                    else:
                        logger.warning(f"Blocked packet from {packet.get('src_ip')} - {ddos_analysis['threat_type']}")
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error in websocket loop: {e}")
                break
                
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

def generate_test_packet(content: str = "Test packet") -> Dict[str, Any]:
    """Generate a test packet"""
    analysis = detector.analyze(content)
    return {
        "id": f"PKT-{str(uuid.uuid4())[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 45678,
        "dst_port": 8080,
        "protocol": "HTTP",
        "size": len(content),
        "threat_level": analysis["threat_level"],
        "threats": analysis["threats"]
    }

def generate_packet_from_analysis(content: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Generate packet from analysis results"""
    src_ip = f"192.168.1.{uuid.uuid4().int % 255}"
    dst_ip = "10.0.0.1"
    src_port = (uuid.uuid4().int % 50000) + 10000
    dst_port = 8080
    protocol = "HTTP"
    
    packet = {
        "id": f"PKT-{str(uuid.uuid4())[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": len(content),
        "threat_level": analysis["threat_level"],
        "threats": analysis["threats"]
    }
    
    # Update network store with packet data
    network_store.add_connection(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol.lower(),
        port=dst_port,
        bytes=len(content),
        threat_level=analysis["threat_level"]
    )
    
    # Add anomalies if threats detected
    for threat in analysis["threats"]:
        network_store.add_anomaly(
            anomaly_type=threat["type"],
            description=f"Detected {threat['type']} pattern: {threat['pattern']}",
            severity=threat["severity"],
            source=src_ip,
            target=dst_ip
        )
    
    # Save periodically
    if len(packet_storage) % 10 == 0:
        network_store.save()
    
    return packet

@app.post("/api/simulate")
async def simulate_attack(data: Dict[str, str]):
    """Simulate an attack for testing"""
    content = data.get("data", "")
    analysis = detector.analyze(content)
    packet = generate_packet_from_analysis(content, analysis)
    
    packet_storage.append(packet)
    if len(packet_storage) > 100:
        packet_storage.pop(0)
    
    await manager.broadcast(packet)
    return packet

@app.get("/api/packets")
async def get_packets(limit: int = Query(50, ge=1, le=100)):
    """Get recent packets"""
    return {"packets": packet_storage[-limit:]}

@app.get("/api/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "connections": len(manager.active_connections),
        "packets": len(packet_storage)
    }

@app.get("/")
async def root():
    """Simple test page"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>NetSentinel WebSocket Monitor</title>
        <style>
            body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
            .status { padding: 10px; border: 1px solid #0f0; margin: 10px 0; }
            .connected { border-color: #0f0; color: #0f0; }
            .disconnected { border-color: #f00; color: #f00; }
            .packet { border: 1px solid #0f0; padding: 10px; margin: 5px 0; }
            button { background: #000; color: #0f0; border: 1px solid #0f0; padding: 5px 10px; cursor: pointer; }
        </style>
    </head>
    <body>
        <h1>NetSentinel WebSocket Monitor</h1>
        <div id="status" class="status disconnected">Disconnected</div>
        <button onclick="connect()">Connect</button>
        <button onclick="sendTest()">Send Test Attack</button>
        <div id="packets"></div>
        
        <script>
            let ws = null;
            
            function connect() {
                ws = new WebSocket('ws://localhost:8000/ws');
                
                ws.onopen = () => {
                    document.getElementById('status').className = 'status connected';
                    document.getElementById('status').textContent = 'Connected';
                    console.log('Connected to WebSocket');
                };
                
                ws.onmessage = (event) => {
                    const packet = JSON.parse(event.data);
                    displayPacket(packet);
                };
                
                ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    document.getElementById('status').className = 'status disconnected';
                    document.getElementById('status').textContent = 'Error';
                };
                
                ws.onclose = () => {
                    document.getElementById('status').className = 'status disconnected';
                    document.getElementById('status').textContent = 'Disconnected';
                };
            }
            
            function sendTest() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send("' OR '1'='1");
                }
            }
            
            function displayPacket(packet) {
                const div = document.createElement('div');
                div.className = 'packet';
                div.textContent = JSON.stringify(packet, null, 2);
                const container = document.getElementById('packets');
                container.insertBefore(div, container.firstChild);
                if (container.children.length > 10) {
                    container.removeChild(container.lastChild);
                }
            }
            
            // Auto-connect
            connect();
        </script>
    </body>
    </html>
    """)

@app.post("/api/ddos/start")
async def start_ddos_attack(attack_config: Dict[str, Any]):
    """Start a DDoS attack simulation"""
    global ddos_simulator, current_attack_id, attack_detection_start, attack_auto_stopped
    
    attack_type = attack_config.get("type", "volumetric")
    duration = attack_config.get("duration", 30)
    intensity = attack_config.get("intensity", 50)
    
    ddos_simulator = DDoSSimulator()
    current_attack_id = f"ATTACK-{uuid.uuid4().hex[:8]}"
    attack_detection_start = datetime.now(timezone.utc)
    attack_auto_stopped = False
    
    # Mark attack as active
    attack_report_storage.mark_attack_active(current_attack_id, {
        "type": attack_type,
        "duration": duration,
        "intensity": intensity,
        "start_time": attack_detection_start.isoformat()
    })
    
    # Start attack based on type
    if attack_type == "volumetric":
        asyncio.create_task(ddos_simulator.volumetric_flood(duration, intensity))
    elif attack_type == "slowloris":
        asyncio.create_task(ddos_simulator.slowloris_attack(duration, intensity))
    elif attack_type == "application":
        asyncio.create_task(ddos_simulator.application_layer_attack(duration, intensity))
    elif attack_type == "multi-vector":
        asyncio.create_task(ddos_simulator.multi_vector_attack(duration))
    
    # Start monitoring for auto-stop
    asyncio.create_task(monitor_and_auto_stop_attack())
    
    return {
        "status": "attack_started",
        "attack_id": current_attack_id,
        "type": attack_type,
        "duration": duration,
        "intensity": intensity
    }

@app.post("/api/ddos/stop")
async def stop_ddos_attack():
    """Stop the DDoS attack"""
    global ddos_simulator
    
    if ddos_simulator:
        result = ddos_simulator.stop_attack()
        return result
    
    return {"status": "no_active_attack"}

@app.get("/api/ddos/status")
async def get_ddos_status():
    """Get DDoS protection status"""
    protection_status = ddos_agent.get_mitigation_status()
    
    # Get attack stats if active
    attack_stats = {}
    if ddos_simulator:
        attack_stats = ddos_simulator.get_stats()
    
    # Generate visualizations
    attack_flow = attack_visualizer.generate_attack_flow_diagram({"attack_type": attack_stats.get("attack_type", "Unknown"), "stats": attack_stats})
    mitigation_flow = attack_visualizer.generate_mitigation_diagram(protection_status)
    stats_diagram = attack_visualizer.generate_statistics_diagram({**attack_stats, **protection_status.get("metrics", {})})
    
    # Get explanation
    explanation = attack_visualizer.generate_attack_explanation(
        {"attack_type": attack_stats.get("attack_type", "Unknown"), "stats": attack_stats},
        protection_status
    )
    
    return {
        "protection": protection_status,
        "attack": attack_stats,
        "visualizations": {
            "attack_flow": attack_flow,
            "mitigation": mitigation_flow,
            "statistics": stats_diagram
        },
        "explanation": explanation
    }

@app.post("/api/ddos/reset")
async def reset_ddos_protection():
    """Reset DDoS protection and clear blocked IPs"""
    ddos_agent.reset_mitigation()
    return {"status": "protection_reset"}

@app.get("/api/reports")
async def get_attack_reports(hours: int = 24):
    """Get recent attack reports"""
    reports = attack_report_storage.get_recent_reports(hours)
    return {
        "reports": reports,
        "count": len(reports),
        "time_range": f"{hours} hours"
    }

@app.get("/api/reports/{report_id}")
async def get_report(report_id: str):
    """Get specific attack report"""
    report = attack_report_storage.get_report(report_id)
    if report:
        return report
    return {"error": "Report not found"}

@app.get("/api/reports/stats")
async def get_attack_statistics():
    """Get overall attack statistics"""
    stats = attack_report_storage.get_statistics()
    return stats

@app.get("/api/reports/latest")
async def get_latest_report():
    """Get the most recent attack report"""
    reports = attack_report_storage.get_all_reports()
    if reports:
        return reports[-1]
    return {"message": "No reports available"}

@app.on_event("startup")
async def startup_event():
    """Generate some initial test packets on startup"""
    logger.info("Starting NetSentinel WebSocket Monitor with DDoS Protection")
    
    # Add some initial packets for testing
    test_data = [
        "Normal request",
        "<script>alert('XSS')</script>",
        "admin' OR '1'='1",
        "Normal search query"
    ]
    
    for data in test_data:
        packet = generate_test_packet(data)
        packet_storage.append(packet)
    
    logger.info(f"Added {len(test_data)} test packets")
    logger.info("DDoS Protection Agent initialized")

if __name__ == "__main__":
    print("🛡️ NetSentinel WebSocket Monitor")
    print("📡 WebSocket endpoint: ws://localhost:8000/ws")
    print("🌐 Test page: http://localhost:8000")
    print("📊 Packets API: http://localhost:8000/api/packets")
    print("\n✨ Server starting...")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )