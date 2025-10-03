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
                    packet_storage.append(packet)
                    await manager.broadcast(packet)
                    
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
    return {
        "id": f"PKT-{str(uuid.uuid4())[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": f"192.168.1.{uuid.uuid4().int % 255}",
        "dst_ip": "10.0.0.1",
        "src_port": (uuid.uuid4().int % 50000) + 10000,
        "dst_port": 8080,
        "protocol": "HTTP",
        "size": len(content),
        "threat_level": analysis["threat_level"],
        "threats": analysis["threats"]
    }

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

@app.on_event("startup")
async def startup_event():
    """Generate some initial test packets on startup"""
    logger.info("Starting NetSentinel WebSocket Monitor")
    
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