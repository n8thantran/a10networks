"""
Test the complete DDoS detection and auto-stop flow
"""
import asyncio
import aiohttp
import json
import time

async def test_ddos_flow():
    """Test the complete flow"""
    base_url = "http://localhost:8000"
    
    print("=" * 60)
    print("🧪 Testing Complete DDoS Detection & Auto-Stop Flow")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # 1. Start a DDoS attack
        print("\n1. Starting DDoS attack...")
        attack_config = {
            "type": "multi-vector",
            "duration": 30,  # 30 seconds
            "intensity": 50   # Medium intensity
        }
        
        try:
            async with session.post(f"{base_url}/api/ddos/start", json=attack_config) as resp:
                result = await resp.json()
                attack_id = result.get("attack_id")
                print(f"   ✅ Attack started: {attack_id}")
        except Exception as e:
            print(f"   ❌ Failed to start attack: {e}")
            return
        
        # 2. Monitor for auto-stop
        print("\n2. Monitoring for auto-detection and stop...")
        print("   (The AI should detect and stop the attack within 10-15 seconds)")
        
        stopped = False
        for i in range(20):  # Check for 20 seconds
            await asyncio.sleep(1)
            
            try:
                async with session.get(f"{base_url}/api/ddos/status") as resp:
                    status = await resp.json()
                    
                    protection = status.get("protection", {})
                    attack = status.get("attack", {})
                    
                    rps = protection.get("current_rps", 0)
                    detected = protection.get("attack_detected", False)
                    blocked = protection.get("blocked_count", 0)
                    
                    print(f"   [{i+1}s] RPS: {rps:.1f}, Detected: {detected}, Blocked IPs: {blocked}")
                    
                    # Check if attack was stopped
                    if attack.get("attack_type") and not attack.get("attack_active", True):
                        stopped = True
                        print(f"\n   🛡️ ATTACK AUTO-STOPPED!")
                        break
                        
            except Exception as e:
                print(f"   Error checking status: {e}")
        
        if not stopped:
            print("\n   ⚠️  Attack was not auto-stopped in time")
            # Manually stop it
            try:
                async with session.post(f"{base_url}/api/ddos/stop") as resp:
                    print("   Manually stopping attack...")
            except:
                pass
        
        # 3. Check for generated report
        print("\n3. Checking for attack report...")
        await asyncio.sleep(2)  # Give it time to generate report
        
        try:
            async with session.get(f"{base_url}/api/reports/latest") as resp:
                report = await resp.json()
                
                if report and "id" in report:
                    report_id = report["id"]
                    severity = report.get("attack_summary", {}).get("severity", "unknown")
                    effectiveness = report.get("mitigation_actions", {}).get("effectiveness_percentage", 0)
                    
                    print(f"   ✅ Report generated: {report_id}")
                    print(f"      Severity: {severity}")
                    print(f"      Mitigation Effectiveness: {effectiveness:.1f}%")
                else:
                    print("   ❌ No report found")
                    
        except Exception as e:
            print(f"   Error fetching report: {e}")
        
        # 4. Test Mermaid visualization
        print("\n4. Testing Mermaid diagram generation...")
        
        try:
            async with session.get(f"{base_url}/api/ddos/status") as resp:
                status = await resp.json()
                visualizations = status.get("visualizations", {})
                
                if visualizations:
                    print("   ✅ Visualizations generated:")
                    for viz_type, diagram in visualizations.items():
                        if diagram:
                            lines = diagram.count('\n') + 1
                            print(f"      - {viz_type}: {lines} lines")
                            # Print first line to verify format
                            first_line = diagram.split('\n')[0]
                            print(f"        First line: {first_line}")
                else:
                    print("   ❌ No visualizations generated")
                    
        except Exception as e:
            print(f"   Error fetching visualizations: {e}")
        
        print("\n" + "=" * 60)
        print("✅ Test Complete!")
        print("=" * 60)

if __name__ == "__main__":
    print("Make sure the backend is running: python main_ws.py")
    print("Starting test in 3 seconds...")
    time.sleep(3)
    asyncio.run(test_ddos_flow())